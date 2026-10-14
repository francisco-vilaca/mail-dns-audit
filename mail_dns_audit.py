#!/usr/bin/env python3
"""mail-dns-audit: audit the DNS records that decide whether a domain's email
gets delivered (MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI).

Read-only: it only performs DNS queries (and, with --fetch-mta-sts, one HTTPS
GET to the domain's public MTA-STS policy). It never sends email and never
touches the mail servers themselves.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass

__version__ = "0.1.0"

OK, INFO, WARN, FAIL, ERROR = "OK", "INFO", "WARN", "FAIL", "ERROR"
SPF_LOOKUP_LIMIT = 10
SPF_VOID_LIMIT = 2

# Selectors used by common providers. Pass --selector to test your own.
DEFAULT_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "k3",
    "s1", "s2", "dkim", "mail", "smtp", "mx", "fm1", "fm2", "fm3",
    "zoho", "zmail", "protonmail", "protonmail2", "protonmail3",
    "mandrill", "mxvault", "everlytickey1", "everlytickey2", "sendgrid",
    "smtpapi", "amazonses", "pm", "mailjet", "sib",
]


@dataclass
class Finding:
    check: str
    status: str
    message: str
    detail: str = ""


class DNSError(Exception):
    """A lookup failed for a reason other than 'the record does not exist'."""


class DNSClient:
    """Thin wrapper around dnspython. Missing records return an empty list;
    real failures (timeouts, SERVFAIL) raise DNSError."""

    def __init__(self, nameserver: str | None = None, timeout: float = 5.0):
        import dns.resolver  # imported here so tests can run without network

        self._resolver = dns.resolver.Resolver()
        if nameserver:
            self._resolver.nameservers = [nameserver]
        self._resolver.lifetime = timeout

    def _query(self, name: str, rtype: str):
        import dns.exception
        import dns.resolver

        try:
            return list(self._resolver.resolve(name, rtype))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.exception.DNSException, OSError) as exc:
            raise DNSError(f"{rtype} {name}: {exc.__class__.__name__}") from exc

    def exists(self, name: str) -> bool:
        """False only when the name itself does not exist (NXDOMAIN)."""
        import dns.exception
        import dns.resolver

        try:
            self._resolver.resolve(name, "SOA")
        except dns.resolver.NXDOMAIN:
            return False
        except dns.resolver.NoAnswer:
            return True
        except (dns.exception.DNSException, OSError) as exc:
            raise DNSError(f"SOA {name}: {exc.__class__.__name__}") from exc
        return True

    def txt(self, name: str) -> list[str]:
        return [b"".join(r.strings).decode("utf-8", "replace") for r in self._query(name, "TXT")]

    def mx(self, name: str) -> list[tuple[int, str]]:
        return sorted((r.preference, r.exchange.to_text().rstrip(".")) for r in self._query(name, "MX"))

    def addresses(self, name: str) -> list[str]:
        return [r.to_text() for rtype in ("A", "AAAA") for r in self._query(name, rtype)]


# --------------------------------------------------------------------------- helpers

def parse_tags(record: str) -> dict[str, str]:
    """Parse 'k=v; k2=v2' style records (DMARC, DKIM, MTA-STS, TLS-RPT)."""
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    return tags


def _der_header(buf: bytes, i: int) -> tuple[int, int, int]:
    """Return (tag, content_start, content_length) for the DER element at i."""
    tag = buf[i]
    length = buf[i + 1]
    i += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[i:i + n], "big")
        i += n
    return tag, i, length


def rsa_key_bits(p_value: str) -> int:
    """Size in bits of the RSA modulus in a DKIM p= value.

    Accepts SubjectPublicKeyInfo (the normal DKIM form) and bare PKCS#1
    RSAPublicKey. Raises ValueError on anything else."""
    data = "".join(p_value.split())
    try:
        der = base64.b64decode(data + "=" * (-len(data) % 4), validate=True)
    except binascii.Error as exc:
        raise ValueError("p= is not valid base64") from exc
    try:
        tag, i, _ = _der_header(der, 0)
        if tag != 0x30:
            raise ValueError("not a DER sequence")
        tag, j, length = _der_header(der, i)
        if tag == 0x30:  # SubjectPublicKeyInfo: AlgorithmIdentifier, BIT STRING
            tag, k, _ = _der_header(der, j + length)
            if tag != 0x03:
                raise ValueError("missing BIT STRING")
            k += 1  # skip the 'unused bits' byte
            tag, k, _ = _der_header(der, k)  # RSAPublicKey SEQUENCE
            tag, k, length = _der_header(der, k)  # modulus INTEGER
        elif tag == 0x02:  # PKCS#1 RSAPublicKey: modulus comes first
            k = j
        else:
            raise ValueError("unexpected DER structure")
    except IndexError as exc:
        raise ValueError("truncated key") from exc
    modulus = der[k:k + length].lstrip(b"\x00")
    if not modulus:
        raise ValueError("empty modulus")
    return (len(modulus) - 1) * 8 + modulus[0].bit_length()


def _spf_records(client, domain: str) -> list[str]:
    return [t for t in client.txt(domain) if t.lower() == "v=spf1" or t.lower().startswith("v=spf1 ")]


def count_spf_lookups(client, domain: str, _seen: set | None = None, _depth: int = 0):
    """Count DNS-querying SPF terms recursively (RFC 7208 §4.6.4).

    Returns (lookups, void_lookups, problems)."""
    seen = _seen if _seen is not None else set()
    if domain.lower() in seen:
        return 0, 0, [f"include loop at {domain}"]
    if _depth > SPF_LOOKUP_LIMIT:
        return 0, 0, [f"include chain deeper than {SPF_LOOKUP_LIMIT} at {domain}"]
    seen.add(domain.lower())

    records = _spf_records(client, domain)
    if not records:
        return 0, 1, []
    lookups, voids, problems = 0, 0, []
    for term in records[0].split()[1:]:
        bare = term.lstrip("+-~?").lower()
        if bare.startswith(("include:", "redirect=")):
            lookups += 1
            target = term.split(":", 1)[1] if bare.startswith("include:") else term.split("=", 1)[1]
            if "%" in target:  # macro, cannot be expanded without a sender
                continue
            sub_lookups, sub_voids, sub_problems = count_spf_lookups(client, target, seen, _depth + 1)
            if sub_voids and not sub_lookups and not _spf_records(client, target):
                problems.append(f"{bare.split(':')[0].split('=')[0]} target {target} has no SPF record")
            lookups += sub_lookups
            voids += sub_voids
            problems += sub_problems
        elif bare in ("a", "mx", "ptr") or bare.startswith(("a:", "a/", "mx:", "mx/", "ptr:", "exists:")):
            lookups += 1
    return lookups, voids, problems


# --------------------------------------------------------------------------- checks

def check_mx(client, domain: str) -> list[Finding]:
    records = client.mx(domain)
    if not records:
        return [Finding("MX", FAIL, "No MX record: this domain cannot receive email",
                        "Add MX records pointing to your mail provider.")]
    if len(records) == 1 and records[0][1] in ("", "."):
        return [Finding("MX", INFO, "Null MX: domain explicitly does not accept email (RFC 7505)")]
    out = [Finding("MX", OK, f"{len(records)} MX record(s)",
                   ", ".join(f"{pref} {host}" for pref, host in records))]
    for _, host in records:
        if not client.addresses(host):
            out.append(Finding("MX", FAIL, f"MX host {host} does not resolve to any address"))
    return out


def check_spf(client, domain: str) -> list[Finding]:
    records = _spf_records(client, domain)
    if not records:
        return [Finding("SPF", FAIL, "No SPF record",
                        'Publish one TXT record starting with "v=spf1" listing every service that sends as you.')]
    if len(records) > 1:
        return [Finding("SPF", FAIL, f"{len(records)} SPF records found (only one is allowed: permerror)",
                        " | ".join(records))]
    record = records[0]
    out = []
    terms = [t.lower() for t in record.split()[1:]]
    all_terms = [t for t in terms if t.lstrip("+-~?") == "all"]
    if not all_terms:
        if any(t.startswith("redirect=") for t in terms):
            out.append(Finding("SPF", OK, "Policy delegated with redirect=", record))
        else:
            out.append(Finding("SPF", WARN, "No 'all' mechanism: unlisted senders get a neutral result", record))
    else:
        qualifier = all_terms[-1][0] if all_terms[-1][0] in "+-~?" else "+"
        if qualifier == "-":
            out.append(Finding("SPF", OK, "Hard fail for unlisted senders (-all)", record))
        elif qualifier == "~":
            out.append(Finding("SPF", OK, "Soft fail for unlisted senders (~all)", record))
        elif qualifier == "?":
            out.append(Finding("SPF", WARN, "Neutral (?all): SPF gives no protection", record))
        else:
            out.append(Finding("SPF", FAIL, "+all lets anyone on the internet send as this domain", record))
    if any(t.lstrip("+-~?").startswith("ptr") for t in terms):
        out.append(Finding("SPF", WARN, "Uses the deprecated 'ptr' mechanism (RFC 7208 §5.5)"))

    lookups, voids, problems = count_spf_lookups(client, domain)
    if lookups > SPF_LOOKUP_LIMIT:
        out.append(Finding("SPF", FAIL, f"{lookups} DNS lookups (limit is {SPF_LOOKUP_LIMIT}: permerror)",
                           "Flatten or remove includes; receivers will treat SPF as broken."))
    elif lookups >= SPF_LOOKUP_LIMIT - 2:
        out.append(Finding("SPF", WARN, f"{lookups}/{SPF_LOOKUP_LIMIT} DNS lookups: close to the limit"))
    else:
        out.append(Finding("SPF", OK, f"{lookups}/{SPF_LOOKUP_LIMIT} DNS lookups"))
    if voids > SPF_VOID_LIMIT:
        out.append(Finding("SPF", WARN, f"{voids} void lookups (more than {SPF_VOID_LIMIT} may cause permerror)"))
    for problem in problems:
        out.append(Finding("SPF", FAIL, problem))
    return out


def _dmarc_records(client, name: str) -> list[str]:
    return [t for t in client.txt(f"_dmarc.{name}") if t.lower().replace(" ", "").startswith("v=dmarc1")]


def check_dmarc(client, domain: str) -> list[Finding]:
    records = _dmarc_records(client, domain)
    inherited_from = None
    if not records:
        labels = domain.split(".")
        for i in range(1, len(labels) - 1):  # walk up towards the organizational domain
            parent = ".".join(labels[i:])
            records = _dmarc_records(client, parent)
            if records:
                inherited_from = parent
                break
    if not records:
        return [Finding("DMARC", FAIL, "No DMARC record",
                        f'Start with: _dmarc.{domain} TXT "v=DMARC1; p=none; rua=mailto:dmarc@{domain}"')]
    if len(records) > 1:
        return [Finding("DMARC", FAIL, f"{len(records)} DMARC records found (only one is allowed)")]

    tags = parse_tags(records[0])
    out = []
    policy = tags.get("p", "").lower()
    if inherited_from:
        policy = tags.get("sp", policy).lower()
        out.append(Finding("DMARC", INFO, f"No record of its own; inherits from {inherited_from}", records[0]))
    if policy not in ("none", "quarantine", "reject"):
        return out + [Finding("DMARC", FAIL, "Missing or invalid p= tag", records[0])]
    if policy == "none":
        out.append(Finding("DMARC", WARN, "p=none: monitoring only, spoofed email is not blocked",
                           "Once reports look clean, move to p=quarantine and then p=reject."))
    else:
        out.append(Finding("DMARC", OK, f"p={policy}: spoofed email is {'rejected' if policy == 'reject' else 'quarantined'}"))
    pct = tags.get("pct", "100")
    if pct != "100":
        out.append(Finding("DMARC", WARN, f"pct={pct}: policy applies to only part of the failing email"))
    if "rua" not in tags:
        out.append(Finding("DMARC", WARN, "No rua= tag: you receive no aggregate reports"))
    else:
        out.append(Finding("DMARC", OK, "Aggregate reports enabled", tags["rua"]))
    return out


def check_dkim(client, domain: str, selectors: list[str]) -> list[Finding]:
    out = []
    for selector in selectors:
        name = f"{selector}._domainkey.{domain}"
        records = [t for t in client.txt(name) if "p=" in t.replace(" ", "")]
        if not records:
            continue
        tags = parse_tags(records[0])
        key, key_type = tags.get("p", ""), tags.get("k", "rsa").lower()
        if not key:
            out.append(Finding("DKIM", WARN, f"Selector '{selector}': key revoked (empty p=)"))
        elif key_type == "ed25519":
            out.append(Finding("DKIM", OK, f"Selector '{selector}': Ed25519 key"))
        else:
            try:
                bits = rsa_key_bits(key)
            except ValueError as exc:
                out.append(Finding("DKIM", FAIL, f"Selector '{selector}': unreadable key ({exc})"))
                continue
            if bits < 1024:
                out.append(Finding("DKIM", FAIL, f"Selector '{selector}': RSA {bits}-bit key is too weak"))
            elif bits < 2048:
                out.append(Finding("DKIM", WARN, f"Selector '{selector}': RSA {bits}-bit key, rotate to 2048"))
            else:
                out.append(Finding("DKIM", OK, f"Selector '{selector}': RSA {bits}-bit key"))
    if not out:
        out.append(Finding("DKIM", WARN, f"No DKIM key found for the {len(selectors)} selector(s) tried",
                           "DKIM selectors cannot be listed via DNS; pass --selector with the one your provider uses."))
    return out


def check_mta_sts(client, domain: str, fetch: bool = False, timeout: float = 5.0) -> list[Finding]:
    records = [t for t in client.txt(f"_mta-sts.{domain}") if t.lower().replace(" ", "").startswith("v=stsv1")]
    if not records:
        return [Finding("MTA-STS", INFO, "Not configured (optional; protects inbound mail from TLS downgrade)")]
    out = [Finding("MTA-STS", OK, "Policy record present", records[0])]
    if fetch:
        url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 - fixed https URL
                body = resp.read(65536).decode("utf-8", "replace")
        except (urllib.error.URLError, OSError) as exc:
            return out + [Finding("MTA-STS", FAIL, "Policy file could not be fetched", f"{url}: {exc}")]
        policy = {k.strip().lower(): v.strip() for k, _, v in
                  (line.partition(":") for line in body.splitlines()) if k.strip()}
        mode = policy.get("mode", "").lower()
        if mode == "enforce":
            out.append(Finding("MTA-STS", OK, "Policy mode: enforce"))
        elif mode == "testing":
            out.append(Finding("MTA-STS", INFO, "Policy mode: testing"))
        else:
            out.append(Finding("MTA-STS", WARN, f"Policy mode: {mode or 'missing'}"))
    return out


def check_tlsrpt(client, domain: str) -> list[Finding]:
    records = [t for t in client.txt(f"_smtp._tls.{domain}") if t.lower().replace(" ", "").startswith("v=tlsrptv1")]
    if not records:
        return [Finding("TLS-RPT", INFO, "Not configured (optional; reports TLS delivery failures to you)")]
    return [Finding("TLS-RPT", OK, "Reporting enabled", records[0])]


def check_bimi(client, domain: str) -> list[Finding]:
    records = [t for t in client.txt(f"default._bimi.{domain}") if t.lower().replace(" ", "").startswith("v=bimi1")]
    if not records:
        return [Finding("BIMI", INFO, "Not configured (optional; brand logo in supporting inboxes)")]
    return [Finding("BIMI", INFO, "Record present", records[0])]


def audit(client, domain: str, selectors: list[str], fetch_mta_sts: bool = False) -> list[Finding]:
    domain = domain.strip().rstrip(".").lower()
    try:
        if not client.exists(domain):
            return [Finding("DOMAIN", ERROR, "Domain does not exist (NXDOMAIN)",
                            "Check the spelling, or try another resolver with --nameserver.")]
    except DNSError as exc:
        return [Finding("DOMAIN", ERROR, "DNS lookup failed", str(exc))]
    findings: list[Finding] = []
    checks = [
        ("MX", lambda: check_mx(client, domain)),
        ("SPF", lambda: check_spf(client, domain)),
        ("DKIM", lambda: check_dkim(client, domain, selectors)),
        ("DMARC", lambda: check_dmarc(client, domain)),
        ("MTA-STS", lambda: check_mta_sts(client, domain, fetch_mta_sts)),
        ("TLS-RPT", lambda: check_tlsrpt(client, domain)),
        ("BIMI", lambda: check_bimi(client, domain)),
    ]
    for name, run in checks:
        try:
            findings += run()
        except DNSError as exc:
            findings.append(Finding(name, ERROR, "DNS lookup failed", str(exc)))
    return findings


# --------------------------------------------------------------------------- output

COLORS = {OK: "\033[32m", INFO: "\033[36m", WARN: "\033[33m", FAIL: "\033[31m", ERROR: "\033[35m"}
RESET = "\033[0m"


def render_text(domain: str, findings: list[Finding], color: bool, verbose: bool) -> str:
    lines = [f"mail-dns-audit {__version__}: {domain}", ""]
    for f in findings:
        status = f"{COLORS[f.status]}{f.status:<5}{RESET}" if color else f"{f.status:<5}"
        lines.append(f"  {f.check:<8} {status}  {f.message}")
        if f.detail and (verbose or f.status in (WARN, FAIL, ERROR)):
            lines.append(f"  {'':<8} {'':<5}  └ {f.detail}")
    counts = {s: sum(1 for f in findings if f.status == s) for s in (OK, INFO, WARN, FAIL, ERROR)}
    lines += ["", "  Summary: " + ", ".join(f"{n} {s}" for s, n in counts.items() if n)]
    return "\n".join(lines)


def main(argv: list[str] | None = None, client=None) -> int:
    parser = argparse.ArgumentParser(
        prog="mail-dns-audit",
        description="Audit MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT and BIMI records for one or more domains.")
    parser.add_argument("domains", nargs="+", help="domain(s) to audit, e.g. example.com")
    parser.add_argument("-s", "--selector", action="append", dest="selectors",
                        help="DKIM selector to check (repeatable). Default: a list of common selectors.")
    parser.add_argument("--json", action="store_true", help="machine-readable JSON output")
    parser.add_argument("--fetch-mta-sts", action="store_true", help="also download and check the MTA-STS policy file")
    parser.add_argument("--nameserver", help="query this resolver instead of the system one, e.g. 1.1.1.1")
    parser.add_argument("--timeout", type=float, default=5.0, help="DNS timeout in seconds (default 5)")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    parser.add_argument("-v", "--verbose", action="store_true", help="show details for every finding")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    if client is None:
        try:
            client = DNSClient(args.nameserver, args.timeout)
        except ImportError:
            print("dnspython is required: pip install dnspython", file=sys.stderr)
            return 2
    selectors = args.selectors or DEFAULT_SELECTORS
    results = {d: audit(client, d, selectors, args.fetch_mta_sts) for d in args.domains}

    if args.json:
        print(json.dumps({d: [asdict(f) for f in fs] for d, fs in results.items()}, indent=2))
    else:
        color = sys.stdout.isatty() and not args.no_color
        print("\n\n".join(render_text(d, fs, color, args.verbose) for d, fs in results.items()))

    statuses = {f.status for fs in results.values() for f in fs}
    if ERROR in statuses:
        return 2
    return 1 if FAIL in statuses else 0


if __name__ == "__main__":
    sys.exit(main())
