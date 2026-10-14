# mail-dns-audit

[![tests](https://github.com/francisco-vilaca/mail-dns-audit/actions/workflows/tests.yml/badge.svg)](https://github.com/francisco-vilaca/mail-dns-audit/actions/workflows/tests.yml) ![license](https://img.shields.io/badge/license-MIT-blue)

Audit the DNS records that decide whether a domain's email lands in the inbox, in the spam folder, or nowhere.

One command checks **MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT and BIMI** and tells you what is wrong in plain language, with a non-zero exit code when something is broken, so it also works in scripts and monitoring.

```
$ ./mail_dns_audit.py example.com -s selector1

mail-dns-audit 0.1.0: example.com

  MX       OK     2 MX record(s)
  SPF      OK     Hard fail for unlisted senders (-all)
  SPF      OK     1/10 DNS lookups
  DKIM     OK     Selector 'selector1': RSA 2048-bit key
  DMARC    WARN   p=none: monitoring only, spoofed email is not blocked
                  └ Once reports look clean, move to p=quarantine and then p=reject.
  DMARC    WARN   No rua= tag: you receive no aggregate reports
  MTA-STS  OK     Policy record present
  TLS-RPT  OK     Reporting enabled
  BIMI     INFO   Not configured (optional; brand logo in supporting inboxes)

  Summary: 6 OK, 1 INFO, 2 WARN
```

## What it checks

| Check | What it looks for |
|---|---|
| **MX** | Records exist, every MX host resolves, null MX (RFC 7505) |
| **SPF** | Exactly one record, `all` qualifier (`+all` / `?all` / missing), deprecated `ptr`, **recursive count of DNS lookups against the 10-lookup limit**, void lookups, include loops and includes pointing to domains with no SPF |
| **DKIM** | Key present for each selector, revoked keys (`p=`), **RSA key size parsed from the key itself** (1024-bit flagged), Ed25519 |
| **DMARC** | Record present and unique, policy (`none` / `quarantine` / `reject`), `pct`, aggregate reports (`rua`), subdomains inheriting the parent policy (`sp`) |
| **MTA-STS** | `_mta-sts` record; with `--fetch-mta-sts`, downloads the policy and checks the mode |
| **TLS-RPT** | `_smtp._tls` reporting record |
| **BIMI** | `default._bimi` record (informational) |

It is **read-only**: it only makes DNS queries (plus one HTTPS GET with `--fetch-mta-sts`). It never connects to mail servers or sends email.

## Install

Requires Python 3.9+ and [dnspython](https://www.dnspython.org/).

Install it as a command with [pipx](https://pipx.pypa.io/):

```bash
pipx install git+https://github.com/francisco-vilaca/mail-dns-audit.git
mail-dns-audit example.com
```

Or run it straight from a clone:

```bash
git clone https://github.com/francisco-vilaca/mail-dns-audit.git
cd mail-dns-audit
pip install -r requirements.txt
./mail_dns_audit.py example.com
```

## Usage

```bash
./mail_dns_audit.py example.com                      # common DKIM selectors are tried automatically
./mail_dns_audit.py example.com -s google            # Google Workspace
./mail_dns_audit.py example.com -s selector1 -s selector2   # Microsoft 365
./mail_dns_audit.py example.com example.org --json   # several domains, JSON output
./mail_dns_audit.py example.com --nameserver 1.1.1.1 --fetch-mta-sts -v
```

DKIM selectors cannot be listed through DNS. If yours is not in the built-in list, find it in the `DKIM-Signature: ... s=<selector>` header of an email sent from the domain and pass it with `-s`.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No failures (warnings may exist) |
| `1` | At least one `FAIL` |
| `2` | DNS error or domain does not exist |

That makes it easy to run from cron or a monitoring system and alert when, for example, someone deletes the DMARC record or an SPF include pushes you over the lookup limit.

## Tests

```bash
pip install pytest
python -m pytest
```

The tests use an in-memory resolver, so they run offline and cover the tricky cases: SPF lookup counting across nested includes, include loops, multiple SPF records, DMARC inheritance for subdomains, and DKIM key-size parsing for both SubjectPublicKeyInfo and PKCS#1 keys.

## License

MIT, see [LICENSE](LICENSE).
