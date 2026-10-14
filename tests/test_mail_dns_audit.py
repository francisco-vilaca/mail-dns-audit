import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mail_dns_audit as m  # noqa: E402

KEY_1024 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDArCvchc+xsVE9mQK8AzjyHyhNSwJBew17bv3m/nUWMEGVMKQ+3oo70yQiNbDlkPFj"
    "2p2b/BWuhyBySSye4Bqh2AuQVerbcmo/s23osz/l9YHcc0R0IgIzjzEOA6h2GCZA+Caf6acGNktAMlTzMdVmr87ZEt3jWSvAMKcgs4Lz"
    "xwIDAQAB"
)
KEY_2048 = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjFgsDsjqePEMUZpEfLHxsWE7FTPgQg7qq/PWLHVXaHZ5KT2/09T1THkvdP0v"
    "UEZCoqTHLPzkWFBbgjaocVQmQ6es1BKREzUpjvXVaHF9MCK8hCMlyZI5/vUtHEC/BwytIMeQoLDMnu9ddf6IZcZ9UFdABy32bv6AG1dQ"
    "BINzcwGzL5BhvhVZXTPG8SZxggBFxnk+0eHfKxHSN8i1UZQpXcF/+wQZhsn9U9eVmA7gUuP3VXqsWU0HmG/0uCgVwEuk1Lj3SbVLniDF"
    "O5v7BTrAXqjQYpWIV1Zy2thCVgomphCi6ZLkwUqSzpcyyb5FaCPTgVkAPucuWhJLdstz0/smgwIDAQAB"
)
PKCS1_2048 = (
    "MIIBCgKCAQEAjFgsDsjqePEMUZpEfLHxsWE7FTPgQg7qq/PWLHVXaHZ5KT2/09T1THkvdP0vUEZCoqTHLPzkWFBbgjaocVQmQ6es1BKR"
    "EzUpjvXVaHF9MCK8hCMlyZI5/vUtHEC/BwytIMeQoLDMnu9ddf6IZcZ9UFdABy32bv6AG1dQBINzcwGzL5BhvhVZXTPG8SZxggBFxnk+"
    "0eHfKxHSN8i1UZQpXcF/+wQZhsn9U9eVmA7gUuP3VXqsWU0HmG/0uCgVwEuk1Lj3SbVLniDFO5v7BTrAXqjQYpWIV1Zy2thCVgomphCi"
    "6ZLkwUqSzpcyyb5FaCPTgVkAPucuWhJLdstz0/smgwIDAQAB"
)


class FakeDNS:
    """In-memory resolver: txt/mx/addr maps keyed by lowercase name."""

    def __init__(self, txt=None, mx=None, addr=None, fail=(), nxdomain=()):
        self._txt = {k.lower(): v for k, v in (txt or {}).items()}
        self._mx = {k.lower(): v for k, v in (mx or {}).items()}
        self._addr = {k.lower(): v for k, v in (addr or {}).items()}
        self._fail = set(fail)
        self._nx = set(nxdomain)

    def exists(self, name):
        return name.lower() not in self._nx

    def txt(self, name):
        if name.lower() in self._fail:
            raise m.DNSError(f"TXT {name}: Timeout")
        return list(self._txt.get(name.lower(), []))

    def mx(self, name):
        return sorted(self._mx.get(name.lower(), []))

    def addresses(self, name):
        return list(self._addr.get(name.lower(), []))


def healthy(**overrides):
    txt = {
        "example.com": ["v=spf1 include:_spf.mail.test -all", "google-site-verification=abc"],
        "_spf.mail.test": ["v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.0/24 -all"],
        "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
        "selector1._domainkey.example.com": [f"v=DKIM1; k=rsa; p={KEY_2048}"],
        "_mta-sts.example.com": ["v=STSv1; id=20261014"],
        "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:tls@example.com"],
    }
    txt.update(overrides)
    return FakeDNS(
        txt=txt,
        mx={"example.com": [(10, "mx1.mail.test"), (20, "mx2.mail.test")]},
        addr={"mx1.mail.test": ["192.0.2.10"], "mx2.mail.test": ["192.0.2.11"]},
    )


def statuses(findings, check):
    return [f.status for f in findings if f.check == check]


# ------------------------------------------------------------------ key parsing

def test_rsa_bits_spki():
    assert m.rsa_key_bits(KEY_1024) == 1024
    assert m.rsa_key_bits(KEY_2048) == 2048


def test_rsa_bits_pkcs1_and_whitespace():
    spaced = " ".join(PKCS1_2048[i:i + 60] for i in range(0, len(PKCS1_2048), 60))
    assert m.rsa_key_bits(spaced) == 2048


@pytest.mark.parametrize("bad", ["not base64!!", "AAAA", ""])
def test_rsa_bits_rejects_garbage(bad):
    with pytest.raises(ValueError):
        m.rsa_key_bits(bad)


def test_parse_tags():
    assert m.parse_tags("v=DMARC1; p=reject ;rua=mailto:a@b.c") == {
        "v": "DMARC1", "p": "reject", "rua": "mailto:a@b.c"}


# ------------------------------------------------------------------ full audit

def test_healthy_domain_has_no_warnings_or_failures():
    findings = m.audit(healthy(), "example.com", ["selector1"])
    assert not [f for f in findings if f.status in (m.WARN, m.FAIL, m.ERROR)], findings


def test_main_exit_codes_and_json(capsys):
    assert m.main(["example.com", "-s", "selector1", "--json"], client=healthy()) == 0
    data = json.loads(capsys.readouterr().out)
    assert "example.com" in data and data["example.com"][0]["check"] == "MX"

    broken = healthy(**{"example.com": []})  # no SPF
    assert m.main(["example.com", "-s", "selector1"], client=broken) == 1
    assert "No SPF record" in capsys.readouterr().out


def test_dns_error_is_reported_not_raised():
    client = healthy()
    client._fail.add("_dmarc.example.com")
    findings = m.audit(client, "example.com", ["selector1"])
    assert statuses(findings, "DMARC") == [m.ERROR]
    assert m.main(["example.com", "-s", "selector1"], client=client) == 2


def test_nonexistent_domain_stops_early():
    findings = m.audit(FakeDNS(nxdomain={"typo.example"}), "typo.example", ["selector1"])
    assert [(f.check, f.status) for f in findings] == [("DOMAIN", m.ERROR)]


# ------------------------------------------------------------------ MX

def test_mx_missing_and_unresolvable():
    assert statuses(m.check_mx(FakeDNS(), "example.com"), "MX") == [m.FAIL]
    client = FakeDNS(mx={"example.com": [(10, "ghost.mail.test")]})
    assert statuses(m.check_mx(client, "example.com"), "MX") == [m.OK, m.FAIL]


def test_null_mx():
    client = FakeDNS(mx={"example.com": [(0, "")]})
    assert statuses(m.check_mx(client, "example.com"), "MX") == [m.INFO]


# ------------------------------------------------------------------ SPF

def test_spf_multiple_records_is_permerror():
    client = healthy(**{"example.com": ["v=spf1 -all", "v=spf1 ~all"]})
    assert statuses(m.check_spf(client, "example.com"), "SPF") == [m.FAIL]


@pytest.mark.parametrize("record,expected", [
    ("v=spf1 ip4:192.0.2.1 +all", m.FAIL),
    ("v=spf1 ip4:192.0.2.1 all", m.FAIL),
    ("v=spf1 ip4:192.0.2.1 ?all", m.WARN),
    ("v=spf1 ip4:192.0.2.1", m.WARN),
    ("v=spf1 ip4:192.0.2.1 ~all", m.OK),
])
def test_spf_all_qualifier(record, expected):
    client = FakeDNS(txt={"example.com": [record]})
    assert m.check_spf(client, "example.com")[0].status == expected


def test_spf_lookup_limit_exceeded():
    includes = " ".join(f"include:s{i}.test" for i in range(6))
    txt = {"example.com": [f"v=spf1 {includes} -all"]}
    for i in range(6):
        txt[f"s{i}.test"] = ["v=spf1 a mx -all"]  # 2 lookups each
    lookups, voids, problems = m.count_spf_lookups(FakeDNS(txt=txt), "example.com")
    assert lookups == 18 and voids == 0 and problems == []
    assert m.FAIL in statuses(m.check_spf(FakeDNS(txt=txt), "example.com"), "SPF")


def test_spf_include_loop_and_missing_target():
    txt = {
        "example.com": ["v=spf1 include:a.test include:missing.test -all"],
        "a.test": ["v=spf1 include:example.com -all"],
    }
    _, voids, problems = m.count_spf_lookups(FakeDNS(txt=txt), "example.com")
    assert voids == 1
    assert any("loop" in p for p in problems)
    assert any("missing.test has no SPF record" in p for p in problems)


def test_spf_ptr_is_flagged():
    client = FakeDNS(txt={"example.com": ["v=spf1 ptr -all"]})
    messages = [f.message for f in m.check_spf(client, "example.com")]
    assert any("ptr" in msg for msg in messages)


# ------------------------------------------------------------------ DMARC

def test_dmarc_missing_none_and_no_rua():
    assert statuses(m.check_dmarc(FakeDNS(), "example.com"), "DMARC") == [m.FAIL]
    client = FakeDNS(txt={"_dmarc.example.com": ["v=DMARC1; p=none"]})
    assert statuses(m.check_dmarc(client, "example.com"), "DMARC") == [m.WARN, m.WARN]


def test_dmarc_pct_and_invalid_policy():
    client = FakeDNS(txt={"_dmarc.example.com": ["v=DMARC1; p=quarantine; pct=25; rua=mailto:x@example.com"]})
    assert statuses(m.check_dmarc(client, "example.com"), "DMARC") == [m.OK, m.WARN, m.OK]
    client = FakeDNS(txt={"_dmarc.example.com": ["v=DMARC1; p=block"]})
    assert statuses(m.check_dmarc(client, "example.com"), "DMARC") == [m.FAIL]


def test_dmarc_subdomain_inherits_sp():
    client = FakeDNS(txt={"_dmarc.example.com": ["v=DMARC1; p=reject; sp=none; rua=mailto:x@example.com"]})
    findings = m.check_dmarc(client, "news.example.com")
    assert statuses(findings, "DMARC") == [m.INFO, m.WARN, m.OK]


# ------------------------------------------------------------------ DKIM

def test_dkim_key_sizes_and_revoked():
    client = FakeDNS(txt={
        "old._domainkey.example.com": [f"v=DKIM1; k=rsa; p={KEY_1024}"],
        "new._domainkey.example.com": [f"v=DKIM1; k=rsa; p={KEY_2048}"],
        "gone._domainkey.example.com": ["v=DKIM1; p="],
        "ed._domainkey.example.com": ["v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="],
    })
    findings = m.check_dkim(client, "example.com", ["old", "new", "gone", "ed"])
    assert [f.status for f in findings] == [m.WARN, m.OK, m.WARN, m.OK]


def test_dkim_not_found_is_warning_not_failure():
    findings = m.check_dkim(FakeDNS(), "example.com", ["a", "b"])
    assert [f.status for f in findings] == [m.WARN]


# ------------------------------------------------------------------ optional records

def test_optional_records_absent_are_info():
    client = FakeDNS()
    assert m.check_mta_sts(client, "example.com")[0].status == m.INFO
    assert m.check_tlsrpt(client, "example.com")[0].status == m.INFO
    assert m.check_bimi(client, "example.com")[0].status == m.INFO
