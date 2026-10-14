# Changelog

## 0.1.0 (2026-10-14)

- First release: MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT and BIMI checks
- Recursive SPF lookup counting (10-lookup limit), void lookups and include loops
- DKIM RSA key size parsed from the published key
- DMARC inheritance for subdomains
- Text and JSON output, exit codes for scripting and monitoring
- Installable as a command with `pipx install`
