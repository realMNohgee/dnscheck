# DNSCheck 🌐

**DNS record lookup tool with SPF/DMARC parsing.** Zero dependencies, pure Python stdlib.

Look up A, AAAA, MX, TXT, NS, CNAME, SOA, and PTR records. Uses raw DNS wire format queries (UDP) with fallback to `dig` and `host` commands. Parses and displays MX priority ordering and TXT records with SPF/DMARC detection.

> Part of the **Trust & Reliability Layer for Agentic AI**

## Why it exists

`dig` and `nslookup` are standard but their output is hard to parse in scripts. DNSCheck provides structured output (text tables or JSON) for all common DNS record types, with built-in SPF and DMARC parsing. Useful for debugging DNS configurations, email deliverability checks, and domain audits.

## One tool, many domains

| Domain | What DNSCheck does |
|---|---|
| 📧 **Email** | Check MX records and SPF/DMARC configuration |
| 🌐 **Web** | Look up A/AAAA/CNAME records for domains |
| 🔍 **Debugging** | Quick DNS lookups with structured output |
| 🛡️ **Security** | Audit TXT records for SPF/DMARC/DKIM |
| 🤖 **Automation** | JSON output for monitoring scripts |

## Install
```bash
git clone git@github.com:realMNohgee/dnscheck.git
cd dnscheck
python3 dnscheck.py --help
```

## Quick start
```bash
# Look up A records
python3 dnscheck.py lookup A google.com

# Look up MX records
python3 dnscheck.py lookup MX gmail.com

# Show MX records sorted by priority
python3 dnscheck.py mx-priority gmail.com

# All common record types
python3 dnscheck.py all google.com

# TXT records with SPF/DMARC parsing
python3 dnscheck.py txt google.com

# JSON output
python3 dnscheck.py --format json lookup A google.com
```

## Commands

| Command | Description |
|---|---|
| `lookup <TYPE> <domain>` | Look up a specific record type |
| `all <domain>` | Look up all common record types (A, AAAA, MX, TXT, NS, CNAME, SOA) |
| `mx-priority <domain>` | Show MX records sorted by priority |
| `txt <domain>` | Show TXT records with SPF/DMARC parsing |

## Supported Record Types

| Type | Description | Resolution Method |
|---|---|---|
| A | IPv4 address | DNS wire + socket fallback |
| AAAA | IPv6 address | DNS wire + socket fallback |
| MX | Mail exchange | DNS wire + dig/host fallback |
| TXT | Text records | DNS wire + dig/host fallback |
| NS | Nameserver | DNS wire + dig/host fallback |
| CNAME | Canonical name | DNS wire + dig/host fallback |
| SOA | Start of authority | DNS wire + dig/host fallback |
| PTR | Reverse pointer | DNS wire + dig/host fallback |

## License
MIT — see [LICENSE](LICENSE).

---
🧰 **[Tool on Hermtica Marketplace](https://hermtica.com/marketplace)**
