
# URL Guard 🛡

**Advanced Terminal URL Security Scanner** — analyze any URL before you open it.

URL Guard inspects redirects, HTTPS/SSL, DNS, WHOIS, IP geolocation,
and applies phishing heuristics plus optional VirusTotal reputation
checks, then produces a 0–100 risk score and verdict. Built for
defensive security awareness and education.

---

## Features

- URL validation and normalization (auto-adds `https://`)
- Full redirect chain tracing, loop detection, shortener expansion
  (bit.ly, tinyurl.com, t.co, rb.gy, cutt.ly, is.gd, goo.gl, etc.)
- HTTPS/SSL certificate inspection (issuer, expiry, self-signed detection)
- DNS record lookups (A, AAAA, MX, NS, TXT, CNAME, reverse DNS)
- WHOIS lookup with newly-registered-domain warning
- IP geolocation (ASN, ISP, country, region, city, lat/long)
- Phishing heuristics (IP-as-host, punycode/homograph, typosquatting,
  suspicious keywords, mixed HTTP/HTTPS, suspicious redirect params, etc.)
- Optional VirusTotal reputation lookup
- Rich terminal UI (panels, tables, progress spinner)
- JSON and HTML report export
- Batch scanning from a text file
- Persistent scan logging

---

## Installation

### Linux

```bash
git clone <your-repo-url> url_guard
cd url_guard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
