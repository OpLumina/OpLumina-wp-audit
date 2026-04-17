# WP-Audit

**Open-source WordPress vulnerability scanner. No API keys, runs local, editable CVE database.**

Scans WordPress installations for exposed sensitive files, version disclosures, misconfigured paths, and plugins with known CVEs. Everything runs on your machine — no external services, no accounts, no telemetry.

---

## Features

- **Path & file checks** — 150+ built-in checks covering credentials, backups, logs, shells, staging artifacts, auth endpoints, and more
- **Passive plugin detection** — extracts plugin slugs from page source without active enumeration
- **Version fingerprinting** — fetches `readme.txt` from detected plugins to determine installed version
- **CVE matching** — built-in database of 130+ plugin vulnerabilities matched against detected versions
- **Tor support** — route all traffic through Tor with DNS-over-SOCKS5 (`socks5h`) and exit node verification
- **Subdomain discovery** — passive enumeration via crt.sh
- **False positive reduction** — homepage hash comparison to filter redirects masquerading as findings
- **Flexible output** — JSON or plaintext report
- **Editable vuln DB** — extend the built-in database with a pipe-delimited external file

---

## Requirements

```
Python 3.9+
httpx[socks]
packaging
```

Install dependencies:
```bash
pip install httpx[socks] packaging
```

---

## Usage

### Basic scan
```bash
python wp-audit.py --url https://target.com
```

### Through Tor (recommended for authorized remote testing)
```bash
python wp-audit.py --url https://target.com --tor
```

### Custom proxy
```bash
python wp-audit.py --url https://target.com --proxy socks5h://127.0.0.1:9050
python wp-audit.py --url https://target.com --proxy http://127.0.0.1:8080
```

### Filter by severity
```bash
python wp-audit.py --url https://target.com --only CRIT
python wp-audit.py --url https://target.com --only HIGH
```

### Save report
```bash
python wp-audit.py --url https://target.com --output report.json
python wp-audit.py --url https://target.com --output report.txt
```

### Slow scan with throttling (evade rate limiting)
```bash
python wp-audit.py --url https://target.com --throttle 5,14 --threads 1
```

### Skip phases
```bash
python wp-audit.py --url https://target.com --skip-paths
python wp-audit.py --url https://target.com --skip-enum
python wp-audit.py --url https://target.com --skip-passive
```

### Subdomain discovery + scan
```bash
python wp-audit.py --url https://target.com --subdomains
```

### Custom headers
```bash
python wp-audit.py --url https://target.com --header "Authorization: Bearer token"
python wp-audit.py --url https://target.com --header "X-Custom: value"
```

### Rotate user agents
```bash
python wp-audit.py --url https://target.com --random-user-agent
```

### Filter by category
```bash
python wp-audit.py --url https://target.com --categories sensitive backup
python wp-audit.py --url https://target.com --categories auth scripts
```

### Exclude status codes
```bash
python wp-audit.py --url https://target.com --exclude-codes 403
```

---

## All Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | required | Target URL |
| `--tor` | off | Route through Tor, verify exit node |
| `--proxy` | none | Proxy URL with scheme (`socks5h://`, `http://`) |
| `--threads` | 10 | Concurrent requests |
| `--throttle` | 0.1 | Delay between requests in seconds. Accepts range: `5,14` |
| `--random-user-agent` | off | Rotate user agents per request |
| `--user-agent` | none | Override user agent string |
| `--header` | none | Extra header, repeatable (`Key:Value`) |
| `--only` | none | Severity filter: `CRIT`, `HIGH`, `MED`, `INFO` |
| `--categories` | all | Path categories to check (space-separated) |
| `--exclude-codes` | none | HTTP status codes to ignore |
| `--output` | none | Save report to file (`.json` or `.txt`) |
| `--vuln-db` | none | External plugin vuln DB file |
| `--paths` | none | Extra paths file |
| `--plugins` | none | Extra plugin slugs file |
| `--subdomains` | off | Passive subdomain discovery via crt.sh |
| `--skip-paths` | off | Skip path & file checks |
| `--skip-passive` | off | Skip passive plugin detection |
| `--skip-enum` | off | Skip wordlist plugin enumeration |

---

## Path Categories

| Category | What it checks |
|----------|---------------|
| `recon` | Version disclosure, REST API endpoints, feeds, sitemaps |
| `sensitive` | Config files, credentials, `.env`, SSH keys, CI/CD leaks |
| `backup` | SQL dumps, zip archives, backup directories |
| `auth` | Login pages, admin endpoints, phpMyAdmin |
| `scripts` | Install scripts, web shells, potential backdoors |
| `uploads` | Directory listing on uploads, plugins, themes |
| `staging` | Dev/test/beta directories, OS artifacts |
| `users` | Author archives, REST API user enumeration |

---

## External Vuln DB Format

Extend the built-in CVE database with a pipe-delimited file:

```
# slug | SEV | Name | vuln_below | fixed | CVE | description
my-plugin | HIGH | My Plugin | 2.1.0 | 2.1.0 | CVE-2024-1234 | Stored XSS via input field
```

```bash
python wp-audit.py --url https://target.com --vuln-db my_vulns.txt
```

---

## External Paths File

Add custom paths to check:

```
/custom-admin/ | HIGH | Custom admin panel | auth
/api/v1/users  | HIGH | Unauthenticated API | sensitive
```

```bash
python wp-audit.py --url https://target.com --paths extra_paths.txt
```

---

## Scan Phases

| Phase | Flag to skip | Description |
|-------|-------------|-------------|
| 1. Path checks | `--skip-paths` | Requests each path, reports 200/403 responses |
| 2. Passive detection | `--skip-passive` | Fetches homepage source, extracts plugin slugs and WP version |
| 3. Plugin enumeration | `--skip-enum` | Probes each slug in the vuln DB, fetches readme for version |

Plugins found in Phase 2 are skipped in Phase 3 to avoid duplicate requests.

---

## Tor Setup

Requires Tor running locally:

```bash
# Debian/Ubuntu
sudo apt install tor
sudo systemctl start tor

# Verify
systemctl status tor@default
```

The scanner uses `socks5h://` which routes DNS resolution through Tor, preventing DNS leaks. On startup with `--tor`, the scanner verifies the exit node via `check.torproject.org/api/ip` and aborts if the connection is not confirmed as a Tor exit node.

```
--tor and --proxy are mutually exclusive.
```

---

## Legal

This tool is for **authorized security testing only**.

> Unauthorized scanning of computer systems may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and equivalent laws in your jurisdiction. You must have explicit written authorization from the system owner before scanning any target. The authors of this tool accept no liability for unauthorized or illegal use.

Every scan requires confirmation at runtime:
```
Type 'I HAVE AUTHORIZATION' OR 'ACK' to continue:
```

---

## License

MIT
