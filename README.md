Unlike other scripts, this tool uses "Smart Detection" logic. Even if a page returns "200 OK", the tool analyzes the content to detect false positives (like "Access Denied" titles, JSON errors, or CAPTCHAs). It leverages HTTP/2, Wayback Machine mining, and Hop-by-Hop attacks to bypass modern WAF rules.

🔥 Key Features
🛡️ HTTP/2 Support: Uses httpx to bypass WAF rules that only inspect HTTP/1.1 traffic.

🧠 Smart Detection: Automatically filters out:

Fake 200 OK pages ("Access Denied" in title).

JSON error responses (e.g., {"error": "Forbidden"}).

CAPTCHA pages (ReCaptcha, Cloudflare Turnstile).

Login forms disguised as success.

⛏️ Wayback Machine Mining: Scrapes the last 5 years of history to find forgotten endpoints and old API keys.

⚡ 330+ Bypass Techniques:

Hop-by-Hop Header Stripping (RFC 7239 exploits).

IP Variations: Integer, Hex, Octal, and Private IP spoofing.

HTTP/1.0 Downgrade attacks.

Aggressive Mixed-Case path manipulation (Bit-flipping).

💾 Crash-Safe Output: Uses .jsonl (Append-Only) format. No data loss even if the tool crashes mid-scan.

🤖 WAF Evasion: Dynamic delay adjustment when Rate Limiting (429) or WAF Ban (403) is detected.
## 🔧 Options

| Flag | Description | Recommendation |
| :--- | :--- | :--- |
| `-u`, `--url` | **Required.** Target URL to scan (must return 403 Forbidden). | `https://target.com/admin` |
| `--http2` | **Critical.** Enables HTTP/2 protocol support using `httpx`. Highly recommended to bypass legacy WAF rules. | Always use this! |
| `--waf-detect` | Analyzes response headers/cookies to identify the WAF (Cloudflare, AWS, Akamai, etc.). | Use on first scan. |
| `--wayback` | Scrapes Archive.org for historical 200 OK snapshots and sensitive data mining (API keys, endpoints). | Use for deep recon. |
| `-T`, `--threads` | Number of concurrent threads. | `1` for strict WAFs, `10+` for speed. |
| `-d`, `--delay` | Delay between requests in milliseconds. **Auto-adjusts** if Rate Limiting is detected. | `200` for standard, `1000` for stealth. |
| `-t`, `--timeout` | Max time (in seconds) to wait for a server response. | Default: `10`s. Increase for slow VPNs. |
| `-o`, `--output` | Output file path. Supports `.txt`, `.json`, and `.jsonl`. | Use `.jsonl` for crash safety. |
| `-H`, `--header` | Add custom headers (Cookies, Auth tokens). Can be used multiple times. | `-H "Cookie: sess=xyz"` |
| `-p`, `--proxy` | Send traffic through a proxy (e.g., Burp Suite, ZAP). | `http://127.0.0.1:8080` |
| `--force` | Non-interactive mode. Skips "Continue?" prompts. | Essential for CI/CD or Cron jobs. |
| `-v`, `--verbose` | Enable verbose output to see all attempts and failure reasons. | Good for debugging. |
| `--follow-redirects`| Follow HTTP 3xx redirects automatically. | Default: `False` |

## ⚡ Usage

### 🚀 Production Scan (Recommended)
This mode enables all advanced features: HTTP/2 for WAF evasion, auto-WAF detection, and historical mining via Wayback Machine.

python3 403_bypasser.py -u https://target.com/admin --http2 --waf-detect --wayback


### 🤖 CI/CD & Automation
Designed for cron jobs or pipelines. Runs without user interaction (`--force`) and saves results in a crash-safe JSON Lines format (`.jsonl`).

python3 403_bypasser.py -u https://target.com/secret -o results.jsonl --force


### 🕵️ Authenticated Scan
Simulate an authorized user by passing session cookies or JWT tokens. Essential for testing internal endpoints that require login.

python3 403_bypasser.py -u https://target.com/admin -H "Cookie: session=xyz"


*You can also add multiple headers:*

python3 403_bypasser.py -u https://target.com/api -H "Authorization: Bearer <token>" -H "X-Custom-ID: 123"

