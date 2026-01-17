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

