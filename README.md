⚠️ Disclaimer
OSINTZ is built for authorized intelligence gathering — security research, threat intel, and investigations of targets you have permission to investigate. Do not use it for stalking, harassment, or any illegal activity. You
are responsible for complying with the terms of service of every platform it queries and the laws of your jurisdiction.

## ✨ Features

| # | Module | What it does |
|---|--------|--------------|
| 1 | **Email OSINT** | MX / SPF / DMARC records, RDAP registrar data, disposable-domain detection, Gravatar profile + linked accounts, reputation scoring, breach exposure (HIBP), pivot queries |
| 2 | **IP Tracker** | Geolocation, ASN / ISP / org, reverse DNS, VPN / proxy / hosting / mobile flags, Shodan · Censys · AbuseIPDB pivots |
| 3 | **Phone Intel** | Validity checks, country + flag, area, timezone, carrier, line type (flags VOIP burners), all number formats, WhatsApp / Telegram / Truecaller pivots |
| 4 | **TikTok Country** | Account region with flag + country name, profile stats (followers, likes, videos), bio, account creation date |
| 5 | **Discord ID** | Snowflake decode (creation date, age, worker/increment), live profile lookup, badge decoding |
| 6 | **Crypto Tracer** | Auto chain detection (BTC / ETH / LTC / DOGE / TRX / SOL / XMR), balance + USD value, tx history, token holdings, explorer links |
| 7 | **Username Finder** | 31 platforms probed concurrently with live progress bar and marker-based false-positive filtering |

## 🖥️ UI

- Deep-red truecolor theme with gradient banner and rounded frames
- Animated spinners around every network call
- Live progress bar during username sweeps
- Automatic JSON export of results (optional autosave)

## 🚀 Installation



```bash
git clone https://github.com/zyx/osintz.git
cd osintz
pip install -r requirements.txt
python osintz.py
