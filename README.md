# BugBounty Observer

Automated vulnerability intelligence platform monitoring 1500+ publicly traded companies across global stock exchanges for security vulnerabilities.

## Features

- **Global Company Database** — 1565 companies from 13 countries (NYSE, NASDAQ, MOEX, LSE, TSE, HKEX, NSE, CAC40, B3, JSE, Tadawul, ADX)
- **Automated CVE Detection** — scans company domains via Shodan InternetDB
- **Professional Disclosure Reports** — ready-to-send emails with server banners, CVE descriptions, NVD links
- **Threat Intelligence** — monitors GitHub PoCs, phishing domains, CISA KEV, NVD, ThreatFox, OpenPhish
- **Attack Chain Builder** — correlates findings into attack scenarios
- **Weekly Cron Scan** — automated scanning every Sunday

## Coverage

| Country | Companies | Exchange |
|---------|-----------|----------|
| USA | 672 | NYSE/NASDAQ (S&P500) |
| Russia | 261 | MOEX |
| China | 115 | SSE/SZSE/HKEX |
| Japan | 93 | TSE (Nikkei225) |
| Hong Kong | 92 | HKEX |
| India | 87 | NSE/BSE |
| UK | 84 | LSE (FTSE100) |
| France | 65 | Euronext (CAC40) |
| Brazil | 30 | B3 |
| South Africa | 29 | JSE |
| Saudi Arabia | 20 | Tadawul |
| UAE | 15 | ADX/DFM |

## Results (June 2026)

- **844** companies scanned
- **37** with CVE vulnerabilities  
- **25** with fresh CVE 2025-2026
- Countries covered: USA 15, India 5, China 4, HK 4, France 3, Japan 3, UK 1, UAE 1, SA 1

## Quick Start

    git clone https://github.com/berestov0181/bugbounty-observer
    cd bugbounty-observer
    pip install -r requirements.txt
    
    # Scan companies by country
    python3 company_scanner.py USA 100
    python3 company_scanner.py RU 50
    
    # Generate disclosure report
    python3 gen_report.py
    
    # Start full observer
    bash start.sh

## Project Structure

    bugbounty-observer/
    company_scanner.py      # Domain scanner + CVE checker via Shodan InternetDB
    gen_report.py           # Professional disclosure report generator
    observer_core.py        # Core observer engine
    start.sh                # Start all watchers
    observers/              # Threat intelligence watchers
    ai/                     # AI correlation and attack chain modules
    data/global_companies/  # Company database + scan results

## Disclaimer

This tool is for educational and research purposes only.
All findings are reported responsibly following standard disclosure practices.
No exploitation is performed.

## License

MIT License — Andrey Berestov
