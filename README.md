# Zentivox - A Threat Intel Gathering Tool

A Tool to Stay Ahead with Cyber Updates
Zentivox is a powerful, lightweight, and user-friendly desktop application designed to centralize and automate the retrieval of critical cybersecurity updates. In today's rapidly evolving threat landscape, manually tracking new vulnerabilities (CVEs) and cybersecurity news across numerous sources is challenging and time-consuming. Zentivox addresses this by automatically gathering and displaying essential threat intelligence in one convenient location, saving valuable time and ensuring users don't miss crucial information.

The tool aims to provide a reliable alternative to subscribing to multiple, often generalized, cybersecurity newsletters, which may not be purely cybersecurity-focused and often require users to share their email addresses with various companies.

**Zentivox solves this** by consolidating CVE alerts and cyber news in one dashboard—simple, efficient, and fast.

## 🚀 Getting Started

### 🔧 Prerequisites
- Python 3.8+
- Internet connection

### 📦 Install Dependencies

' pip install -r requirements.txt' 

▶️ Run the Tool

' python Zentivox.py '

#### OR you can Download Standalone Desktop Application for Windows and Linux if don't want manually to install.


## 🛠️ Technologies Used:

| Tech              | Purpose                                      |
|------------------|----------------------------------------------|
| Python           | Core language for logic and GUI              |
| `tkinter`        | GUI interface for easy interaction           |
| `aiohttp`        | Async fetching of data                       |
| `feedparser`     | Parsing RSS feeds                            |
| `BeautifulSoup`  | Cleaning up HTML from feeds                  |
| `asyncio`        | Concurrency for non-blocking tasks           |
| `threading`      | Background refresh without UI freeze         |
| `logging`        | Operational diagnostics                      |
| `dateutil`       | Smart date parsing from feeds                |
| `webbrowser`     | Opens threat links with one click            |

---

## ✨ Features

- **Live Threat Feeds** from:
  - NIST NVD
  - CISA Alerts
  - Exploit-DB
- **Cybersecurity News Feeds** from:
  - BleepingComputer
  - The Hacker News
  - Krebs on Security
  - Wired Security
  - Security Affairs
- **Auto Refresh:** Updates every 5 minutes (toggleable)
- **JSON Report Generator:** Save current data for offline viewing or reporting
- **Link Clickability:** Instantly open full CVE or news via embedded browser links
- **Cross-platform:** Works on Windows, Linux (Kali).
---


## 👤 Target Users

- **SOC Analysts / IT Teams** – Stay updated on active threats
- **Students & Educators** – Learn from live, real-world CVE & threat data
- **Freelancers / Hobbyists** – Explore cyber news and exploit info easily
- **Startups & Small Teams** – Centralized threat monitoring without cost

---


## 📈 Future Scope

🌐 Global Feeds: Include more CERT, ISAC, and dark web sources

⚠️ Priority Alerts: Zero-day/high-severity CVE flagging

📱 Mobile App: Real-time push notifications on phones

🤖 AI Integration: News summarization & threat correlation

🔄 Tool Integration: Link with Nmap, Nessus, or scanners

🧑‍🤝‍🧑 Team Collaboration: Shared dashboards, exportable alerts

🌍 Open Source Community: Extend functionality with contributors


## 🤝 Contributing

Welcome to feedback, ideas, and PRs! Help me to make Zentivox a strong open-source cyber tool.

