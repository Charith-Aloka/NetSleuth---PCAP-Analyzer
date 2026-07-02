# 🕵️ NetSleuth - PCAP Analyzer

> 🔍 A desktop network-forensics tool that ingests packet captures (`.pcap` / `.pcapng`) and turns raw traffic into actionable security intelligence - hosts, devices, domains, flows, an interactive network map, AI-assisted threat verdicts, live IP reputation lookups, and a natural-language chat assistant.

Built as a cyber-security coursework project, **NetSleuth** pairs an **Electron** desktop UI with a **Flask + Scapy** analysis backend and a local **SQLite** store. Captures stay on your machine; the only external calls are optional threat-intelligence / AI lookups you explicitly trigger.

**📦 Repository:** [github.com/Charith-Aloka/PCAP-Analizer](https://github.com/Charith-Aloka/PCAP-Analizer)

---

## ✨ Features

NetSleuth is organized into five workspaces (see the top navigation):

### 📁 Files
- Drag-and-drop upload of `.pcap`, `.pcapng`, `.cap` (and more).
- **SHA-256 deduplication** - identical captures are detected and stored once.
- List, download, and delete captures. Handles files up to **500 MB**.

### 🔬 Analysis
- **Deep packet parsing with Scapy**, extracting:
  - 🌐 Unique **IP addresses** and observation counts
  - 💻 **Devices** (IP ↔ MAC ↔ hostname, first/last seen)
  - 🔗 **Domains**, resolved from **DNS queries, HTTP Host headers, and TLS SNI**
  - 📊 **Flows** (5-tuple) with packet counts, byte counts, and time windows
  - 📈 **Protocol & volume** breakdown, plus a per-host **user-activity** timeline
- 🤖 **AI domain classification** - Google **Gemini** labels each domain `safe` / `suspicious` / `malicious` with a short explanation, processed in resilient batches with retries and fallbacks.

### 🔎 IP Investigation
- Deep-dive report for any single IP: overview, upload/download volumes, protocol mix, domains accessed, and top incoming/outgoing connections.
- 🧠 **AI behavior analysis** (Gemini) returns a **risk level** (low → critical), key findings, security recommendations, and detected anomalies.

### 🕸️ Network Map
- Interactive **topology graph** of the capture: nodes are hosts (internal vs. external), edges are connections.
- Nodes are colored by **threat level** (safe / suspicious / malicious) based on the domains they touched, with live stats on node/edge counts and threats.

### 🛡️ Threat Intelligence
- Live **IP reputation** lookups via **VirusTotal** and **AbuseIPDB**.
- Single-IP checks, **batch** checks, and a one-click **scan of all external IPs** in a capture.
- Combines sources into a weighted **threat score** + level (clean → critical), with 24-hour caching and free-tier rate-limit handling.

### 🤖 AI Assistant
- Natural-language **chatbot** (Gemini) that answers questions about your traffic ("What are the top threats?", "Show me the most active IPs").
- Pulls live context from the database (summary stats, protocols, top talkers, detected threats), keeps conversation history, and offers suggested questions.

### 🔒 Local-first & private
All captures and analysis live in a local SQLite database - nothing is uploaded except the domain strings / IPs you explicitly send to Gemini, VirusTotal, or AbuseIPDB.

---

## 🧰 Tech Stack

| Layer      | Technology                                        |
|------------|---------------------------------------------------|
| 🖥️ Frontend | Electron 31, HTML/CSS/JS, Axios, Font Awesome    |
| ⚙️ Backend  | Python, Flask, Flask-CORS                         |
| 🔬 Analysis | Scapy (packet parsing)                            |
| 🤖 AI       | Google Generative AI (Gemini)                    |
| 🛡️ Threat Intel | VirusTotal API, AbuseIPDB API                |
| 💾 Storage  | SQLite                                            |
| 🔧 Config   | python-dotenv (`.env`)                            |

---

## 📁 Project Structure

```
PCAP-Analizer/
├── backend/                        # Flask API + analysis engine
│   ├── app.py                      # App entry, blueprint registration, health checks
│   ├── config/
│   │   ├── gemini.py               # Gemini settings from env vars
│   │   ├── gemini_config.py        # Gemini API key (git-ignored)
│   │   └── threat_intel_config.py  # VirusTotal / AbuseIPDB config (reads .env)
│   ├── routes/
│   │   ├── ingest.py               # Upload / list / download / delete PCAPs
│   │   ├── analyze.py              # Run analysis + fetch IPs, devices, domains, flows
│   │   ├── investigation.py        # Per-IP deep-dive + AI behavior report
│   │   ├── network.py              # Network topology graph data
│   │   ├── threat_intel.py         # VirusTotal / AbuseIPDB IP reputation
│   │   └── chat.py                 # AI chat assistant endpoints
│   ├── services/
│   │   ├── analyzer.py             # Scapy parser → SQLite
│   │   ├── gemini_service.py       # Gemini text gen + domain classification
│   │   ├── ip_investigator.py      # Gemini-powered IP behavior analysis
│   │   ├── chat_service.py         # Chatbot context builder + Gemini calls
│   │   └── threat_intel_service.py # VirusTotal + AbuseIPDB client + scoring
│   ├── utils/db.py                 # SQLite schema + connection helpers
│   ├── .env                        # API keys (git-ignored)
│   └── requirements.txt
│
├── electron-app/                   # Desktop UI
│   ├── main.js                     # Electron main process (spawns backend in dev)
│   ├── preload.js
│   └── src/
│       ├── index.html / analysis.html / investigation.html
│       ├── network.html / chat.html
│       ├── css/                    # Per-page stylesheets
│       └── js/                     # Renderer logic (api, files, analysis, network, chat…)
│
├── database/                       # Local SQLite DB (git-ignored)
└── README.md
```

---

## 🚀 Getting Started

### 📋 Prerequisites

- **Python 3.10+**
- **Node.js 18+** and npm
- (Optional) API keys for **Google Gemini**, **VirusTotal**, and **AbuseIPDB** - all have free tiers

### 1️⃣ Clone

```sh
git clone https://github.com/Charith-Aloka/PCAP-Analizer.git
cd PCAP-Analizer
```

### 2️⃣ Configure API keys (optional but recommended)

Create `backend/.env` with any keys you have. All features degrade gracefully - core Scapy analysis works with no keys at all.

```env
GEMINI_API_KEY=your_gemini_key
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
```

> ⚠️ Never commit real keys. `backend/.env` is git-ignored. Get keys from [Google AI Studio](https://aistudio.google.com/), [VirusTotal](https://www.virustotal.com/), and [AbuseIPDB](https://www.abuseipdb.com/).

### 3️⃣ Backend (Flask)

```sh
cd backend
pip install -r requirements.txt
python app.py
```

The API starts on **http://localhost:5000** and auto-creates the SQLite database on first run.

### 4️⃣ Desktop App (Electron)

In a second terminal:

```sh
cd electron-app
npm install
npm start
```

`npm start` launches the desktop app; in dev mode it can auto-start the backend for you.

---

## 🖱️ Usage

1. 📤 **Upload** one or more capture files on the **Files** page.
2. 🔬 Open **Analysis**, pick a capture, and run it - Scapy parses every packet into the database. Optionally run **AI domain classification**.
3. 🔎 Use **IP Investigation** to deep-dive any IP and get an AI risk assessment.
4. 🕸️ Explore the **Network Map** to see who talked to whom and where the threats are.
5. 🛡️ Run **Threat Intelligence** to check external IPs against VirusTotal & AbuseIPDB.
6. 🤖 Ask the **AI Assistant** natural-language questions about the capture.

---

## 🔌 API Reference

Base URL: `http://localhost:5000/api`

### 📥 Ingest
| Method   | Endpoint             | Description                     |
|----------|----------------------|---------------------------------|
| `POST`   | `/upload`            | Upload one or more PCAP files   |
| `GET`    | `/files`             | List all stored captures        |
| `GET`    | `/file/<id>/info`    | Metadata for a single capture   |
| `GET`    | `/download/<id>`     | Download the original capture   |
| `DELETE` | `/delete/<id>`       | Delete one capture              |
| `DELETE` | `/files`             | Delete all captures             |

### 🔬 Analyze
| Method | Endpoint                          | Description                              |
|--------|-----------------------------------|------------------------------------------|
| `POST` | `/analyze/<id>`                   | Run Scapy analysis on a capture          |
| `GET`  | `/analysis/<id>/summary`          | Counts + protocol/packet/byte breakdown  |
| `GET`  | `/analysis/<id>/ips`              | Observed IPs (paginated)                 |
| `GET`  | `/analysis/<id>/devices`          | Devices: IP / MAC / hostname (paginated) |
| `GET`  | `/analysis/<id>/domains`          | Domains via DNS / HTTP / TLS (paginated) |
| `GET`  | `/analysis/<id>/flows`            | Network flows (paginated)                |
| `GET`  | `/analysis/<id>/user_activity`    | Per-host activity timeline (paginated)   |
| `POST` | `/analysis/<id>/assess_domains`   | Trigger Gemini domain classification     |
| `GET`  | `/analysis/<id>/assessments`      | Fetch domain verdicts (`?summary=true`)  |

### 🔎 Investigation
| Method | Endpoint                          | Description                              |
|--------|-----------------------------------|------------------------------------------|
| `GET`  | `/investigation/<pcap_id>/ips`    | List IPs available for investigation     |
| `GET`  | `/investigation/<pcap_id>/<ip>`   | Full IP report + Gemini AI analysis      |

### 🕸️ Network
| Method | Endpoint                     | Description                              |
|--------|------------------------------|------------------------------------------|
| `GET`  | `/network-graph/<pcap_id>`   | Nodes + edges + stats for the topology   |

### 🛡️ Threat Intelligence
| Method | Endpoint                              | Description                              |
|--------|---------------------------------------|------------------------------------------|
| `GET`  | `/threat-intel/check/<ip>`            | Reputation for one IP (VT + AbuseIPDB)   |
| `POST` | `/threat-intel/batch`                 | Check up to 50 IPs (`{"ips":[...]}`)     |
| `GET`  | `/threat-intel/status`                | Which services are configured            |
| `POST` | `/threat-intel/pcap/<id>/scan`        | Scan all external IPs in a capture       |

### 🤖 Chat
| Method | Endpoint             | Description                                  |
|--------|----------------------|----------------------------------------------|
| `POST` | `/chat/message`      | Send a message (`{"message","pcap_id?"}`)    |
| `GET`  | `/chat/history`      | Get conversation history                     |
| `POST` | `/chat/clear`        | Clear conversation history                   |
| `GET`  | `/chat/suggestions`  | Suggested questions                          |

List endpoints accept `?page=` and `?limit=` (default 10, max 100).

---

## 🔐 Security & Privacy

Packet captures are among the most sensitive artefacts in security work - they can contain credentials, session tokens, personal data, and internal network layout. NetSleuth is built **local-first** to keep that data under your control.

### 💾 Data handling
- 🏠 **Local-only storage.** Captures and all extracted analysis live in a local SQLite database (`database/netsleuth.db`).
- 📡 **Minimal external exposure.** The only data that leaves your machine is what you explicitly submit for enrichment - **domain strings** (to Gemini) and **IP addresses** (to VirusTotal / AbuseIPDB). Raw packets and payloads are never transmitted.
- 🔑 **Integrity & dedup.** Every upload is hashed with **SHA-256**; duplicates are detected and stored once.

### 🗝️ Secret management
- 🚫 API keys belong in `backend/.env` (git-ignored). `backend/config/gemini_config.py` is also git-ignored.
- 🙈 Captures and databases (`*.pcap`, `*.pcapng`, `*.db`) are git-ignored so traffic data is never accidentally committed.
- ⚠️ **Never commit secrets.** Prefer `.env`, rotate any exposed key, and run `git status` before every commit.

### ⚖️ Responsible use
- ✅ Only capture and analyze traffic on networks/systems you **own or are authorized** to inspect. Unauthorized interception may be illegal.
- 🎓 Intended for **education, lab environments, and authorized security assessments** only.

---

## 📄 License

MIT - see `electron-app/package.json`.

