# 🕵️ NetSleuth — PCAP Analyzer

> A desktop network-forensics tool that ingests packet captures (`.pcap` / `.pcapng`) and turns raw traffic into readable intelligence: hosts, devices, domains, flows, and AI-assisted threat verdicts.

Built as a cyber-security coursework project. NetSleuth pairs an **Electron** desktop UI with a **Flask + Scapy** analysis backend and a local **SQLite** store, so captures never leave your machine.

**📦 Repository:** [github.com/Charith-Aloka/PCAP-Analizer](https://github.com/Charith-Aloka/PCAP-Analizer)

---

## ✨ Features

- 📤 **Upload & manage captures** — drag in `.pcap`, `.pcapng`, `.cap`, `.dmp` and more; duplicates are detected by SHA-256 so the same capture is never stored twice.
- 🔬 **Deep packet analysis with Scapy** — extracts:
  - Unique **IP addresses** and how often each appears
  - **Devices** on the network (IP ↔ MAC ↔ hostname, first/last seen)
  - **Domains** accessed, resolved from **DNS queries, HTTP Host headers, and TLS SNI**
  - **Flows** (5-tuple src/dst/port/protocol) with packet counts, byte counts, and time windows
- 📈 **Protocol & volume summary** — packets and bytes broken down per protocol.
- 👤 **User / host activity view** — per-host timeline correlating IP, MAC, hostname, and top domains.
- 🤖 **AI threat assessment** — optional **Google Gemini** integration classifies observed domains as `benign` / `suspicious` / `malicious` with reasoning.
- 🔒 **Local-first & private** — all data lives in a local SQLite database; nothing is uploaded except the domain strings you explicitly send for AI assessment.

---

## 🧰 Tech Stack

| Layer      | Technology                                   |
|------------|----------------------------------------------|
| 🖥️ Frontend | Electron 31, HTML/CSS/JS, Axios              |
| ⚙️ Backend   | Python, Flask, Flask-CORS                    |
| 🔬 Analysis  | Scapy (packet parsing)                       |
| 🤖 AI        | Google Generative AI (Gemini)               |
| 💾 Storage   | SQLite                                        |

---

## 📁 Project Structure

```
PCAP-Analizer/
├── backend/                  # Flask API + analysis engine
│   ├── app.py                # App entry point, route registration, health checks
│   ├── config/               # Gemini API configuration (git-ignored secrets)
│   ├── routes/
│   │   ├── ingest.py         # Upload / list / download / delete PCAPs
│   │   └── analyze.py        # Run analysis + fetch IPs, devices, domains, flows, threats
│   ├── services/
│   │   ├── analyzer.py       # Scapy parser → SQLite (IPs, devices, domains, flows)
│   │   ├── gemini_client.py  # Gemini API wrapper
│   │   └── threat_assessment.py  # Domain threat classification
│   ├── utils/db.py           # SQLite schema + connection helpers
│   └── requirements.txt
│
├── electron-app/             # Desktop UI
│   ├── main.js               # Electron main process (spawns backend in dev)
│   ├── preload.js
│   └── src/                  # HTML / CSS / renderer JS
│
├── database/                 # Local SQLite DB (git-ignored)
└── README.md
```

---

## 🚀 Getting Started

### 📋 Prerequisites

- **Python 3.10+**
- **Node.js 18+** and npm
- (Optional) a **Google Gemini API key** for threat assessment

### 1️⃣ Clone

```sh
git clone https://github.com/Charith-Aloka/PCAP-Analizer.git
cd PCAP-Analizer
```

### 2️⃣ Backend (Flask)

```sh
cd backend
pip install -r requirements.txt
python app.py
```

The API starts on **http://localhost:5000** and auto-creates the SQLite database on first run.

### 3️⃣ Desktop App (Electron)

In a second terminal:

```sh
cd electron-app
npm install
npm start
```

`npm start` launches the desktop app; in dev mode it can auto-start the backend for you.

### 4️⃣ (Optional) Enable AI Threat Assessment 🤖

Add your Gemini API key to `backend/config/gemini_config.py` (this file is git-ignored so your key stays local). Without a key, all core analysis features still work — only the domain threat verdicts are disabled.

---

## 🖱️ Usage

1. Launch the app and **upload** one or more capture files.
2. Select a capture and **Analyze** it — Scapy parses every packet into the database.
3. Explore the results tabs: **IPs**, **Devices**, **Domains**, **Flows**, and **User Activity** (all paginated).
4. Optionally run **Threat Assessment** to have Gemini classify the observed domains.

---

## 🔌 API Reference

Base URL: `http://localhost:5000/api`

### 📥 Ingest

| Method   | Endpoint             | Description                          |
|----------|----------------------|--------------------------------------|
| `POST`   | `/upload`            | Upload one or more PCAP files        |
| `GET`    | `/files`             | List all stored captures             |
| `GET`    | `/file/<id>/info`    | Metadata for a single capture        |
| `GET`    | `/download/<id>`     | Download the original capture        |
| `DELETE` | `/delete/<id>`       | Delete one capture                   |
| `DELETE` | `/files`             | Delete all captures                  |

### 🔬 Analyze

| Method | Endpoint                             | Description                                   |
|--------|--------------------------------------|-----------------------------------------------|
| `POST` | `/analyze/<id>`                      | Run Scapy analysis on a capture               |
| `GET`  | `/analysis/<id>/summary`             | Counts + protocol/packet/byte breakdown       |
| `GET`  | `/analysis/<id>/ips`                 | Observed IPs (paginated)                       |
| `GET`  | `/analysis/<id>/devices`             | Devices: IP / MAC / hostname (paginated)      |
| `GET`  | `/analysis/<id>/domains`             | Domains via DNS / HTTP / TLS (paginated)      |
| `GET`  | `/analysis/<id>/flows`               | Network flows (paginated)                      |
| `GET`  | `/analysis/<id>/user_activity`       | Per-host activity timeline (paginated)        |
| `POST` | `/analysis/<id>/assess_domains`      | Trigger Gemini threat assessment              |
| `GET`  | `/analysis/<id>/assessments`         | Fetch stored domain verdicts (`?summary=true` for counts) |

List endpoints accept `?page=` and `?limit=` (default 10, max 100).

---

## 🔐 Security & Privacy

Packet captures are among the most sensitive artefacts in security work — they can contain credentials, session tokens, personal data, and internal network layout. NetSleuth is built **local-first** to keep that data under your control.

### 💾 Data handling
- **Local-only storage.** Captures and all extracted analysis live in a local SQLite database (`database/netsleuth.db`). Nothing is sent to a remote server by the core workflow.
- **Minimal external exposure.** The *only* data that ever leaves your machine is the list of **domain strings** you explicitly submit for AI threat assessment — and only if you have configured a Gemini API key. Raw packets, payloads, IPs, and MACs are never transmitted.
- **Integrity & dedup.** Every upload is hashed with **SHA-256**; identical captures are detected and stored once.

### 🗝️ Secret management
- API keys live only in `backend/config/gemini_config.py`, which is **git-ignored** — verified with `git check-ignore`.
- Captures and databases (`*.pcap`, `*.pcapng`, `*.db`) are **git-ignored** so traffic data can never be accidentally committed or pushed.
- **Never commit secrets.** Prefer an environment variable or an untracked local config; rotate any key that is exposed. Run `git status` before every commit to confirm no capture or key file is staged.

### ⚖️ Responsible use
- Only capture and analyze traffic on networks and systems you **own or are explicitly authorized** to inspect. Unauthorized interception may be illegal in your jurisdiction.
- This project is intended for **education, lab environments, and authorized security assessments** only.


---

## 📄 License

MIT — see `electron-app/package.json`.

