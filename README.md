# PCAP Analyzer

A desktop app for uploading, storing, and downloading .pcap/.pcapng files using Electron (frontend) and Flask (backend).

## Project folder Structure

NetSleuth/
│
├── frontend/              # UI Layer (Electron frontend)
│   ├── src/
│   │   ├── components/        # UI components like upload forms, report viewer
│   │   └── assets/            # Static assets (icons, images, CSS, logos)
│
├── backend/                   # Python backend (analysis + APIs)
│   ├── services/              # Core logic (pcap parsing, analysis, ML, Gemini API)
│   ├── routes/                # API endpoints (upload, analyze, report generation)
│   └── utils/                 # Helpers (DB connection, report builder, common funcs)
│
├── database/                  # Local database files
│   └── migrations/            # Schema change history / version control
│
├── reports/                   # Generated analysis reports (PDF/HTML)
│
└── README.md



## Setup Instructions

### 1. Backend (Flask)

- Open a terminal in the `backend` folder:
  ```sh
  pip install -r requirements.txt
  python app.py
  ```
  The backend will run on http://localhost:5000

### 2. Electron App

- Open a terminal in the `electron-app` folder:
  ```sh
  npm install
  npm start
  ```
  This will launch the Electron desktop app and auto-start the backend in dev mode.

### Usage
- Upload `.pcap` or `.pcapng` files via the UI.
- View, download, and manage files in the table.

---

- Flask API endpoints:
  - `POST /upload` — Upload a PCAP file
  - `GET /files` — List all uploaded files
  - `GET /download/<id>` — Download a file by ID
