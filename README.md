# SentinelX — Real-Time Autonomous Cyber Defense Platform

Real-Time Multi-Layer Threat Detection, Attack Correlation, AI-Assisted Investigation, and Controlled Automated Response.

---

## 🚀 Project Overview

**SentinelX** is a modern, real-time autonomous security operations center (SOC) and cyber defense platform designed for Windows laboratory environments. It ingests live endpoint, network, and event telemetry, normailzes heterogeneous logs, runs deterministic security rules alongside unsupervised Machine Learning (Isolation Forest) anomaly detection, correlates threats into high-context security incidents, builds attack graphs, maps tactics to MITRE ATT&CK, and recommends containment steps with a controlled dry-run response engine.

---

## 🏗️ Architecture & Processing Pipeline

SentinelX segregates duties across isolated modular components to ensure low-latency processing (< 1s ingestion-to-alert latency) and bounded memory usage.

```
                 LIVE ENVIRONMENT (Windows 10/11)
                                |
        +-----------------------+-----------------------+
        |                       |                       |
        v                       v                       v
     WINDOWS                 ENDPOINT                NETWORK
     EVENTS                  TELEMETRY               TELEMETRY
        |                       |                       |
        +-----------------------+-----------------------+
                                |
                                v
                      WindowsEventCollector (polled every 1s)
                                |
                                v
                       EVENT NORMALIZATION
                                |
                                v
                      REAL-TIME EVENT ENGINE (FastAPI WebSockets)
                                |
        +-----------------------+-----------------------+
        |                       |                       |
        v                       v                       v
     RULES                   BEHAVIORAL              ANOMALY ML
 (RuleEngine)             (Rolling Profiles)      (Isolation Forest)
        |                       |                       |
        +-----------------------+-----------------------+
                                |
                                v
                        EVENT CORRELATION (CorrelationEngine)
                                |
                                v
                          ATTACK GRAPH (NetworkX Directed Modeling)
                                |
                                v
                         MITRE ATT&CK MAP
                                |
                                v
                          RISK ENGINE (0-100 score matrix)
                                |
                                v
                          INCIDENT LIFECYCLE (OPEN/INVESTIGATING)
                                |
                                v
                       AI SECURITY INVESTIGATOR (Playbook Copilot)
                                |
                                v
                         RESPONSE ENGINE (Dry-Run Containment)
                                |
                                v
                         REAL-TIME React SOC Dashboard
```

---

## 🛠️ Technology Stack

- **Backend**: Python 3.10+, FastAPI, Uvicorn, Asyncio.
- **Machine Learning**: Scikit-Learn (`IsolationForest`, `RandomForestClassifier`), NumPy, Pandas, Joblib.
- **Graph Modeling**: NetworkX (`DiGraph`).
- **Database Persistence**: SQLAlchemy ORM, AioSQLite (Asynchronous SQLite database).
- **Frontend**: React, TypeScript, Vite, Vanilla CSS.
- **Telemetry Sources**: Windows Security & Application Event logs (using `pywin32`).

---

## 📁 Repository Structure

```
sentinelx/
├── backend/
│   ├── app/
│   │   ├── main.py                 # FastAPI Application Server Entrypoint
│   │   ├── api/                    # APIRouter Modules (events, incidents, threats, risk, response)
│   │   ├── core/                   # Config settings, enums, status registry, schema models
│   │   ├── collectors/             # Windows Event Log Collector (Security & Application)
│   │   ├── streaming/              # EventManager (Pub/Sub) and Background Consumer Queue
│   │   ├── detection/              # Rules rules.py, RuleEngine, Behavioral baseline, ML Anomaly, Classifier
│   │   ├── correlation/            # CorrelationEngine, AttackGraph (NetworkX), MITRE mapper
│   │   ├── risk/                   # Risk assessment engine (0-100 scoring)
│   │   ├── incidents/              # Incident schema definitions
│   │   ├── response/               # ResponseEngine and simulated mitigation controls
│   │   ├── ai/                     # Local AI analyst playbook generator
│   │   ├── database/               # session.py configuration and declarative Event/Incident models
│   │   └── models/                 # ML artifact directories for Joblib storage
│   └── .env.example                # Config template file
├── frontend/                       # React + TypeScript Vite frontend project
├── attack_simulator/
│   └── simulator.py                # Telemetry Attack Playbook simulator
├── tests/                          # Automated unit tests and integration tests
└── README.md
```

---

## ⚡ Detection Capabilities & Rule Sets

### 1. Deterministic Security Rules (RuleEngine)
SentinelX ships with 8 core deterministic detection rules:
- **RULE-001**: Multiple failed logins within 60s from the same IP/user (Brute Force).
- **RULE-002**: Multiple failed logins followed by a successful login within 60s (Account Compromise).
- **RULE-003**: Special privileges assigned during user logon (e.g. `SeDebugPrivilege`, `SeLoadDriverPrivilege`).
- **RULE-004**: New service installed executing from temporary or user directories.
- **RULE-005**: Credential Manager read correlated with suspicious shell process launches.
- **RULE-006**: Successful logons originating from non-local/external IP addresses.
- **RULE-007**: Multi-anomaly host activity (elevated rate of high-severity events on a single host).
- **RULE-008**: Suspicious process execution chains (e.g. web/database servers spawning cmd/powershell).

### 2. Unsupervised Behavioral Anomaly Detection
- Features are engineered dynamically on User and Host profiles: failed logins, successes, process counts, credential reads, network logs, and working hours.
- An **Isolation Forest** model evaluates the feature matrix in real time, assigning a normalized anomaly score from `0` to `100`.
- Implements **Z-score explanation matrices** to identify and display exactly which feature dimensions drifted from baseline behaviors, ensuring ML models are fully explainable to SOC analysts.

---

## 🧪 Installation & Setup

### Prerequisites
- Windows 10 or 11
- Python 3.10.x
- Node.js 22.x

### 1. Backend Setup
1. Open PowerShell in `backend/` directory:
   ```powershell
   cd backend
   ```
2. Activate the virtual environment:
   ```powershell
   .venv\Scripts\Activate.ps1
   ```
3. Install project dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
   *(Note: Core dependencies: fastapi, uvicorn, pydantic, pydantic-settings, python-dotenv, pywin32, scikit-learn, joblib, numpy, pandas, networkx, sqlalchemy, aiosqlite)*
4. Launch the backend server:
   ```powershell
   uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
   ```

### 2. Frontend Setup
1. Open a new terminal in the `frontend/` directory:
   ```powershell
   cd frontend
   npm install
   ```
2. Launch Vite development server:
   ```powershell
   npm run dev
   ```
3. Open `http://localhost:5173` in your browser.

---

## 🛡️ Laboratory Threat Simulation & E2E Validation

SentinelX includes a safe telemetry simulator to validate E2E incident promotion and alerting.

1. Keep the backend and frontend servers running.
2. In a separate terminal, launch the simulator:
   ```powershell
   cd attack_simulator
   ..\backend\.venv\Scripts\python simulator.py
   ```
3. Select Option `1` (BRUTE_FORCE_CHAIN).
4. Watch the React SOC Dashboard in real-time. Dials will spike, the live feed will log events, and a **CRITICAL INCIDENT (100/100 Risk)** will appear detailing the Attack Graph, mapped MITRE techniques, and the AI investigation recommendations.

---

## 🔬 Testing
SentinelX features a comprehensive test suite (21 unit and integration tests):
```powershell
# Run the test suite
pytest
```
Tests validate:
- Pydantic schema constraints.
- Event Manager pub/sub boundaries and subscriber drops.
- Event log parsing on simulated Windows events.
- ML Anomaly Isolation Forest Z-score calculations.
- Rule Engine pattern matching.
- Asynchronous database CRUD operations.
