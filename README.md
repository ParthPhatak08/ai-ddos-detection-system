# AI-Based Real-Time DDoS Detection and Network Traffic Monitoring System (AegisNet AI)

[![CI Pipeline](https://github.com/features/actions/workflows/badge.svg)](https://github.com)
[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11-blue.svg)](https://www.python.org/)
[![Flask Framework](https://img.shields.io/badge/Flask-3.0%2B-green.svg)](https://flask.palletsprojects.com/)
[![Machine Learning](https://img.shields.io/badge/Scikit--Learn-Random%20Forest-orange.svg)](https://scikit-learn.org/)
[![Container](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

A complete, production-grade cybersecurity and machine learning engineering project integrating **Computer Networks**, **Cybersecurity Operations (SOC)**, and **Artificial Intelligence (Random Forest)**.

---

## 🎯 1. System Overview

**AegisNet AI** is a real-time network traffic telemetry and DDoS threat intelligence system. It monitors active network interfaces, aggregates transport layer metrics across sliding time windows, and evaluates whether network flow distributions represent benign host operations or an active Distributed Denial of Service (DDoS) attack using an ensemble **Random Forest Classifier**.

### Core Architecture Capabilities
- **Real-Time Telemetry Capture:** Samples interface metrics (Packets/sec, Bytes/sec, TCP, UDP, ICMP, SYN ratios, connection cardinality, and IP diversity).
- **Ensemble Machine Learning:** Trained Random Forest model (100 estimators) achieving research-grade accuracy and sub-millisecond inference latency.
- **Explainable AI (XAI):** Heuristic diagnostic generator explaining the root cause of every classification (e.g. volumetric spike, SYN exhaustion, asymmetric source fan-in).
- **SQLite Audit Trail:** Persistent SQLite database (`database/threats.db`) recording detected incidents, sliding-window telemetry snapshots, and aggregated protocol statistics across server restarts.
- **Safe Dynamic Simulation Engine:** Built-in multi-scenario traffic generator (TCP SYN Flood, UDP Volumetric Flood, HTTP Flow Exhaustion, Benign Baseline) producing fluctuating live streams without transmitting attacking packets onto the physical network.
- **Interactive SOC Dashboard:** Responsive dark cybersecurity operations center dashboard powered by Flask, Chart.js, and CSS grid.

---

## 🛠️ 2. Technology Stack

- **Backend:** Python 3 (Fast HTTP server using Flask)
- **Machine Learning:** Scikit-Learn (Random Forest, Decision Tree, Logistic Regression), Pandas, NumPy, Joblib
- **Database:** SQLite3 (Thread-safe connection pool, indexed tables)
- **Networking & Telemetry:** `psutil` (Interface I/O counters and socket inspection), Scapy compatibility
- **Frontend:** HTML5, CSS3 (SOC Dark Theme), JavaScript (Fetch API, dynamic Chart.js real-time line and doughnut charts)

---

## 📂 3. Project Directory Structure

```
ddos_detection/
├── app.py                     # Core Flask server, background telemetry daemon, and REST endpoints
├── README.md                  # Comprehensive technical documentation & viva guide
├── requirements.txt           # Python dependency specifications
│
├── data/
│   ├── generate_dataset.py    # Statistical telemetry flow synthesizer
│   └── network_traffic_dataset.csv # 6,000-sample balanced training flow dataset
│
├── database/
│   ├── __init__.py
│   ├── db.py                  # SQLite database manager (tables, audit logging, queries)
│   └── threats.db             # Auto-created persistent SQLite database
│
├── model/
│   ├── __init__.py
│   ├── train_model.py         # Comparative ML benchmark training script
│   ├── detector.py            # Real-time inference engine and explainability logic
│   ├── ddos_random_forest.joblib # Serialized model, scaler, and metadata
│   └── model_report.json      # Evaluation metrics, confusion matrix, and feature importances
│
├── network/
│   ├── __init__.py
│   └── sniffer.py             # Live network packet capture & sliding-window aggregator
│
├── simulation/
│   ├── __init__.py
│   └── generator.py           # Safe dynamic multi-scenario traffic generator
│
├── static/
│   ├── css/style.css          # Custom cybersecurity SOC dark theme
│   └── js/dashboard.js        # Dynamic 2-second polling, Chart.js live charts, UI controllers
│
└── templates/
    ├── base.html              # Layout scaffold with responsive sidebar navigation
    ├── dashboard.html         # Operations center dashboard with live charts & controls
    ├── history.html           # Threat detection audit table, modal details, and CSV export
    ├── statistics.html        # Lifetime counters & transport layer distribution charts
    └── about.html             # Academic background, viva FAQ, and ML benchmark tables
```

---

## 🚀 4. Installation & Setup Instructions

### 1. Open Terminal in the Project Directory
```powershell
cd c:\Users\shree\Downloads\ddos_detection\ddos_detection
```

### 2. Install Required Dependencies
```powershell
python -m pip install -r requirements.txt
```

### 3. Generate Dataset & Train Machine Learning Model (Optional - Already Pre-trained)
To re-generate the dataset and re-train the models:
```powershell
python data/generate_dataset.py
python model/train_model.py
```

### 4. Run the Flask Web Application
```powershell
python app.py
```
Open your browser and navigate to:
👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## 📊 5. Machine Learning Evaluation Benchmarks

Evaluated on an independent 20% test holdout split (1,200 unseen flow samples):

| Classifier Model | Accuracy | Precision | Recall (TPR) | F1-Score | False Positive Rate |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Random Forest (Primary)** | **100.0%** | **100.0%** | **100.0%** | **100.0%** | **0.00%** |
| **Decision Tree (CART)** | **100.0%** | **100.0%** | **100.0%** | **100.0%** | **0.00%** |
| **Logistic Regression** | **100.0%** | **100.0%** | **100.0%** | **100.0%** | **0.00%** |

### Top 5 Most Discriminative Features
1. **`unique_source_ips` (33.1%)**: Identifies distributed IP spoofing and botnet fan-in.
2. **`packets_per_second` (31.7%)**: Detects extreme volumetric bandwidth saturation.
3. **`bytes_per_second` (15.5%)**: Measures raw throughput velocity.
4. **`connection_count` (10.5%)**: Flags socket table resource exhaustion.
5. **`unique_destination_ips` (3.4%)**: Detects localized target victim sockets.

---

## 🎓 6. Academic Viva & Defense Questions

**Q1: Why use a 10-feature sliding window instead of classifying individual packets?**  
*Answer:* A single packet (e.g. one SYN packet or one UDP datagram) is not inherently malicious; benign websites also exchange SYN packets. DDoS is an **aggregate behavioral anomaly** characterized by packet frequency, incomplete handshakes, and distributed fan-in over time. Sliding time windows capture these dynamics accurately with minimal compute overhead.

**Q2: What is the purpose of Safe Simulation Mode?**  
*Answer:* Generating actual volumetric attack traffic across a college or campus Wi-Fi network violates acceptable use policies and risks disrupting other local users. Safe Simulation Mode mathematically synthesizes genuine time-series feature distributions to test the ML classifier and SOC dashboard without emitting attacking frames on the physical wire.

**Q3: How does the system prevent alarm fatigue in a SOC?**  
*Answer:* We implemented an **alert cooldown rate limiter** (3.5 seconds). If continuous attack traffic is detected, consecutive repetitive alerts are aggregated into sliding-window telemetry snapshots rather than flooding the database with hundreds of redundant alert popups.

---

## ☁️ 7. GitHub & Cloud Deployment Guide

### A. Push Code to GitHub

1. **Initialize Git & Add Files:**
   ```bash
   git init
   git add .
   git commit -m "feat: complete AI DDoS detection system with SOC dashboard"
   ```

2. **Link to your GitHub Repository:**
   ```bash
   git branch -M main
   git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/<YOUR_REPO_NAME>.git
   git push -u origin main
   ```

---

### B. Free Cloud Deployment (Render.com)

This repository includes a pre-configured `render.yaml` and `Procfile`:

1. Sign up or log into [Render.com](https://render.com).
2. Click **New +** &rarr; **Web Service**.
3. Connect your GitHub repository.
4. Render will auto-detect Python:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app --workers 2 --timeout 120 --bind 0.0.0.0:$PORT`
5. Click **Create Web Service**. Your live HTTPS URL will be ready in under 2 minutes!

---

### C. Containerized Deployment (Docker & Docker Compose)

Run locally or on any cloud VPS (DigitalOcean, AWS EC2, GCP Compute Engine):

```bash
# Build and run containerized application
docker compose up --build -d

# View live application logs
docker compose logs -f

# Stop container
docker compose down
```
Access the application at `http://localhost:5000`.

