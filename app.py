"""
AI-Based Real-Time DDoS Detection and Network Traffic Monitoring System
Production Flask Web Application Core Server (Phase 2 - 100% Complete)
Integrates Machine Learning (Random Forest), Live Telemetry, SQLite DB, and Safe Simulation.
"""

import os
import io
import csv
import time
import socket
import datetime
import threading
from typing import Dict, Any, List

from flask import Flask, render_template, jsonify, request, Response
import psutil

# Internal project modules
from database.db import (
    init_db, log_threat_event, log_telemetry_snapshot,
    get_recent_threats, get_threat_by_id, get_system_statistics,
    clear_all_events
)
from model.detector import detector
from network.sniffer import telemetry_monitor
from simulation.generator import simulation_engine

app = Flask(__name__)

# Initialize database schema upon launch
init_db()

# Global Application State (Thread-safe read/write)
state_lock = threading.Lock()
app_state: Dict[str, Any] = {
    "is_monitoring": True,
    "mode": "LIVE",  # 'STANDBY', 'LIVE', 'SIMULATION'
    "simulation_scenario": "NORMAL",
    "selected_interface": "auto",
    "local_ip": "127.0.0.1",
    "interfaces": [],
    "metrics": {
        "packets_per_second": 0.0,
        "bytes_per_second": 0.0,
        "tcp_count": 0,
        "udp_count": 0,
        "icmp_count": 0,
        "syn_count": 0,
        "average_packet_size": 0.0,
        "unique_source_ips": 1,
        "unique_destination_ips": 1,
        "connection_count": 0
    },
    "prediction": "NORMAL",
    "confidence": 0.99,
    "prob_normal": 0.99,
    "prob_ddos": 0.01,
    "risk_level": "LOW",
    "threats_count": 0,
    "observations": [
        "Network telemetry initialized and operating within baseline parameters",
        "TCP SYN-to-ACK handshake ratio balanced"
    ],
    "recent_events": []
}

# Threat alert rate-limiting cooldown tracking
last_alert_time = 0.0
ALERT_COOLDOWN_SECONDS = 3.5

def detect_network_interfaces():
    """Detect local active network interfaces safely using psutil and socket."""
    interfaces = []
    try:
        # Detect primary local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            app_state["local_ip"] = s.getsockname()[0]
        except Exception:
            app_state["local_ip"] = "127.0.0.1"
        finally:
            s.close()

        # List active network interfaces
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for name, addr_list in addrs.items():
            is_up = stats.get(name).isup if name in stats else False
            if is_up:
                interfaces.append({
                    "name": name,
                    "is_up": is_up,
                    "is_selected": (name == app_state["selected_interface"] or app_state["selected_interface"] == "auto")
                })
        if not interfaces:
            interfaces.append({"name": "Default Ethernet / Wi-Fi", "is_up": True, "is_selected": True})
    except Exception:
        interfaces.append({"name": "Loopback / Local", "is_up": True, "is_selected": True})
    
    with state_lock:
        app_state["interfaces"] = interfaces
    return interfaces

# Pre-populate interfaces and past events from SQLite
detect_network_interfaces()
telemetry_monitor.start("auto")
try:
    past_threats = get_recent_threats(10)
    app_state["recent_events"] = past_threats
    app_state["threats_count"] = len(past_threats)
except Exception:
    pass

# ==============================================================================
# Background Telemetry & Machine Learning Evaluation Loop
# ==============================================================================
def background_telemetry_daemon():
    """
    Background worker that continuously samples network metrics, evaluates them
    through the Random Forest model, logs snapshots, and persists threat alerts.
    """
    global last_alert_time
    snapshot_counter = 0
    simulation_burst_counter = 0

    while True:
        try:
            time.sleep(1.2)
            mode = app_state["mode"]
            is_monitoring = app_state["is_monitoring"]

            # Step 1: Collect Metrics according to mode
            if mode == "SIMULATION":
                metrics = simulation_engine.step()
                # Auto-cooldown attack burst after ~10 seconds to return to baseline
                if app_state["simulation_scenario"] != "NORMAL":
                    simulation_burst_counter += 1
                    if simulation_burst_counter >= 8:
                        simulation_engine.start_simulation("NORMAL")
                        with state_lock:
                            app_state["simulation_scenario"] = "NORMAL"
                        simulation_burst_counter = 0
            elif mode == "LIVE":
                metrics = telemetry_monitor.get_metrics()
            else:
                # Standby: Sample low passive background traffic
                raw_m = telemetry_monitor.get_metrics()
                metrics = {
                    "packets_per_second": round(raw_m.get("packets_per_second", 0) * 0.1, 2),
                    "bytes_per_second": round(raw_m.get("bytes_per_second", 0) * 0.1, 2),
                    "tcp_count": max(0, int(raw_m.get("tcp_count", 0) * 0.1)),
                    "udp_count": max(0, int(raw_m.get("udp_count", 0) * 0.1)),
                    "icmp_count": 0,
                    "syn_count": 0,
                    "average_packet_size": raw_m.get("average_packet_size", 512),
                    "unique_source_ips": 1,
                    "unique_destination_ips": 1,
                    "connection_count": max(1, int(raw_m.get("connection_count", 0) * 0.1))
                }

            # Step 2: Real-Time Machine Learning Inference
            eval_res = detector.predict(metrics)
            pred = eval_res["prediction"]
            conf = eval_res["confidence"]
            prob_norm = eval_res["prob_normal"]
            prob_ddos = eval_res["prob_ddos"]
            risk = eval_res["risk_level"]
            obs = eval_res["observations"]

            # Step 3: Periodic Telemetry Logging into SQLite
            snapshot_counter += 1
            if snapshot_counter % 2 == 0:
                try:
                    log_telemetry_snapshot(metrics, pred, risk)
                except Exception:
                    pass

            # Step 4: Threat Alert Detection & Cooldown Deduplication
            now_ts = time.time()
            if (pred == "POSSIBLE DDoS" or prob_ddos >= 0.50) and (now_ts - last_alert_time >= ALERT_COOLDOWN_SECONDS):
                last_alert_time = now_ts
                now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                event_data = {
                    "timestamp": now_str,
                    "mode": mode,
                    "prediction": pred,
                    "confidence": conf,
                    "risk_level": risk,
                    "packets_per_second": metrics["packets_per_second"],
                    "bytes_per_second": metrics["bytes_per_second"],
                    "syn_count": metrics["syn_count"],
                    "tcp_count": metrics["tcp_count"],
                    "udp_count": metrics["udp_count"],
                    "icmp_count": metrics["icmp_count"],
                    "connection_count": metrics["connection_count"],
                    "unique_source_ips": metrics["unique_source_ips"],
                    "unique_destination_ips": metrics["unique_destination_ips"],
                    "observations": obs
                }
                
                try:
                    event_id = log_threat_event(event_data)
                    event_data["id"] = event_id
                except Exception:
                    event_data["id"] = len(app_state["recent_events"]) + 1

                with state_lock:
                    app_state["recent_events"].insert(0, event_data)
                    if len(app_state["recent_events"]) > 20:
                        app_state["recent_events"].pop()
                    app_state["threats_count"] += 1

            # Step 5: Update Application State
            with state_lock:
                app_state["metrics"] = metrics
                app_state["prediction"] = pred
                app_state["confidence"] = conf
                app_state["prob_normal"] = prob_norm
                app_state["prob_ddos"] = prob_ddos
                app_state["risk_level"] = risk
                app_state["observations"] = obs

        except Exception as e:
            time.sleep(1.0)

# Launch daemon thread
daemon_thread = threading.Thread(target=background_telemetry_daemon, daemon=True)
daemon_thread.start()

# ==============================================================================
# Web Routes & API Endpoints
# ==============================================================================
@app.route("/")
def dashboard():
    """Render main operations center dashboard."""
    detect_network_interfaces()
    with state_lock:
        state_copy = dict(app_state)
    return render_template("dashboard.html", active_page="dashboard", state=state_copy)

@app.route("/api/status")
def api_status():
    """Return current network telemetry and AI threat analysis."""
    with state_lock:
        return jsonify(app_state)

@app.route("/api/start", methods=["POST"])
def api_start():
    """Start live network packet monitoring on selected interface."""
    data = request.get_json(silent=True) or {}
    chosen_iface = data.get("interface", "auto")
    
    simulation_engine.stop_simulation()
    telemetry_monitor.start(chosen_iface)
    
    with state_lock:
        app_state["selected_interface"] = chosen_iface
        app_state["is_monitoring"] = True
        app_state["mode"] = "LIVE"
        
    return jsonify({
        "status": "success",
        "message": f"Live telemetry monitoring initiated on interface '{chosen_iface}'",
        "mode": "LIVE"
    })

@app.route("/api/stop", methods=["POST"])
def api_stop():
    """Stop network monitoring and simulation."""
    telemetry_monitor.stop()
    simulation_engine.stop_simulation()
    
    with state_lock:
        app_state["is_monitoring"] = False
        app_state["mode"] = "STANDBY"
        
    return jsonify({
        "status": "success",
        "message": "Monitoring halted (STANDBY mode)",
        "mode": "STANDBY"
    })

@app.route("/api/simulate/normal", methods=["POST"])
def api_simulate_normal():
    """Activate safe dynamic normal traffic simulation."""
    telemetry_monitor.stop()
    simulation_engine.start_simulation("NORMAL")
    
    with state_lock:
        app_state["mode"] = "SIMULATION"
        app_state["simulation_scenario"] = "NORMAL"
        app_state["is_monitoring"] = True
        
    return jsonify({"status": "success", "message": "Dynamic Normal Traffic Simulation active"})

@app.route("/api/simulate/ddos", methods=["POST"])
def api_simulate_ddos():
    """Activate safe dynamic DDoS attack simulation (SYN flood / UDP flood / HTTP flood)."""
    data = request.get_json(silent=True) or {}
    attack_type = data.get("attack_type", "SYN_FLOOD").upper()
    if attack_type not in ("SYN_FLOOD", "UDP_FLOOD", "HTTP_FLOOD"):
        attack_type = "SYN_FLOOD"

    telemetry_monitor.stop()
    simulation_engine.start_simulation(attack_type)
    
    # Generate immediate step to display right away
    metrics = simulation_engine.step()
    eval_res = detector.predict(metrics)
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    event_data = {
        "timestamp": now_str,
        "mode": "SIMULATION",
        "prediction": eval_res["prediction"],
        "confidence": eval_res["confidence"],
        "risk_level": eval_res["risk_level"],
        "packets_per_second": metrics["packets_per_second"],
        "bytes_per_second": metrics["bytes_per_second"],
        "syn_count": metrics["syn_count"],
        "tcp_count": metrics["tcp_count"],
        "udp_count": metrics["udp_count"],
        "icmp_count": metrics["icmp_count"],
        "connection_count": metrics["connection_count"],
        "unique_source_ips": metrics["unique_source_ips"],
        "unique_destination_ips": metrics["unique_destination_ips"],
        "observations": eval_res["observations"]
    }

    try:
        event_id = log_threat_event(event_data)
        event_data["id"] = event_id
    except Exception:
        event_data["id"] = len(app_state["recent_events"]) + 1

    with state_lock:
        app_state["mode"] = "SIMULATION"
        app_state["simulation_scenario"] = attack_type
        app_state["is_monitoring"] = True
        app_state["metrics"] = metrics
        app_state["prediction"] = eval_res["prediction"]
        app_state["confidence"] = eval_res["confidence"]
        app_state["prob_normal"] = eval_res["prob_normal"]
        app_state["prob_ddos"] = eval_res["prob_ddos"]
        app_state["risk_level"] = eval_res["risk_level"]
        app_state["observations"] = eval_res["observations"]
        app_state["threats_count"] += 1
        app_state["recent_events"].insert(0, event_data)
        if len(app_state["recent_events"]) > 20:
            app_state["recent_events"].pop()

    return jsonify({
        "status": "success",
        "message": f"Dynamic DDoS Simulation loaded ({attack_type})",
        "event": event_data
    })

@app.route("/history")
def threat_history():
    """Display threat detection event history from SQLite database."""
    events = get_recent_threats(50)
    return render_template("history.html", active_page="history", events=events)

@app.route("/api/history/clear", methods=["POST"])
def api_clear_history():
    """Reset and clear all threat events and telemetry records."""
    clear_all_events()
    with state_lock:
        app_state["recent_events"] = []
        app_state["threats_count"] = 0
    return jsonify({"status": "success", "message": "Threat detection audit log reset successfully."})

@app.route("/api/threat/<int:event_id>")
def api_threat_detail(event_id: int):
    """Fetch JSON detail of a single threat event."""
    evt = get_threat_by_id(event_id)
    if not evt:
        return jsonify({"error": "Event not found"}), 404
    return jsonify(evt)

@app.route("/statistics")
def statistics():
    """Display comprehensive network statistics from SQLite audit history."""
    stats_data = get_system_statistics()
    return render_template("statistics.html", active_page="statistics", stats=stats_data, state=app_state)

@app.route("/api/statistics")
def api_statistics():
    """Return JSON statistics for dynamic client reloads."""
    return jsonify(get_system_statistics())

@app.route("/about")
def about_project():
    """Display project background, ML model benchmarks, and viva concepts."""
    report_file = os.path.join(os.path.dirname(__file__), "model", "model_report.json")
    report_data = {}
    if os.path.exists(report_file):
        try:
            import json
            with open(report_file, "r") as f:
                report_data = json.load(f)
        except Exception:
            pass
    return render_template("about.html", active_page="about", report=report_data)

@app.route("/export")
@app.route("/export/csv")
def export_csv():
    """Export complete threat detection history from SQLite as CSV."""
    events = get_recent_threats(1000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Event ID", "Timestamp", "Mode", "Detection", "Confidence",
        "Risk Level", "Packets_Per_Sec", "Bytes_Per_Sec", "SYN_Count",
        "TCP_Count", "UDP_Count", "ICMP_Count", "Connections", "Unique_Source_IPs"
    ])
    for evt in events:
        conf_pct = f"{evt['confidence'] * 100:.1f}%" if isinstance(evt.get('confidence'), (int, float)) else str(evt.get('confidence', ''))
        writer.writerow([
            evt["id"],
            evt["timestamp"],
            evt["mode"],
            evt["prediction"],
            conf_pct,
            evt["risk_level"],
            evt["packets_per_second"],
            evt["bytes_per_second"],
            evt["syn_count"],
            evt["tcp_count"],
            evt["udp_count"],
            evt["icmp_count"],
            evt["connection_count"],
            evt["unique_source_ips"]
        ])
        
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=aegisnet_threat_history.csv"}
    )

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = "0.0.0.0" if os.environ.get("PORT") else "127.0.0.1"
    print("================================================================")
    print("Starting AI-Based Real-Time DDoS Detection System (Phase 2)...")
    print(f"Web URL: http://{host}:{port}")
    print("Database: SQLite3 (database/threats.db)")
    print("ML Engine: Random Forest Classifier (model/ddos_random_forest.joblib)")
    print("Safe Mode: Local dynamic simulation enabled")
    print("================================================================")
    app.run(host=host, port=port, debug=(os.environ.get("FLASK_DEBUG", "True").lower() == "true"))
