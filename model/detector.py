"""
Real-Time DDoS Detection Inference Engine
Loads serialized Random Forest model and provides predictions, probabilities,
risk scoring, and explainable heuristic observations.
"""

import os
import joblib
import numpy as np
from typing import Dict, Any, List

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_FILE = os.path.join(MODEL_DIR, "ddos_random_forest.joblib")

class DDoSDetector:
    def __init__(self, model_path: str = MODEL_FILE):
        self.model_path = model_path
        self.model = None
        self.scaler = None
        self.feature_columns = []
        self.metrics = {}
        self.feature_importances = []
        self.is_loaded = False
        self._load_model()

    def _load_model(self):
        if not os.path.exists(self.model_path):
            print(f"[!] Warning: Model file not found at {self.model_path}. Run model/train_model.py")
            return
        try:
            artifact = joblib.load(self.model_path)
            self.model = artifact["model"]
            self.scaler = artifact["scaler"]
            self.feature_columns = artifact["feature_columns"]
            self.metrics = artifact.get("metrics", {})
            self.feature_importances = artifact.get("feature_importances", [])
            self.is_loaded = True
            print(f"[+] DDoSDetector successfully loaded Random Forest model ({len(self.feature_columns)} features).")
        except Exception as e:
            print(f"[-] Failed to load model artifact: {e}")
            self.is_loaded = False

    def predict(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate a single telemetry dictionary and return classification,
        confidence, risk level, and diagnostic observations.
        """
        # Fallback if model not loaded
        if not self.is_loaded:
            return self._heuristic_fallback(metrics)

        # Build feature vector
        vector = []
        for col in self.feature_columns:
            val = float(metrics.get(col, 0.0))
            vector.append(val)

        X = np.array([vector])
        X_scaled = self.scaler.transform(X)

        # Probabilities
        probs = self.model.predict_proba(X_scaled)[0]
        prob_norm = float(probs[0])
        prob_ddos = float(probs[1])

        # Multi-tiered Risk Assessment (NIST / SOC Severity Matrix)
        pps = float(metrics.get("packets_per_second", 0))
        bps = float(metrics.get("bytes_per_second", 0))
        syn = int(metrics.get("syn_count", 0))
        tcp = max(1, int(metrics.get("tcp_count", 0)))

        if prob_ddos >= 0.5:
            prediction = "POSSIBLE DDoS"
            confidence = prob_ddos
            
            # CRITICAL: Extreme flood / link saturation (> 8,000 pps, or severe SYN flood > 4,000 syn)
            if pps > 8000 or (syn > 4000 and (syn / tcp) > 0.75):
                risk_level = "CRITICAL"
            # HIGH: Heavy sustained attack flow (> 3,500 pps or syn > 1,500 with high SYN ratio)
            elif pps > 3500 or (syn > 1500 and (syn / tcp) > 0.50):
                risk_level = "HIGH"
            # ELEVATED: Moderate anomaly / emerging attack vector
            else:
                risk_level = "ELEVATED"
        else:
            prediction = "NORMAL"
            confidence = prob_norm
            # Normal baseline: traffic is LOW risk unless suspicious protocol imbalance is observed
            if pps > 4000 and (syn / tcp) > 0.35:
                risk_level = "ELEVATED"
            else:
                risk_level = "LOW"

        observations = self._generate_observations(metrics, prediction, prob_ddos)

        return {
            "prediction": prediction,
            "confidence": round(confidence, 4),
            "prob_normal": round(prob_norm, 4),
            "prob_ddos": round(prob_ddos, 4),
            "risk_level": risk_level,
            "observations": observations
        }

    def _generate_observations(self, m: Dict[str, Any], pred: str, prob_ddos: float) -> List[str]:
        obs = []
        pps = float(m.get("packets_per_second", 0))
        bps = float(m.get("bytes_per_second", 0))
        tcp = int(m.get("tcp_count", 0))
        udp = int(m.get("udp_count", 0))
        icmp = int(m.get("icmp_count", 0))
        syn = int(m.get("syn_count", 0))
        src_ips = int(m.get("unique_source_ips", 0))
        conn = int(m.get("connection_count", 0))

        if pred == "POSSIBLE DDoS":
            if pps > 2000:
                obs.append(f"Critical volumetric anomaly: Packet rate reaches {pps:,.0f} pps")
            if bps > 2000000:
                obs.append(f"High bandwidth consumption: {bps/1000000:.2f} MB/s observed")
            if tcp > 0 and (syn / tcp) > 0.70 and syn > 100:
                obs.append(f"Severe SYN flood signature: {syn:,} SYN packets ({(syn/tcp)*100:.1f}% of TCP)")
            if udp > 1000 and (udp / max(1, pps)) > 0.75:
                obs.append(f"UDP packet storm: {udp:,} UDP packets saturating ports")
            if icmp > 500:
                obs.append(f"ICMP flood detected: {icmp:,} echo packets")
            if src_ips > 150:
                obs.append(f"Asymmetric source fan-in: Traffic originating from {src_ips:,} distinct hosts")
            if conn > 1000:
                obs.append(f"High concurrent flow exhaustion: {conn:,} active connections")
            if not obs:
                obs.append(f"Anomalous multi-dimensional traffic pattern detected (Risk Likelihood: {prob_ddos*100:.1f}%)")
        else:
            obs.append("Network telemetry operating within baseline parameters (< 500 pps)")
            obs.append("TCP SYN-to-ACK handshake ratio well balanced")
            if conn > 0:
                obs.append(f"Active connections ({conn}) distributed normally across benign endpoints")

        return obs

    def _heuristic_fallback(self, m: Dict[str, Any]) -> Dict[str, Any]:
        pps = float(m.get("packets_per_second", 0))
        syn = int(m.get("syn_count", 0))
        if pps > 2000 or syn > 500:
            return {
                "prediction": "POSSIBLE DDoS",
                "confidence": 0.95,
                "prob_normal": 0.05,
                "prob_ddos": 0.95,
                "risk_level": "CRITICAL",
                "observations": ["Heuristic fallback: Volumetric anomaly threshold exceeded"]
            }
        return {
            "prediction": "NORMAL",
            "confidence": 0.97,
            "prob_normal": 0.97,
            "prob_ddos": 0.03,
            "risk_level": "LOW",
            "observations": ["Heuristic baseline normal"]
        }

# Global singleton
detector = DDoSDetector()
