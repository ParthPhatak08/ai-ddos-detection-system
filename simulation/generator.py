"""
Safe Dynamic Traffic Simulation Engine
Generates realistic, continuously fluctuating benign and DDoS traffic feature vectors.
Academic Safety Guarantee: No real attack packets are transmitted onto the wire.
"""

import time
import math
import random
import threading
from typing import Dict, Any

class SimulationEngine:
    def __init__(self):
        self.is_active = False
        self.current_scenario = "NORMAL"  # 'NORMAL', 'SYN_FLOOD', 'UDP_FLOOD', 'HTTP_FLOOD'
        self._lock = threading.Lock()
        
        # Base state with baseline normal values
        self._pps = 45.0
        self._bps = 32000.0
        self._tcp = 36
        self._udp = 8
        self._icmp = 1
        self._syn = 3
        self._avg_size = 720.0
        self._src_ips = 3
        self._dst_ips = 6
        self._conn = 14

    def start_simulation(self, scenario: str = "NORMAL"):
        """Enable simulation with the chosen scenario."""
        with self._lock:
            self.is_active = True
            self.current_scenario = scenario.upper()
            self._reset_scenario_baseline()
            print(f"[+] Simulation active: {self.current_scenario}")

    def stop_simulation(self):
        """Disable simulation."""
        with self._lock:
            self.is_active = False
            self.current_scenario = "NORMAL"
            print("[-] Simulation deactivated.")

    def _reset_scenario_baseline(self):
        if self.current_scenario in ("DDoS", "SYN_FLOOD"):
            self._pps = random.uniform(7500, 9500)
            self._avg_size = random.uniform(54, 76)
            self._bps = self._pps * self._avg_size
            self._tcp = int(self._pps * 0.98)
            self._udp = random.randint(5, 25)
            self._icmp = random.randint(0, 5)
            self._syn = int(self._tcp * random.uniform(0.93, 0.98))
            self._src_ips = random.randint(1200, 3500)
            self._dst_ips = random.randint(1, 3)
            self._conn = random.randint(3500, 6000)
        elif self.current_scenario == "UDP_FLOOD":
            self._pps = random.uniform(8000, 14000)
            self._avg_size = random.uniform(800, 1300)
            self._bps = self._pps * self._avg_size
            self._tcp = random.randint(10, 60)
            self._udp = int(self._pps * 0.96)
            self._icmp = random.randint(0, 10)
            self._syn = random.randint(0, 5)
            self._src_ips = random.randint(800, 2500)
            self._dst_ips = random.randint(1, 4)
            self._conn = random.randint(1200, 2800)
        elif self.current_scenario == "HTTP_FLOOD":
            self._pps = random.uniform(3200, 6500)
            self._avg_size = random.uniform(300, 550)
            self._bps = self._pps * self._avg_size
            self._tcp = int(self._pps * 0.94)
            self._udp = random.randint(20, 80)
            self._icmp = 0
            self._syn = int(self._tcp * random.uniform(0.20, 0.35))
            self._src_ips = random.randint(400, 1800)
            self._dst_ips = random.randint(1, 2)
            self._conn = random.randint(3000, 7500)
        else:  # NORMAL
            self._pps = random.uniform(35, 75)
            self._avg_size = random.uniform(600, 850)
            self._bps = self._pps * self._avg_size
            self._tcp = int(self._pps * random.uniform(0.70, 0.85))
            self._udp = int(self._pps * random.uniform(0.12, 0.25))
            self._icmp = random.randint(0, 2)
            self._syn = max(1, int(self._tcp * random.uniform(0.04, 0.08)))
            self._src_ips = random.randint(2, 6)
            self._dst_ips = random.randint(3, 12)
            self._conn = random.randint(8, 28)

    def step(self) -> Dict[str, Any]:
        """
        Advance one simulation step with realistic micro-variations.
        Returns a fresh 10-feature telemetry dictionary.
        """
        with self._lock:
            # Apply smooth random walk + dynamic surge waves
            wave = math.sin(time.time() * 0.75) * 0.12 + 1.0
            burst = random.choice([1.0, 1.0, 1.05, 0.96, 1.12 if random.random() < 0.15 else 1.0])

            if self.current_scenario in ("DDoS", "SYN_FLOOD"):
                self._pps = max(4500.0, min(24000.0, self._pps * random.uniform(0.94, 1.06) * wave * burst))
                self._tcp = int(self._pps * random.uniform(0.95, 0.99))
                self._syn = int(self._tcp * random.uniform(0.93, 0.98))
                self._udp = random.randint(5, 45)
                self._icmp = random.randint(0, 8)
                self._bps = self._pps * self._avg_size * random.uniform(0.95, 1.05)
                self._src_ips = max(600, int(self._src_ips * random.uniform(0.96, 1.04)))
                self._conn = max(2500, int(self._conn * random.uniform(0.97, 1.03)))
            elif self.current_scenario == "UDP_FLOOD":
                self._pps = max(5500.0, min(28000.0, self._pps * random.uniform(0.93, 1.07) * wave))
                self._udp = int(self._pps * random.uniform(0.94, 0.98))
                self._tcp = random.randint(10, 80)
                self._syn = random.randint(0, 8)
                self._bps = self._pps * self._avg_size * random.uniform(0.95, 1.05)
            elif self.current_scenario == "HTTP_FLOOD":
                self._pps = max(2200.0, min(8500.0, self._pps * random.uniform(0.95, 1.05) * wave))
                self._tcp = int(self._pps * random.uniform(0.90, 0.96))
                self._syn = int(self._tcp * random.uniform(0.20, 0.35))
                self._bps = self._pps * self._avg_size * random.uniform(0.95, 1.05)
                self._conn = max(1800, int(self._conn * random.uniform(0.96, 1.04)))
            else:  # NORMAL
                self._pps = max(25.0, min(140.0, self._pps * random.uniform(0.88, 1.12)))
                self._tcp = int(self._pps * random.uniform(0.70, 0.85))
                self._udp = int(self._pps * random.uniform(0.12, 0.25))
                self._icmp = random.randint(0, 2)
                self._syn = max(1, int(self._tcp * random.uniform(0.04, 0.08)))
                self._bps = self._pps * self._avg_size * random.uniform(0.92, 1.08)
                self._conn = max(6, min(40, int(self._conn * random.uniform(0.94, 1.06))))

            return {
                "packets_per_second": round(self._pps, 2),
                "bytes_per_second": round(self._bps, 2),
                "tcp_count": max(0, self._tcp),
                "udp_count": max(0, self._udp),
                "icmp_count": max(0, self._icmp),
                "syn_count": max(0, self._syn),
                "average_packet_size": round(self._avg_size, 1),
                "unique_source_ips": self._src_ips,
                "unique_destination_ips": self._dst_ips,
                "connection_count": self._conn
            }

# Global simulation instance
simulation_engine = SimulationEngine()
