"""
Dataset Generation Script for Network Traffic and DDoS Telemetry
Synthesizes realistic normal and DDoS flow vectors aligned with CIC-DDoS / UNSW-NB15 statistical distributions.
"""

import os
import numpy as np
import pandas as pd

def generate_telemetry_dataset(num_samples: int = 6000, output_path: str = "data/network_traffic_dataset.csv"):
    np.random.seed(42)
    half = num_samples // 2
    
    # =========================================================================
    # =========================================================================
    # 1. Benign / Normal Network Traffic (3000 samples)
    # =========================================================================
    # Variations across realistic workloads:
    # - Idle / Background (35%): 10 - 200 pps, 20 - 150 connections
    # - Web Browsing / API Traffic (40%): 200 - 1,500 pps, 100 - 450 connections
    # - High-Bandwidth Streaming / Downloads (25%): 1,500 - 4,500 pps, 150 - 650 connections
    n_idle = int(half * 0.35)
    n_browse = int(half * 0.40)
    n_stream = half - (n_idle + n_browse)
    
    # 1A. Idle
    pps_idle = np.random.uniform(10, 200, size=n_idle)
    conn_idle = np.random.randint(15, 120, size=n_idle)
    bps_idle = pps_idle * np.random.uniform(200, 600, size=n_idle)
    tcp_ratio_idle = np.random.uniform(0.60, 0.85, size=n_idle)
    tcp_idle = (pps_idle * tcp_ratio_idle).astype(int)
    udp_idle = (pps_idle - tcp_idle).astype(int)
    icmp_idle = np.random.poisson(0.1, size=n_idle)
    syn_idle = np.clip((tcp_idle * np.random.uniform(0.01, 0.05, size=n_idle)).astype(int), 0, None)
    src_idle = np.random.randint(1, 5, size=n_idle)
    dst_idle = np.random.randint(5, 30, size=n_idle)
    pkt_sz_idle = np.clip(bps_idle / np.maximum(1.0, pps_idle), 64, 1500)
    
    # 1B. Web Browsing / Active APIs
    pps_browse = np.random.uniform(200, 1500, size=n_browse)
    conn_browse = np.random.randint(80, 450, size=n_browse)
    bps_browse = pps_browse * np.random.uniform(500, 1100, size=n_browse)
    tcp_ratio_browse = np.random.uniform(0.70, 0.92, size=n_browse)
    tcp_browse = (pps_browse * tcp_ratio_browse).astype(int)
    udp_browse = (pps_browse - tcp_browse).astype(int)
    icmp_browse = np.random.poisson(0.2, size=n_browse)
    syn_browse = np.clip((tcp_browse * np.random.uniform(0.02, 0.06, size=n_browse)).astype(int), 0, None)
    src_browse = np.random.randint(1, 10, size=n_browse)
    dst_browse = np.random.randint(20, 120, size=n_browse)
    pkt_sz_browse = np.clip(bps_browse / np.maximum(1.0, pps_browse), 64, 1500)
    
    # 1C. High-Bandwidth Streaming / Downloading
    pps_stream = np.random.uniform(1500, 4500, size=n_stream)
    conn_stream = np.random.randint(120, 650, size=n_stream)
    bps_stream = pps_stream * np.random.uniform(900, 1450, size=n_stream)
    tcp_ratio_stream = np.random.uniform(0.80, 0.95, size=n_stream)
    tcp_stream = (pps_stream * tcp_ratio_stream).astype(int)
    udp_stream = (pps_stream - tcp_stream).astype(int)
    icmp_stream = np.random.poisson(0.1, size=n_stream)
    syn_stream = np.clip((tcp_stream * np.random.uniform(0.01, 0.04, size=n_stream)).astype(int), 0, None)
    src_stream = np.random.randint(1, 12, size=n_stream)
    dst_stream = np.random.randint(30, 150, size=n_stream)
    pkt_sz_stream = np.clip(bps_stream / np.maximum(1.0, pps_stream), 64, 1500)
    
    # Concatenate normal subsets
    pps_normal = np.concatenate([pps_idle, pps_browse, pps_stream])
    bps_normal = np.concatenate([bps_idle, bps_browse, bps_stream])
    tcp_norm = np.concatenate([tcp_idle, tcp_browse, tcp_stream])
    udp_norm = np.concatenate([udp_idle, udp_browse, udp_stream])
    icmp_norm = np.concatenate([icmp_idle, icmp_browse, icmp_stream])
    syn_norm = np.concatenate([syn_idle, syn_browse, syn_stream])
    pkt_sz_norm = np.concatenate([pkt_sz_idle, pkt_sz_browse, pkt_sz_stream])
    src_norm = np.concatenate([src_idle, src_browse, src_stream])
    dst_norm = np.concatenate([dst_idle, dst_browse, dst_stream])
    conn_norm = np.concatenate([conn_idle, conn_browse, conn_stream])
    
    df_normal = pd.DataFrame({
        "packets_per_second": np.round(pps_normal, 2),
        "bytes_per_second": np.round(bps_normal, 2),
        "tcp_count": tcp_norm,
        "udp_count": udp_norm,
        "icmp_count": icmp_norm,
        "syn_count": syn_norm,
        "average_packet_size": np.round(pkt_sz_norm, 1),
        "unique_source_ips": src_norm,
        "unique_destination_ips": dst_norm,
        "connection_count": conn_norm,
        "label": 0  # 0 = Normal
    })
    
    # =========================================================================
    # 2. Attack Traffic: Varied DDoS Vectors (3000 samples)
    # =========================================================================
    # Divide into: SYN Flood (40%), UDP Flood (30%), ICMP Flood (15%), HTTP/Connection Flood (15%)
    n_syn = int(half * 0.40)
    n_udp = int(half * 0.30)
    n_icmp = int(half * 0.15)
    n_http = half - (n_syn + n_udp + n_icmp)
    
    # 2A. TCP SYN Flood
    pps_syn = np.random.uniform(4000, 22000, size=n_syn)
    pkt_sz_syn = np.random.uniform(54, 80, size=n_syn)  # Minimal TCP header packets
    bps_syn = pps_syn * pkt_sz_syn
    tcp_syn = pps_syn.astype(int)
    udp_syn = np.random.randint(0, 15, size=n_syn)
    icmp_syn = np.random.randint(0, 5, size=n_syn)
    syn_syn = (tcp_syn * np.random.uniform(0.92, 0.99, size=n_syn)).astype(int)
    src_ips_syn = np.random.randint(400, 8000, size=n_syn)  # Spoofed IP fan-in
    dst_ips_syn = np.random.randint(1, 3, size=n_syn)       # Targeted victim
    conn_syn = np.random.randint(1500, 7000, size=n_syn)
    
    df_syn = pd.DataFrame({
        "packets_per_second": np.round(pps_syn, 2),
        "bytes_per_second": np.round(bps_syn, 2),
        "tcp_count": tcp_syn,
        "udp_count": udp_syn,
        "icmp_count": icmp_syn,
        "syn_count": syn_syn,
        "average_packet_size": np.round(pkt_sz_syn, 1),
        "unique_source_ips": src_ips_syn,
        "unique_destination_ips": dst_ips_syn,
        "connection_count": conn_syn,
        "label": 1
    })
    
    # 2B. UDP Volumetric Flood
    pps_udp = np.random.uniform(5000, 28000, size=n_udp)
    pkt_sz_udp = np.random.uniform(512, 1400, size=n_udp)
    bps_udp = pps_udp * pkt_sz_udp
    udp_udp = pps_udp.astype(int)
    tcp_udp = np.random.randint(0, 50, size=n_udp)
    icmp_udp = np.random.randint(0, 10, size=n_udp)
    syn_udp = np.random.randint(0, 5, size=n_udp)
    src_ips_udp = np.random.randint(200, 5000, size=n_udp)
    dst_ips_udp = np.random.randint(1, 4, size=n_udp)
    conn_udp = np.random.randint(500, 3500, size=n_udp)
    
    df_udp = pd.DataFrame({
        "packets_per_second": np.round(pps_udp, 2),
        "bytes_per_second": np.round(bps_udp, 2),
        "tcp_count": tcp_udp,
        "udp_count": udp_udp,
        "icmp_count": icmp_udp,
        "syn_count": syn_udp,
        "average_packet_size": np.round(pkt_sz_udp, 1),
        "unique_source_ips": src_ips_udp,
        "unique_destination_ips": dst_ips_udp,
        "connection_count": conn_udp,
        "label": 1
    })
    
    # 2C. ICMP Ping Flood
    pps_icmp = np.random.uniform(3000, 15000, size=n_icmp)
    pkt_sz_icmp = np.random.uniform(64, 512, size=n_icmp)
    bps_icmp = pps_icmp * pkt_sz_icmp
    icmp_icmp = pps_icmp.astype(int)
    tcp_icmp = np.random.randint(0, 20, size=n_icmp)
    udp_icmp = np.random.randint(0, 20, size=n_icmp)
    syn_icmp = np.zeros(n_icmp, dtype=int)
    src_ips_icmp = np.random.randint(100, 2000, size=n_icmp)
    dst_ips_icmp = np.random.randint(1, 2, size=n_icmp)
    conn_icmp = np.random.randint(10, 100, size=n_icmp)
    
    df_icmp = pd.DataFrame({
        "packets_per_second": np.round(pps_icmp, 2),
        "bytes_per_second": np.round(bps_icmp, 2),
        "tcp_count": tcp_icmp,
        "udp_count": udp_icmp,
        "icmp_count": icmp_icmp,
        "syn_count": syn_icmp,
        "average_packet_size": np.round(pkt_sz_icmp, 1),
        "unique_source_ips": src_ips_icmp,
        "unique_destination_ips": dst_ips_icmp,
        "connection_count": conn_icmp,
        "label": 1
    })
    
    # 2D. HTTP / Layer-7 Volumetric Flood
    pps_http = np.random.uniform(2000, 8000, size=n_http)
    pkt_sz_http = np.random.uniform(250, 600, size=n_http)
    bps_http = pps_http * pkt_sz_http
    tcp_http = pps_http.astype(int)
    udp_http = np.random.randint(0, 40, size=n_http)
    icmp_http = np.random.randint(0, 5, size=n_http)
    syn_http = (tcp_http * np.random.uniform(0.15, 0.35, size=n_http)).astype(int)
    src_ips_http = np.random.randint(500, 4000, size=n_http)
    dst_ips_http = np.random.randint(1, 5, size=n_http)
    conn_http = np.random.randint(2500, 9000, size=n_http)
    
    df_http = pd.DataFrame({
        "packets_per_second": np.round(pps_http, 2),
        "bytes_per_second": np.round(bps_http, 2),
        "tcp_count": tcp_http,
        "udp_count": udp_http,
        "icmp_count": icmp_http,
        "syn_count": syn_http,
        "average_packet_size": np.round(pkt_sz_http, 1),
        "unique_source_ips": src_ips_http,
        "unique_destination_ips": dst_ips_http,
        "connection_count": conn_http,
        "label": 1
    })
    
    # Combine and shuffle
    df_all = pd.concat([df_normal, df_syn, df_udp, df_icmp, df_http], ignore_index=True)
    df_all = df_all.sample(frac=1.0, random_state=42).reset_index(drop=True)
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df_all.to_csv(output_path, index=False)
    print(f"[+] Successfully synthesized dataset with {len(df_all)} samples at: {output_path}")
    print(f"    - Normal samples: {len(df_normal)}")
    print(f"    - DDoS Attack samples: {len(df_syn) + len(df_udp) + len(df_icmp) + len(df_http)}")
    return df_all

if __name__ == "__main__":
    generate_telemetry_dataset()
