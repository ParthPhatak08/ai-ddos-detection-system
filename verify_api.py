import urllib.request
import json
import time

def test_endpoint(name, url, method="GET", data=None):
    try:
        encoded_data = json.dumps(data).encode("utf-8") if data else None
        headers = {"Content-Type": "application/json"} if data else {}
        req = urllib.request.Request(url, data=encoded_data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=5) as res:
            body = res.read()
            status = res.status
            content_type = res.headers.get("Content-Type", "")
            preview = body[:80].decode("utf-8", errors="ignore").replace("\n", " ")
            print(f"[SUCCESS] {name:<30} | HTTP {status} | {content_type.split(';')[0]} | {preview[:45]}...")
            return True, body
    except Exception as e:
        print(f"[FAIL]    {name:<30} | Error: {e}")
        return False, None

print("="*75)
print("  DDoS Detection System - Complete API & Endpoint Verification Suite")
print("="*75)

print("\n1. WEB PAGE ROUTES:")
test_endpoint("Dashboard (GET /)", "http://127.0.0.1:5000/")
test_endpoint("Statistics (GET /statistics)", "http://127.0.0.1:5000/statistics")
test_endpoint("Threat History (GET /history)", "http://127.0.0.1:5000/history")
test_endpoint("Export CSV (GET /export/csv)", "http://127.0.0.1:5000/export/csv")

print("\n2. LIVE TELEMETRY & SYSTEM STATE:")
ok, body = test_endpoint("Live Status (GET /api/status)", "http://127.0.0.1:5000/api/status")
if ok and body:
    s = json.loads(body)
    print(f"   Mode: {s.get('mode')}")
    print(f"   Prediction: {s.get('prediction')} (Confidence: {s.get('confidence', 0)*100:.1f}%)")
    print(f"   Risk Level: {s.get('risk_level')}")
    m = s.get("metrics", {})
    print(f"   Live Flow: {m.get('packets_per_second')} pps | {m.get('bytes_per_second')/1024:.1f} KB/s | {m.get('connection_count')} connections")
    print(f"   Recent Alerts Count: {len(s.get('recent_events', []))}")

ok2, body2 = test_endpoint("Statistics API (GET /api/statistics)", "http://127.0.0.1:5000/api/statistics")
if ok2 and body2:
    st = json.loads(body2)
    print(f"   Classification Breakdown: Normal={st.get('normal_count')} | DDoS={st.get('ddos_count')}")
    print(f"   Total Processed Packets: {st.get('total_packets'):,} | Bytes: {st.get('total_bytes'):,}")

print("\n3. SIMULATION DYNAMICS & AUTO-COOLDOWN VERIFICATION:")
print("   -> Injecting 'UDP_FLOOD' attack burst...")
test_endpoint("Trigger Attack (POST /api/simulate/ddos)", "http://127.0.0.1:5000/api/simulate/ddos", method="POST", data={"vector": "UDP_FLOOD"})

time.sleep(2.0)
ok_atk, body_atk = test_endpoint("Check Attack Status", "http://127.0.0.1:5000/api/status")
if ok_atk and body_atk:
    sa = json.loads(body_atk)
    print(f"   DURING ATTACK -> Prediction: {sa.get('prediction')} | Risk: {sa.get('risk_level')} | PPS: {sa.get('metrics', {}).get('packets_per_second')}")

print("\n   -> Returning to LIVE host capture mode...")
test_endpoint("Start Live (POST /api/start)", "http://127.0.0.1:5000/api/start", method="POST", data={"interface": "auto"})

print("\n   -> Purging historical alerts...")
test_endpoint("Clear History (POST /api/history/clear)", "http://127.0.0.1:5000/api/history/clear", method="POST", data={})

ok_final, body_final = test_endpoint("Final Live Status", "http://127.0.0.1:5000/api/status")
if ok_final and body_final:
    sf = json.loads(body_final)
    print(f"   FINAL -> Mode: {sf.get('mode')} | Risk: {sf.get('risk_level')} | Prediction: {sf.get('prediction')} | Alert Backlog: {len(sf.get('recent_events', []))}")

print("\n" + "="*75)
print("  All Endpoints & Real-Time Security Verification Complete")
print("="*75)
