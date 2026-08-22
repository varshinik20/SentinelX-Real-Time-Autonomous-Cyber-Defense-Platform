import asyncio
import time
import websockets
import json
import os
import sys

# Setup Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from attack_simulator.simulator import simulate_brute_force_chain


async def monitor_e2e_events():
    uri = "ws://127.0.0.1:8000/ws/events"
    print(f"[E2E] Connecting to {uri}...")
    
    events_received = []
    alerts_received = []
    incidents_received = []
    
    try:
        async with websockets.connect(uri) as websocket:
            print("[E2E] Connected! Triggering simulator playbook in 1s...")
            await asyncio.sleep(1.0)
            
            # Inject the brute force attack sequence
            simulate_brute_force_chain("e2e-victim", "10.0.0.55")
            
            print("[E2E] Telemetry injected. Monitoring WebSocket notifications...")
            
            start_time = time.time()
            # Monitor for up to 10 seconds to collect the full correlated chain
            while time.time() - start_time < 10.0:
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=1.5)
                    payload = json.loads(message)
                    msg_type = payload.get("message_type")
                    data = payload.get("data")
                    
                    print(f"[E2E] WebSocket notification: {msg_type}")
                    
                    if msg_type == "EVENT":
                        events_received.append(data)
                    elif msg_type == "ALERT":
                        alerts_received.append(data)
                    elif msg_type == "INCIDENT":
                        incidents_received.append(data)
                except asyncio.TimeoutError:
                    if incidents_received:
                        break
            
            print(f"\n[E2E] Telemetry Summary:")
            print(f"      - Events Captured: {len(events_received)}")
            print(f"      - Alerts Triaged: {len(alerts_received)}")
            print(f"      - Incidents Promoted: {len(incidents_received)}")
            
            # Verify E2E assertions
            assert len(events_received) >= 6, "Expected raw events to be polled and normalized"
            assert len(alerts_received) >= 2, "Expected multiple rules to match"
            assert len(incidents_received) >= 1, "Expected promotion into a correlated incident"
            
            latest_incident = incidents_received[-1]
            print(f"\n[E2E] Correlated Incident Details:")
            print(f"      - Incident ID: {latest_incident.get('incident_id')}")
            print(f"      - Risk Score: {latest_incident.get('risk_score')}/100")
            print(f"      - Severity Band: {latest_incident.get('severity')}")
            print(f"      - Target Account: {latest_incident.get('user')}")
            print(f"      - Target Host: {latest_incident.get('host')}")
            print(f"      - MITRE Techniques Tactic Map: {[t['technique_name'] for t in latest_incident.get('attack_techniques')]}")
            print(f"      - AI Copilot Investigator Analysis:")
            print(f"        {latest_incident.get('ai_summary')}")
            print(f"      - Containment Playbook:")
            for rec in latest_incident.get("recommendations", []):
                print(f"        * {rec}")
                
            assert latest_incident.get("risk_score") >= 70, "Incident risk score should be promoted above threshold"
            assert latest_incident.get("ai_summary") is not None, "AI Investigator should yield analysis summaries"
            assert len(latest_incident.get("recommendations")) > 0, "analyst recommendations should be generated"
            assert "nodes" in latest_incident.get("attack_graph"), "Attack graph nodes should be built"
            assert len(latest_incident.get("attack_graph")["nodes"]) > 0, "Attack graph nodes list should not be empty"

            print("\n[E2E] SUCCESS: End-to-end real-time autonomous threat detection verified!")

    except Exception as e:
        print(f"[E2E] Test failed with exception: {e}")
        sys.exit(1)


def main():
    asyncio.run(monitor_e2e_events())


if __name__ == "__main__":
    main()
