import asyncio
import threading
import time
import websockets
import json
import win32evtlog
import win32evtlogutil


def report_failed_logons():
    # Wait for websocket client to connect
    time.sleep(1.5)
    print("[TEST] Reporting 5 failed login attempts (4625) to Application log...")
    
    for i in range(5):
        strings = [""] * 21
        strings[5] = "target-user-bruteforce"
        strings[6] = "TEST-DOMAIN"
        strings[10] = "3"  # Logon Type: Network
        strings[19] = "10.0.0.99"  # Source IP
        
        win32evtlogutil.ReportEvent(
            "SentinelX-Test",
            4625,
            0,
            win32evtlog.EVENTLOG_WARNING_TYPE,
            strings,
        )
        print(f"[TEST] Failed login {i+1}/5 reported.")
        time.sleep(0.2)  # small interval between events

    print("[TEST] All failed logins reported.")


async def main():
    # Start thread to report events after connection is established
    thread = threading.Thread(target=report_failed_logons)
    thread.daemon = True
    thread.start()

    uri = "ws://127.0.0.1:8000/ws/events"
    print(f"[TEST] Connecting to {uri}...")
    
    events_received = 0
    alert_received = False
    
    async with websockets.connect(uri) as websocket:
        print("[TEST] Connected! Monitoring messages...")
        try:
            # We expect to receive 5 EVENTs and 1 ALERT
            # Set a 10 second timeout for the entire integration test
            start_time = time.time()
            while time.time() - start_time < 10.0:
                message = await asyncio.wait_for(websocket.recv(), timeout=2.0)
                msg_payload = json.loads(message)
                msg_type = msg_payload.get("message_type")
                data = msg_payload.get("data")
                
                print(f"[TEST] Received WebSocket message of type {msg_type}")
                
                if msg_type == "EVENT":
                    events_received += 1
                    print(f"       Raw Event: {data.get('event_type')} for user {data.get('user')}")
                elif msg_type == "ALERT":
                    if data.get("rule_id") == "RULE-001":
                        alert_received = True
                        print(f"       [ALERT MATCHED] Rule: {data.get('rule_name')}")
                        print(f"       Message: {data.get('message')}")
                        print(f"       Evidence: {json.dumps(data.get('evidence'), indent=2)}")
                        break  # We got our target alert, exit!

            assert events_received >= 5, f"Expected at least 5 login failure events, got {events_received}"
            assert alert_received is True, "Expected RULE-001 Brute Force alert, but it was not received"
            print("[TEST] SUCCESS: Real-time brute force detection and WebSocket alerting verified!")
            
        except asyncio.TimeoutError:
            print("[TEST] FAILED: Timed out waiting for messages on WebSocket.")
            exit(1)


if __name__ == "__main__":
    asyncio.run(main())
