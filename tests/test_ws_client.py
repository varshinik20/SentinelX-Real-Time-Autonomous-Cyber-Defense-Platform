import asyncio
import threading
import time
import websockets
import json
import win32evtlog
import win32evtlogutil


def report_test_event():
    # Wait for websocket client to connect
    time.sleep(1)
    print("[TEST] Reporting 4624 event to Application log...")
    strings = [""] * 20
    strings[5] = "WS-REALTIME-USER"
    strings[6] = "WS-REALTIME-DOMAIN"
    strings[18] = "192.168.1.99"
    win32evtlogutil.ReportEvent(
        "SentinelX-Test",
        4624,
        0,
        win32evtlog.EVENTLOG_INFORMATION_TYPE,
        strings,
    )
    print("[TEST] Event reported successfully.")


async def main():
    # Start thread to report event after we connect
    thread = threading.Thread(target=report_test_event)
    thread.daemon = True
    thread.start()

    uri = "ws://127.0.0.1:8000/ws/events"
    print(f"[TEST] Connecting to {uri}...")
    
    async with websockets.connect(uri) as websocket:
        print("[TEST] Connected! Waiting for event...")
        try:
            # Wait for event with a timeout of 5 seconds
            message = await asyncio.wait_for(websocket.recv(), timeout=5.0)
            event = json.loads(message)
            print(f"[TEST] Received event over WebSocket: {json.dumps(event, indent=2)}")
            
            # Assertions to verify correctness
            assert event["event_type"] == "LOGIN_SUCCESS"
            assert event["user"] == "WS-REALTIME-DOMAIN\\WS-REALTIME-USER"
            assert event["source_ip"] == "192.168.1.99"
            assert event["metadata"]["win_event_id"] == 4624
            print("[TEST] SUCCESS: Real-time event propagation verified successfully!")
        except asyncio.TimeoutError:
            print("[TEST] FAILED: Timed out waiting for event on WebSocket.")
            exit(1)


if __name__ == "__main__":
    asyncio.run(main())
