from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta
from typing import Any
import uuid

from app.core.events import SecurityEvent, DetectionAlert, EventType, Severity


class Rule(ABC):
    def __init__(
        self,
        rule_id: str,
        rule_name: str,
        description: str,
        base_confidence: float,
        risk_contribution: int,
    ):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.description = description
        self.base_confidence = base_confidence
        self.risk_contribution = risk_contribution

    @abstractmethod
    def evaluate(
        self, event: SecurityEvent, history: list[SecurityEvent]
    ) -> DetectionAlert | None:
        pass

    def _create_alert(
        self,
        event: SecurityEvent,
        confidence: float,
        evidence: dict[str, Any],
        message: str,
    ) -> DetectionAlert:
        return DetectionAlert(
            alert_id=str(uuid.uuid4()),
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            matched=True,
            confidence=confidence,
            evidence=evidence,
            risk_contribution=self.risk_contribution,
            timestamp=datetime.now(timezone.utc),
            host=event.host,
            user=event.user,
            message=message,
        )


class Rule001_BruteForce(Rule):
    """
    Multiple failed logins within a time window (e.g. 5 failed logins within 60 seconds).
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-001",
            rule_name="Brute Force Authentication",
            description="Multiple failed login attempts detected in a short time window",
            base_confidence=0.8,
            risk_contribution=25,
        )

    def evaluate(
        self, event: SecurityEvent, history: list[SecurityEvent]
    ) -> DetectionAlert | None:
        if event.event_type != EventType.LOGIN_FAILURE:
            return None

        # Filter history for LOGIN_FAILURE from same source_ip or user within last 60 seconds
        cutoff = event.timestamp - timedelta(seconds=60)
        failures = [
            e for e in history
            if e.event_type == EventType.LOGIN_FAILURE
            and e.timestamp >= cutoff
            and (
                (e.source_ip == event.source_ip and event.source_ip is not None)
                or (e.user == event.user and event.user is not None)
            )
        ]

        total_failures = len(failures) + 1  # include current event

        if total_failures >= 5:
            evidence = {
                "failed_login_count": total_failures,
                "window_seconds": 60,
                "source_ip": event.source_ip,
                "target_user": event.user,
                "failure_timestamps": [e.timestamp.isoformat() for e in failures] + [event.timestamp.isoformat()],
            }
            return self._create_alert(
                event=event,
                confidence=self.base_confidence,
                evidence=evidence,
                message=f"Brute force attempt: {total_failures} failed logins in 60s for user '{event.user}' from {event.source_ip}.",
            )
        return None


class Rule002_FailedThenSuccess(Rule):
    """
    Failed logins followed by successful login (same source IP / user within 60s).
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-002",
            rule_name="Successful Login After Failures",
            description="Successful logon detected immediately following multiple login failures",
            base_confidence=0.9,
            risk_contribution=35,
        )

    def evaluate(
        self, event: SecurityEvent, history: list[SecurityEvent]
    ) -> DetectionAlert | None:
        if event.event_type != EventType.LOGIN_SUCCESS:
            return None

        # Filter history for LOGIN_FAILURE from same source_ip or user within last 60 seconds
        cutoff = event.timestamp - timedelta(seconds=60)
        failures = [
            e for e in history
            if e.event_type == EventType.LOGIN_FAILURE
            and e.timestamp >= cutoff
            and (
                (e.source_ip == event.source_ip and event.source_ip is not None)
                or (e.user == event.user and event.user is not None)
            )
        ]

        if len(failures) >= 3:
            evidence = {
                "failed_login_count": len(failures),
                "window_seconds": 60,
                "source_ip": event.source_ip,
                "user": event.user,
                "success_timestamp": event.timestamp.isoformat(),
            }
            return self._create_alert(
                event=event,
                confidence=self.base_confidence,
                evidence=evidence,
                message=f"Suspicious Logon: User '{event.user}' logged in successfully after {len(failures)} failures from {event.source_ip}.",
            )
        return None


class Rule003_UnusualPrivileges(Rule):
    """
    Unusual privilege assignment (SPECIAL_PRIVILEGES event with sensitive privileges).
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-003",
            rule_name="Sensitive Privileges Assigned",
            description="Special administrative privileges assigned during user logon",
            base_confidence=0.7,
            risk_contribution=20,
        )
        self.sensitive_privs = {
            "SeDebugPrivilege",
            "SeTcbPrivilege",
            "SeTakeOwnershipPrivilege",
            "SeLoadDriverPrivilege",
            "SeBackupPrivilege",
            "SeRestorePrivilege",
            "SeCreateTokenPrivilege",
        }

    def evaluate(
        self, event: SecurityEvent, history: list[SecurityEvent]
    ) -> DetectionAlert | None:
        if event.event_type != EventType.SPECIAL_PRIVILEGES:
            return None

        privs = event.metadata.get("privilege_list", [])
        matched_privs = [p for p in privs if p in self.sensitive_privs]

        if matched_privs:
            evidence = {
                "assigned_privileges": privs,
                "matched_sensitive_privileges": matched_privs,
            }
            return self._create_alert(
                event=event,
                confidence=self.base_confidence,
                evidence=evidence,
                message=f"Sensitive privileges ({', '.join(matched_privs)}) assigned to user '{event.user}'.",
            )
        return None


class Rule004_SuspiciousService(Rule):
    """
    New service installation (SERVICE_INSTALLED event, check service path/name).
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-004",
            rule_name="New Service Installed",
            description="A new system service was registered on the host",
            base_confidence=0.6,
            risk_contribution=20,
        )

    def evaluate(
        self, event: SecurityEvent, history: list[SecurityEvent]
    ) -> DetectionAlert | None:
        if event.event_type != EventType.SERVICE_INSTALLED:
            return None

        service_name = event.metadata.get("service_name", "")
        service_path = (event.process_name or "").lower()

        # Check if the service binary executes from a suspicious location
        suspicious_paths = ["\\temp\\", "\\appdata\\", "\\users\\", "\\programdata\\"]
        is_suspicious_path = any(p in service_path for p in suspicious_paths)

        confidence = self.base_confidence
        risk = self.risk_contribution

        if is_suspicious_path:
            confidence = 0.95
            risk += 20  # Escalate risk if running from user/temp directory

        evidence = {
            "service_name": service_name,
            "service_path": event.process_name,
            "is_suspicious_path": is_suspicious_path,
        }

        return self._create_alert(
            event=event,
            confidence=confidence,
            evidence=evidence,
            message=f"New service '{service_name}' installed running '{event.process_name}'" + 
                    (" (SUSPICIOUS PATH)" if is_suspicious_path else "") + ".",
        )


class Rule005_CredentialAccessProcess(Rule):
    """
    Credential access combined with suspicious process activity.
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-005",
            rule_name="Credential Access with Process Activity",
            description="Credential Manager read followed by execution of shell utility",
            base_confidence=0.85,
            risk_contribution=40,
        )
        self.suspicious_binaries = {
            "cmd.exe",
            "powershell.exe",
            "whoami.exe",
            "mimikatz.exe",
            "psexec.exe",
            "net.exe",
            "vssadmin.exe",
        }

    def evaluate(
        self, event: SecurityEvent, history: list[SecurityEvent]
    ) -> DetectionAlert | None:
        # Trigger on either CREDENTIAL_ACCESS or suspicious process launch, correlating with the other
        if event.event_type == EventType.CREDENTIAL_ACCESS:
            # Check for recent suspicious process creation on same host (last 5 min)
            cutoff = event.timestamp - timedelta(minutes=5)
            processes = [
                e for e in history
                if e.event_type == EventType.PROCESS_CREATED
                and e.timestamp >= cutoff
                and e.host == event.host
                and any(b in (e.process_name or "").lower() for b in self.suspicious_binaries)
            ]
            if processes:
                evidence = {
                    "credential_read": event.metadata.get("target_name"),
                    "recent_processes": [p.process_name for p in processes],
                }
                return self._create_alert(
                    event=event,
                    confidence=self.base_confidence,
                    evidence=evidence,
                    message=f"Credential read '{event.metadata.get('target_name')}' correlated with recent suspicious process '{processes[0].process_name}' on {event.host}.",
                )

        elif event.event_type == EventType.PROCESS_CREATED:
            proc_lower = (event.process_name or "").lower()
            if any(b in proc_lower for b in self.suspicious_binaries):
                # Check for recent credential access on same host (last 5 min)
                cutoff = event.timestamp - timedelta(minutes=5)
                creds = [
                    e for e in history
                    if e.event_type == EventType.CREDENTIAL_ACCESS
                    and e.timestamp >= cutoff
                    and e.host == event.host
                ]
                if creds:
                    evidence = {
                        "suspicious_process": event.process_name,
                        "recent_credential_reads": [c.metadata.get("target_name") for c in creds],
                    }
                    return self._create_alert(
                        event=event,
                        confidence=self.base_confidence,
                        evidence=evidence,
                        message=f"Suspicious process '{event.process_name}' launched immediately after credential manager access on {event.host}.",
                    )

        return None


class Rule006_UnusualLoginSource(Rule):
    """
    Unusual login source (login from external or non-standard network address).
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-006",
            rule_name="Unusual Logon Source IP",
            description="Successful logon originating from non-local/external network address",
            base_confidence=0.75,
            risk_contribution=25,
        )

    def evaluate(
        self, event: SecurityEvent, history: list[SecurityEvent]
    ) -> DetectionAlert | None:
        if event.event_type not in (EventType.LOGIN_SUCCESS, EventType.LOGIN_FAILURE):
            return None

        ip = event.source_ip
        if not ip:
            return None

        # Check if external or non-standard IP (e.g. not localhost or common private range)
        is_local = (
            ip == "127.0.0.1"
            or ip == "::1"
            or ip.startswith("192.168.")
            or ip.startswith("10.")
            or ip.startswith("172.16.")
            or ip == "localhost"
        )

        if not is_local:
            evidence = {
                "source_ip": ip,
                "user": event.user,
                "event_type": event.event_type.value,
            }
            return self._create_alert(
                event=event,
                confidence=self.base_confidence,
                evidence=evidence,
                message=f"Logon activity for '{event.user}' detected from external/unusual IP: {ip}.",
            )
        return None


class Rule007_AnomalousHostActivity(Rule):
    """
    Multiple anomalies on the same host within 5 minutes.
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-007",
            rule_name="Multi-Anomaly Host Activity",
            description="Multiple distinct security events or anomalies detected on a single host in a short time window",
            base_confidence=0.8,
            risk_contribution=30,
        )

    def evaluate(
        self, event: SecurityEvent, history: list[SecurityEvent]
    ) -> DetectionAlert | None:
        # Trigger on any event, checks if this host has multiple high severity events or anomalies in past 5 mins
        cutoff = event.timestamp - timedelta(minutes=5)
        host_events = [
            e for e in history
            if e.host == event.host
            and e.timestamp >= cutoff
            and e.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
        ]

        # Count unique event types
        unique_types = {e.event_type for e in host_events}
        unique_types.add(event.event_type)

        if len(host_events) >= 4 or len(unique_types) >= 3:
            evidence = {
                "historical_severity_events_count": len(host_events),
                "unique_event_types": list(unique_types),
            }
            return self._create_alert(
                event=event,
                confidence=self.base_confidence,
                evidence=evidence,
                message=f"Host '{event.host}' exhibiting high rate of diverse security events (Count: {len(host_events) + 1}, Event Types: {len(unique_types)}).",
            )
        return None


class Rule008_SuspiciousProcessChain(Rule):
    """
    Suspicious process chain (e.g. web/database servers launching cmd/powershell, or explorer launching cmd launching whoami).
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-008",
            rule_name="Suspicious Process Execution Chain",
            description="Web/database server or system shell executing suspicious system utility",
            base_confidence=0.9,
            risk_contribution=45,
        )
        self.server_binaries = {
            "w3wp.exe",
            "nginx.exe",
            "httpd.exe",
            "sqlservr.exe",
            "tomcat.exe",
            "wsmprovhost.exe",  # WinRM
        }
        self.shell_binaries = {"cmd.exe", "powershell.exe"}
        self.recon_binaries = {
            "whoami.exe",
            "net.exe",
            "nltest.exe",
            "ipconfig.exe",
            "vssadmin.exe",
            "systeminfo.exe",
            "quser.exe",
        }

    def evaluate(
        self, event: SecurityEvent, history: list[SecurityEvent]
    ) -> DetectionAlert | None:
        if event.event_type != EventType.PROCESS_CREATED:
            return None

        proc_lower = (event.process_name or "").lower()
        parent_lower = (event.parent_process or "").lower()

        # Case 1: Web server or SQL server spawning cmd/powershell (Web Shell / SQL Injection Execution)
        is_server_parent = any(s in parent_lower for s in self.server_binaries)
        is_shell_child = any(s in proc_lower for s in self.shell_binaries)

        if is_server_parent and is_shell_child:
            evidence = {
                "parent_process": event.parent_process,
                "child_process": event.process_name,
                "command_line": event.metadata.get("command_line"),
                "scenario": "server_spawning_shell",
            }
            return self._create_alert(
                event=event,
                confidence=0.95,
                evidence=evidence,
                message=f"Critical Process Chain: Server process '{event.parent_process}' spawned terminal shell '{event.process_name}' on {event.host}.",
            )

        # Case 2: Shell spawning recon tool (Execution / Discovery stage)
        is_shell_parent = any(s in parent_lower for s in self.shell_binaries)
        is_recon_child = any(r in proc_lower for r in self.recon_binaries)

        if is_shell_parent and is_recon_child:
            evidence = {
                "parent_process": event.parent_process,
                "child_process": event.process_name,
                "command_line": event.metadata.get("command_line"),
                "scenario": "shell_spawning_recon",
            }
            return self._create_alert(
                event=event,
                confidence=self.base_confidence,
                evidence=evidence,
                message=f"Suspicious Process Chain: Shell '{event.parent_process}' executed reconnaissance tool '{event.process_name}' on {event.host}.",
            )

        return None


ALL_RULES: list[Rule] = [
    Rule001_BruteForce(),
    Rule002_FailedThenSuccess(),
    Rule003_UnusualPrivileges(),
    Rule004_SuspiciousService(),
    Rule005_CredentialAccessProcess(),
    Rule006_UnusualLoginSource(),
    Rule007_AnomalousHostActivity(),
    Rule008_SuspiciousProcessChain(),
]
