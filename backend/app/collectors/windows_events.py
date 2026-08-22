import asyncio
import logging
import uuid
from datetime import datetime, timezone
import win32evtlog
import win32evtlogutil
import win32security
import pywintypes

from app.core.config import settings
from app.core.events import SecurityEvent, EventType, Severity
from app.core.status import system_status
from app.streaming.event_manager import event_manager

logger = logging.getLogger("sentinelx.windows_events")


def parse_windows_event(record, log_name: str) -> SecurityEvent | None:
    raw_id = record.EventID
    event_id_masked = raw_id & 0xFFFF

    # Map Windows Event IDs to canonical event types and default severities
    event_id_map = {
        4624: (EventType.LOGIN_SUCCESS, Severity.LOW),
        4625: (EventType.LOGIN_FAILURE, Severity.MEDIUM),
        4648: (EventType.EXPLICIT_CREDENTIAL_LOGIN, Severity.MEDIUM),
        4672: (EventType.SPECIAL_PRIVILEGES, Severity.MEDIUM),
        4688: (EventType.PROCESS_CREATED, Severity.LOW),
        4697: (EventType.SERVICE_INSTALLED, Severity.MEDIUM),
        5379: (EventType.CREDENTIAL_ACCESS, Severity.MEDIUM),
    }

    if event_id_masked not in event_id_map:
        return None

    event_type, severity = event_id_map[event_id_masked]

    user = None
    source_ip = None
    destination_ip = None
    process_name = None
    parent_process = None
    message = ""

    # Try LookupAccountSid to get User identifier if SID is available
    if record.Sid:
        try:
            name, domain, _ = win32security.LookupAccountSid(None, record.Sid)
            user = f"{domain}\\{name}"
        except Exception:
            pass

    inserts = record.StringInserts or []
    n_inserts = len(inserts)

    metadata = {
        "win_event_id": event_id_masked,
        "win_raw_id": raw_id,
        "source_name": record.SourceName,
        "record_number": record.RecordNumber,
        "log_name": log_name,
    }

    # Format the event message safely
    try:
        message = win32evtlogutil.SafeFormatMessage(record, log_name).strip()
    except Exception:
        message = f"Windows Event {event_id_masked} from {record.SourceName}"

    # Extract event-specific data based on standard Windows Event fields
    if event_id_masked == 4624:  # LOGIN_SUCCESS
        if n_inserts > 5:
            user = f"{inserts[6]}\\{inserts[5]}" if n_inserts > 6 else inserts[5]
        if n_inserts > 8:
            metadata["logon_type"] = inserts[8]
        if n_inserts > 18:
            source_ip = inserts[18]
            if source_ip in ("-", "::1", "127.0.0.1"):
                source_ip = "127.0.0.1"
            metadata["source_ip"] = source_ip

    elif event_id_masked == 4625:  # LOGIN_FAILURE
        if n_inserts > 5:
            user = f"{inserts[6]}\\{inserts[5]}" if n_inserts > 6 else inserts[5]
        if n_inserts > 10:
            metadata["logon_type"] = inserts[10]
        if n_inserts > 19:
            source_ip = inserts[19]
            if source_ip in ("-", "::1", "127.0.0.1"):
                source_ip = "127.0.0.1"
            metadata["source_ip"] = source_ip

    elif event_id_masked == 4648:  # EXPLICIT_CREDENTIAL_LOGIN
        if n_inserts > 1:
            user = f"{inserts[2]}\\{inserts[1]}"
        if n_inserts > 5:
            metadata["target_user"] = f"{inserts[6]}\\{inserts[5]}" if n_inserts > 6 else inserts[5]
        if n_inserts > 12:
            source_ip = inserts[12]
            if source_ip in ("-", "::1", "127.0.0.1"):
                source_ip = "127.0.0.1"
            metadata["source_ip"] = source_ip

    elif event_id_masked == 4672:  # SPECIAL_PRIVILEGES
        if n_inserts > 1:
            user = f"{inserts[2]}\\{inserts[1]}"
        if n_inserts > 3:
            metadata["privilege_list"] = [p.strip() for p in inserts[3].split("\n") if p.strip()]

    elif event_id_masked == 4688:  # PROCESS_CREATED
        if n_inserts > 1:
            user = f"{inserts[2]}\\{inserts[1]}"
        if n_inserts > 5:
            process_name = inserts[5]
        if n_inserts > 8:
            metadata["command_line"] = inserts[8]
        if n_inserts > 13:
            parent_process = inserts[13]
        metadata["new_process_id"] = inserts[4] if n_inserts > 4 else None

    elif event_id_masked == 4697:  # SERVICE_INSTALLED
        if n_inserts > 0:
            metadata["service_name"] = inserts[0]
        if n_inserts > 1:
            process_name = inserts[1]
        if n_inserts > 4:
            user = inserts[4]

    elif event_id_masked == 5379:  # CREDENTIAL_ACCESS
        if n_inserts > 1:
            user = f"{inserts[2]}\\{inserts[1]}"
        if n_inserts > 4:
            metadata["target_name"] = inserts[4]
        if n_inserts > 5:
            metadata["credential_type"] = inserts[5]

    try:
        timestamp = datetime.fromtimestamp(record.TimeGenerated.timestamp(), tz=timezone.utc)
    except Exception:
        timestamp = datetime.now(timezone.utc)

    return SecurityEvent(
        event_id=str(uuid.uuid4()),
        timestamp=timestamp,
        event_type=event_type,
        source="windows-event-log",
        host=record.ComputerName or "unknown",
        user=user,
        source_ip=source_ip,
        destination_ip=destination_ip,
        process_name=process_name,
        parent_process=parent_process,
        severity=severity,
        message=message,
        metadata=metadata
    )


class WindowsEventCollector:
    def __init__(self):
        self.log_name = "Security"
        self.handle = None
        self.last_record_number = None
        self.is_running = False
        self._task = None

    def _open_log(self) -> bool:
        try:
            self.handle = win32evtlog.OpenEventLog(None, self.log_name)
            count = win32evtlog.GetNumberOfEventLogRecords(self.handle)
            oldest = win32evtlog.GetOldestEventLogRecord(self.handle)
            self.last_record_number = oldest + count - 1
            logger.info(f"[WINDOWS] Successfully opened Security event log. Starting record: {self.last_record_number}")
            system_status.windows_collector = "RUNNING"
            system_status.telemetry_mode = "WINDOWS"
            return True
        except pywintypes.error as e:
            err_code = e.winerror
            logger.warning(f"[WINDOWS] Failed to open Security log (Error {err_code}: {e.strerror}).")
            system_status.degraded = True
            system_status.warnings.append(f"Insufficient privileges to read Security Event Log (Error {err_code}).")

            # Fall back to Application log to verify pipeline functionality
            try:
                self.log_name = "Application"
                self.handle = win32evtlog.OpenEventLog(None, self.log_name)
                count = win32evtlog.GetNumberOfEventLogRecords(self.handle)
                oldest = win32evtlog.GetOldestEventLogRecord(self.handle)
                self.last_record_number = oldest + count - 1
                logger.info(f"[WINDOWS] Falling back to Application log. Starting record: {self.last_record_number}")
                system_status.windows_collector = "DEGRADED"
                system_status.telemetry_mode = "WINDOWS"
                return True
            except Exception as ex:
                logger.error(f"[WINDOWS] Failed to open fallback Application event log: {ex}")
                system_status.windows_collector = "STOPPED"
                return False

    async def start(self):
        if self.is_running:
            return
        self.is_running = True
        self._task = asyncio.create_task(self._poll_loop())

    async def stop(self):
        self.is_running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        if self.handle:
            try:
                win32evtlog.CloseEventLog(self.handle)
            except Exception:
                pass
            self.handle = None
        system_status.windows_collector = "STOPPED"

    async def _poll_loop(self):
        if not self._open_log():
            logger.warning("[WINDOWS] Collector failing back to development generator because Event Log access failed.")
            system_status.windows_collector = "STOPPED"
            return

        flags = win32evtlog.EVENTLOG_SEEK_READ | win32evtlog.EVENTLOG_FORWARDS_READ

        while self.is_running:
            try:
                count = win32evtlog.GetNumberOfEventLogRecords(self.handle)
                oldest = win32evtlog.GetOldestEventLogRecord(self.handle)
                latest_in_log = oldest + count - 1

                if latest_in_log > self.last_record_number:
                    read_from = self.last_record_number + 1
                    
                    while read_from <= latest_in_log:
                        try:
                            events = win32evtlog.ReadEventLog(self.handle, flags, read_from)
                            if not events:
                                break
                            
                            for e in events:
                                parsed = parse_windows_event(e, self.log_name)
                                if parsed:
                                    await event_manager.publish(parsed)
                                    print(f"[WINDOWS EVENT] {parsed.timestamp.isoformat()} | {parsed.event_type.value} | {parsed.message}")
                                
                                read_from = max(read_from, e.RecordNumber + 1)
                                self.last_record_number = max(self.last_record_number, e.RecordNumber)
                        except pywintypes.error as e:
                            if e.winerror == 87:  # Parameter incorrect, log may have rotated/cleared
                                oldest = win32evtlog.GetOldestEventLogRecord(self.handle)
                                read_from = oldest
                                self.last_record_number = oldest - 1
                                logger.warning(f"[WINDOWS] Event Log cleared or rotated. Resetting starting point to {oldest}")
                            else:
                                raise e
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[WINDOWS] Error in poll loop: {e}", exc_info=True)
                await asyncio.sleep(5)
                self._open_log()
                
            await asyncio.sleep(settings.WINDOWS_POLL_INTERVAL)


windows_collector = WindowsEventCollector()
