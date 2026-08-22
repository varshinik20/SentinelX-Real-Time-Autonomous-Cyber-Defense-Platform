class SystemStatus:
    def __init__(self):
        self.windows_collector = "STOPPED"
        self.detection_engine = "STOPPED"
        self.correlation_engine = "STOPPED"
        self.websocket_clients = 0
        self.ai_status = "UNAVAILABLE"
        self.response_mode = "DRY_RUN"
        self.database_status = "DISCONNECTED"
        self.telemetry_mode = "DEVELOPMENT"
        self.degraded = False
        self.warnings: list[str] = []

    def to_dict(self) -> dict:
        return {
            "windows_collector": self.windows_collector,
            "detection": self.detection_engine,
            "correlation": self.correlation_engine,
            "websocket_clients": self.websocket_clients,
            "ai": self.ai_status,
            "response_mode": self.response_mode,
            "database": self.database_status,
            "telemetry_mode": self.telemetry_mode,
            "degraded": self.degraded,
            "warnings": self.warnings,
        }


system_status = SystemStatus()
