import asyncio
import logging

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.enums import WebSocketMessageType
from app.core.events import SecurityEvent, DetectionAlert
from app.core.status import system_status
from app.collectors.windows_events import windows_collector
from app.streaming.consumer import detection_consumer
from app.streaming.event_generator import generate_events
from app.streaming.event_manager import event_manager
from app.incidents.models import Incident

# API Router Imports
from app.api.events import router as events_router
from app.api.incidents import router as incidents_router
from app.api.threats import router as threats_router
from app.api.risk import router as risk_router
from app.api.attack_graph import router as attack_graph_router
from app.api.response import router as response_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
)
logger = logging.getLogger("sentinelx.main")

app = FastAPI(
    title="SentinelX",
    description="Real-Time Autonomous Cyber Defense Platform",
    version="0.1.0",
)

# Add CORS Middleware to allow requests from the React development server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(events_router)
app.include_router(incidents_router)
app.include_router(threats_router)
app.include_router(risk_router)
app.include_router(attack_graph_router)
app.include_router(response_router)


@app.get("/")
async def root():
    return {
        "project": "SentinelX",
        "status": "online",
        "mode": settings.APP_ENV,
        "telemetry_mode": settings.TELEMETRY_MODE,
    }


@app.get("/health")
async def health():
    return system_status.to_dict()


@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await websocket.accept()
    system_status.websocket_clients += 1
    queue = event_manager.subscribe()

    try:
        while True:
            msg = await queue.get()
            
            # Formulate WebSocket payload based on object type
            if isinstance(msg, SecurityEvent):
                payload = {
                    "message_type": WebSocketMessageType.EVENT.value,
                    "data": msg.model_dump(mode="json"),
                }
            elif isinstance(msg, DetectionAlert):
                payload = {
                    "message_type": WebSocketMessageType.ALERT.value,
                    "data": msg.model_dump(mode="json"),
                }
            elif isinstance(msg, Incident):
                payload = {
                    "message_type": WebSocketMessageType.INCIDENT.value,
                    "data": msg.model_dump(mode="json"),
                }
            else:
                payload = {
                    "message_type": WebSocketMessageType.STATUS.value,
                    "data": msg,
                }

            await websocket.send_json(payload)
            queue.task_done()
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"[WEBSOCKET] Error streaming events to client: {e}")
    finally:
        event_manager.unsubscribe(queue)
        system_status.websocket_clients = max(0, system_status.websocket_clients - 1)


@app.on_event("startup")
async def startup():
    # 0. Initialize database tables
    from app.database.models import init_db
    logger.info("[STARTUP] Initializing SQLite database...")
    try:
        await init_db()
        system_status.database_status = "CONNECTED"
        logger.info("[STARTUP] Database initialized successfully.")
    except Exception as e:
        logger.error(f"[STARTUP] Database initialization failed: {e}")
        system_status.database_status = "DISCONNECTED"

    system_status.telemetry_mode = settings.TELEMETRY_MODE.upper()
    system_status.response_mode = settings.RESPONSE_MODE

    # 1. Start Detection & Correlation Consumer Engine
    logger.info("[STARTUP] Starting Detection Consumer Engine...")
    await detection_consumer.start()

    # 2. Start Telemetry Collectors
    if settings.TELEMETRY_MODE == "windows":
        logger.info("[STARTUP] Starting Windows Event Collector...")
        await windows_collector.start()
        # Allow collector to attempt initialization
        await asyncio.sleep(0.5)
        
        # If the collector failed to open the log completely, start simulated events
        if system_status.windows_collector == "STOPPED":
            logger.warning("[STARTUP] Windows collector failed to start. Falling back to development event generator.")
            system_status.telemetry_mode = "DEVELOPMENT"
            asyncio.create_task(generate_events())
    else:
        logger.info("[STARTUP] Starting development event generator...")
        system_status.telemetry_mode = "DEVELOPMENT"
        asyncio.create_task(generate_events())


@app.on_event("shutdown")
async def shutdown():
    logger.info("[SHUTDOWN] Stopping telemetry collectors & detection engine...")
    await windows_collector.stop()
    await detection_consumer.stop()