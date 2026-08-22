from datetime import datetime, timezone
import pytest
from sqlalchemy import select

from app.database.models import init_db, EventModel, AlertModel, IncidentModel
from app.database.session import AsyncSessionLocal


@pytest.mark.asyncio
async def test_database_crud_operations():
    # Initialize DB (creates SQLite tables in memory or locally)
    await init_db()

    async with AsyncSessionLocal() as session:
        # 1. Insert Event
        test_event = EventModel(
            event_id="db-ev-test-1",
            timestamp=datetime.now(timezone.utc),
            event_type="PROCESS_CREATED",
            source="test-source",
            host="HOST-DB-TEST",
            user="db-test-user",
            message="Test DB Event",
            metadata_json={"key": "val"},
        )
        session.add(test_event)

        # 2. Insert Alert
        test_alert = AlertModel(
            alert_id="db-al-test-1",
            rule_id="RULE-001",
            rule_name="Brute Force",
            matched=True,
            confidence=0.85,
            risk_contribution=25,
            timestamp=datetime.now(timezone.utc),
            host="HOST-DB-TEST",
            message="Test DB Alert",
            evidence={"ip": "127.0.0.1"},
        )
        session.add(test_alert)

        # 3. Insert Incident
        test_incident = IncidentModel(
            incident_id="db-inc-test-1",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            severity="HIGH",
            risk_score=75,
            status="OPEN",
            host="HOST-DB-TEST",
            user="db-test-user",
            source_ips=["127.0.0.1"],
            related_event_ids=["db-ev-test-1"],
            related_alerts=[{"alert_id": "db-al-test-1"}],
            attack_techniques=[{"technique_id": "T1110"}],
            evidence=["Brute force detected"],
            recommendations=["Reset password"],
            attack_graph={"nodes": [], "edges": []},
            ai_summary="Test AI summary",
        )
        session.add(test_incident)

        await session.commit()

    # Query back using select
    async with AsyncSessionLocal() as session:
        stmt_ev = select(EventModel).where(EventModel.event_id == "db-ev-test-1")
        res_ev = await session.execute(stmt_ev)
        queried_ev = res_ev.scalar_one()
        assert queried_ev.host == "HOST-DB-TEST"
        assert queried_ev.metadata_json["key"] == "val"

        stmt_al = select(AlertModel).where(AlertModel.alert_id == "db-al-test-1")
        res_al = await session.execute(stmt_al)
        queried_al = res_al.scalar_one()
        assert queried_al.risk_contribution == 25
        assert queried_al.evidence["ip"] == "127.0.0.1"

        stmt_inc = select(IncidentModel).where(IncidentModel.incident_id == "db-inc-test-1")
        res_inc = await session.execute(stmt_inc)
        queried_inc = res_inc.scalar_one()
        assert queried_inc.risk_score == 75
        assert queried_inc.related_event_ids == ["db-ev-test-1"]
        assert queried_inc.related_alerts == [{"alert_id": "db-al-test-1"}]
        assert queried_inc.ai_summary == "Test AI summary"
