from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from app.core.config import settings

# Async Engine configuration for SQLite
engine = create_async_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False},  # Required for SQLite multithreaded access
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db():
    """
    Dependency generator for FastAPI routes to inject async database sessions.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
