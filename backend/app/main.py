"""
Predictive Cyber Defence - FastAPI Application Entry Point
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, REGISTRY, generate_latest
from sqlalchemy import text

from app.core.config import settings
from app.core.database import engine, init_db, close_db
from app.core.redis import redis_manager
from app.core.logging import configure_logging, get_logger
from app.api.v1.router import api_router
from app.ws.manager import ws_manager
from app.services.network_discovery import discovery_service
from app.core.security import decode_token


logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    configure_logging(log_level=settings.LOG_LEVEL, json_logs=not settings.DEBUG)
    logger.info("Starting Predictive Cyber Defence API")
    
    await init_db()
    logger.info("Database initialized")
    
    await redis_manager.initialize()
    logger.info("Redis connected")
    
    # Start WebSocket manager
    await ws_manager.start()
    logger.info("WebSocket manager started")

    # Start network device discovery (auto-register devices as they join)
    await discovery_service.start()

    yield
    
    # Shutdown
    logger.info("Shutting down...")
    await discovery_service.stop()
    await ws_manager.stop()
    await redis_manager.close()
    await close_db()
    logger.info("Shutdown complete")


def create_app() -> FastAPI:
    """Create FastAPI application."""
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        debug=settings.DEBUG,
        openapi_url=f"{settings.API_V1_PREFIX}/openapi.json",
        docs_url=f"{settings.API_V1_PREFIX}/docs",
        redoc_url=f"{settings.API_V1_PREFIX}/redoc",
        lifespan=lifespan,
    )
    
    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # API routes
    app.include_router(api_router, prefix=settings.API_V1_PREFIX)

    @app.middleware("http")
    async def require_admin_for_mutations(request: Request, call_next):
        """Guests are strictly read-only; an authenticated administrator may act."""
        protected = request.url.path.startswith(settings.API_V1_PREFIX)
        auth_path = request.url.path.startswith(f"{settings.API_V1_PREFIX}/auth/")
        mutating = request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}
        if protected and mutating and not auth_path:
            header = request.headers.get("authorization", "")
            token = header.removeprefix("Bearer ").strip() if header.startswith("Bearer ") else ""
            payload = decode_token(token) if token else None
            if not payload or payload.get("type") != "access":
                return JSONResponse(status_code=401, content={"detail": "Not authenticated"}, headers={"WWW-Authenticate": "Bearer"})
            if "admin" not in payload.get("roles", []):
                return JSONResponse(status_code=403, content={"detail": "Guest sessions are view-only"})
        return await call_next(request)
    
    # Health checks
    @app.get("/health")
    @app.get("/health/live")
    async def liveness():
        return {"status": "alive"}
    
    @app.get("/health/ready")
    async def readiness():
        checks = {"database": "error", "redis": "error"}
        try:
            async with engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
            checks["database"] = "ok"
        except Exception:
            logger.exception("Readiness database check failed")
        try:
            await redis_manager.client.ping()
            checks["redis"] = "ok"
        except Exception:
            logger.exception("Readiness Redis check failed")
        if all(value == "ok" for value in checks.values()):
            return {"status": "ready", "checks": checks}
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail={"status": "not_ready", "checks": checks})

    @app.get("/metrics")
    async def metrics():
        """Prometheus scrape endpoint."""
        return Response(content=generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)
    
    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
    )
