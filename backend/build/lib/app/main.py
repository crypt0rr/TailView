from __future__ import annotations

import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from sqlalchemy import text

from .api import router
from .config import get_settings
from .db import SessionLocal, engine
from .demo import seed_demo
from .sync import create_scheduler

log = structlog.get_logger()
REQUESTS = Counter("tailview_http_requests_total", "HTTP requests", ["method", "status"])
DURATION = Histogram("tailview_http_request_duration_seconds", "HTTP request duration", ["method"])


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    if settings.production and settings.setup_token == "change-me-before-starting":  # noqa: S105
        raise RuntimeError("Set a strong TAILVIEW_SETUP_TOKEN before production startup")
    async with engine.begin() as connection:
        await connection.run_sync(
            __import__("app.models", fromlist=["Base"]).Base.metadata.create_all
        )
    if settings.demo_mode:
        async with SessionLocal() as session:
            await seed_demo(session)
    scheduler = create_scheduler()
    if not settings.demo_mode:
        scheduler.start()
    yield
    if scheduler.running:
        scheduler.shutdown(wait=False)
    await engine.dispose()


app = FastAPI(
    title="TailView API", version="1.0.0", lifespan=lifespan, docs_url="/api/docs", redoc_url=None
)
settings = get_settings()
if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Content-Type", "X-CSRF-Token", "X-Correlation-ID"],
    )


@app.middleware("http")
async def request_context(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    correlation_id = request.headers.get("x-correlation-id", str(uuid.uuid4()))[:128]
    started = time.monotonic()
    try:
        response = await call_next(request)
    except Exception as exc:
        log.exception(
            "request_failed",
            correlation_id=correlation_id,
            path=request.url.path,
            error_type=type(exc).__name__,
        )
        response = JSONResponse(
            status_code=500,
            content={
                "code": "internal_error",
                "message": "An internal error occurred",
                "correlationId": correlation_id,
            },
        )
    response.headers.update(
        {
            "X-Correlation-ID": correlation_id,
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Content-Security-Policy": (
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
            ),
        }
    )
    REQUESTS.labels(request.method, str(response.status_code)).inc()
    DURATION.labels(request.method).observe(time.monotonic() - started)
    return response


@app.get("/health/live")
async def live() -> dict[str, str]:
    return {"status": "live"}


@app.get("/health/ready")
async def ready() -> dict[str, str]:
    async with engine.connect() as connection:
        await connection.execute(text("SELECT 1"))
    return {"status": "ready"}


@app.get("/metrics", include_in_schema=False)
async def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


app.include_router(router)
