"""Main FastAPI application for OMCP ONION Control Panel."""

from pathlib import Path
from typing import Dict

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from panel.config import BASE_DIR, UPLOAD_DIR, settings
from panel.database import init_db
from panel.routers import admin, auth, client

FRONTEND_DIR = BASE_DIR / "frontend"

app = FastAPI(
    title="OMCP ONION — Game Server Hosting Control Panel",
    version=settings.VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


app.include_router(auth.router)
app.include_router(client.router)
app.include_router(admin.router)


@app.get("/api/health")
def health_check() -> Dict[str, str]:
    return {"status": "ok", "app": settings.APP_NAME, "version": settings.VERSION}


if UPLOAD_DIR.exists():
    app.mount("/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")

if (FRONTEND_DIR / "assets").exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND_DIR / "assets")), name="assets")


@app.get("/{full_path:path}")
def serve_spa(full_path: str):
    if full_path.startswith("api/"):
        return JSONResponse(status_code=404, content={"detail": "API endpoint not found."})
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return JSONResponse({"app": settings.APP_NAME, "version": settings.VERSION, "docs": "/api/docs"})


if __name__ == "__main__":
    import os
    import uvicorn

    init_db()
    host = os.environ.get("ONION_HOST", "0.0.0.0")
    port = int(os.environ.get("ONION_PORT", "8080"))
    uvicorn.run(app, host=host, port=port)
