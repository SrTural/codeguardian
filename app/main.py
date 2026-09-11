"""
CodeGuardian - Local AI-Powered Code Security Scanner
=====================================================
Production-grade FastAPI application entry point.

Features:
- Zero data exfiltration (100% local)
- AI-powered vulnerability detection (Ollama + Qwen)
- Multi-file format support (Python, JS, TS, Java, Go)
- Structured logging and error handling
- CORS-ready for future frontend integration
- Health checks for monitoring
"""

from contextlib import asynccontextmanager
from typing import Optional

import logging
import time
from datetime import datetime, timezone

from fastapi import FastAPI, UploadFile, File, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from app.core.config import settings
from app.scanners.code_scanner import CodeScanner


# ==============================================================
# LOGGING CONFIGURATION
# ==============================================================

logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(settings.APP_NAME)


# ==============================================================
# LIFESPAN (Startup / Shutdown)
# ==============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    logger.info("=" * 60)
    logger.info(f"  {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"  Environment: {settings.APP_ENV}")
    logger.info(f"  Model: {settings.MODEL_NAME}")
    logger.info(f"  Ollama: {settings.OLLAMA_URL}")
    logger.info("=" * 60)
    yield
    logger.info(f"{settings.APP_NAME} shutting down...")


# ==============================================================
# APP INITIALIZATION
# ==============================================================

app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "Local-first, AI-powered code security scanner. "
        "Zero data exfiltration. GDPR-compliant by design."
    ),
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Scanner singleton
scanner = CodeScanner()


# ==============================================================
# REQUEST TIMING MIDDLEWARE
# ==============================================================

@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """Add X-Process-Time header to every response."""
    start_time = time.perf_counter()
    response = await call_next(request)
    process_time = time.perf_counter() - start_time
    response.headers["X-Process-Time"] = f"{process_time:.4f}"
    return response


# ==============================================================
# EXCEPTION HANDLERS
# ==============================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions."""
    logger.warning(f"HTTP {exc.status_code}: {exc.detail} | {request.url.path}")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "status_code": exc.status_code,
            "detail": exc.detail,
            "path": str(request.url.path),
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors."""
    logger.warning(f"Validation error: {exc.errors()}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": True,
            "status_code": 422,
            "detail": "Validation failed",
            "errors": exc.errors(),
        },
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions."""
    logger.error(f"Unexpected error: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": True,
            "status_code": 500,
            "detail": "Internal server error",
        },
    )


# ==============================================================
# HEALTH & INFO ENDPOINTS
# ==============================================================

@app.get("/", tags=["Health"], summary="Root endpoint")
def root():
    """Health check endpoint."""
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health", tags=["Health"], summary="Health check")
def health():
    """Detailed health check."""
    return {
        "status": "healthy",
        "model": settings.MODEL_NAME,
        "ollama": settings.OLLAMA_URL,
        "environment": settings.APP_ENV,
        "debug": settings.DEBUG,
    }


@app.get("/info", tags=["Health"], summary="Application info")
def info():
    """Return application metadata."""
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.APP_ENV,
        "features": [
            "Local AI scanning",
            "Zero data exfiltration",
            "Multi-format support",
            "OWASP Top 10 detection",
        ],
        "allowed_extensions": settings.ALLOWED_EXTENSIONS,
        "max_file_size_mb": settings.MAX_FILE_SIZE_MB,
    }


# ==============================================================
# SCANNER ENDPOINTS
# ==============================================================

@app.post(
    "/scan",
    tags=["Scanner"],
    summary="Scan code for vulnerabilities",
    description="Upload a code file to scan for security vulnerabilities.",
)
async def scan_code(file: UploadFile = File(...)):
    """
    Scan an uploaded code file for security vulnerabilities.

    - Validates file extension
    - Reads and validates content
    - Runs AST + LLM analysis
    - Returns structured findings
    """
    # --- Validate filename ---
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename is missing",
        )

    # --- Validate extension ---
    if not any(file.filename.endswith(ext) for ext in settings.ALLOWED_EXTENSIONS):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file type. Allowed: {', '.join(settings.ALLOWED_EXTENSIONS)}",
        )

    # --- Read content ---
    try:
        content = await file.read()
        code = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be UTF-8 encoded",
        )

    # --- Validate content ---
    if not code.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File is empty",
        )

    # --- Validate size ---
    size_mb = len(content) / (1024 * 1024)
    if size_mb > settings.MAX_FILE_SIZE_MB:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large. Max: {settings.MAX_FILE_SIZE_MB} MB",
        )

    logger.info(f"Scanning: {file.filename} | {len(code)} bytes | {size_mb:.2f} MB")

    # --- Run scan ---
    start = time.perf_counter()
    try:
        result = scanner.scan(code)
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed: {str(e)}",
        )
    duration = time.perf_counter() - start

    logger.info(
        f"Scan complete: {file.filename} | "
        f"{result.get('total', 0)} issues | {duration:.2f}s"
    )

    # --- Return response ---
    return JSONResponse(
        content={
            "file": file.filename,
            "size_bytes": len(code),
            "size_mb": round(size_mb, 3),
            "scan_duration_seconds": round(duration, 3),
            "result": result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


# ==============================================================
# ENTRY POINT
# ==============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.is_debug,
        log_level=settings.LOG_LEVEL.lower(),
    )