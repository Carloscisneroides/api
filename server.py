#!/usr/bin/env python3
"""
BRT Italia - Tracking API Server (Production-ready)
=====================================================
Inicio:
    python3 server.py
    # Con múltiples workers (producción real):
    gunicorn server:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000

Endpoints:
    GET /track/{parcel_number}    → estado del envío (JSON)
    GET /health                   → estado del servidor
    GET /docs                     → Swagger UI
"""

import logging
import os
import re
import time
from functools import lru_cache
from typing import List, Optional

import requests
from bs4 import BeautifulSoup
from cachetools import TTLCache
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# ──────────────────────────────────────────────────────────────────────────────
# CONFIG (via variables de entorno o valores por defecto)
# ──────────────────────────────────────────────────────────────────────────────
API_KEY        = os.getenv("API_KEY", "")              # "" = sin autenticación
CACHE_TTL_SEC  = int(os.getenv("CACHE_TTL", "300"))    # 5 minutos por defecto
RATE_LIMIT     = os.getenv("RATE_LIMIT", "30/minute")  # max 30 req/min por IP
REQUEST_TIMEOUT = int(os.getenv("BRT_TIMEOUT", "25"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("brt-api")

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
)

BRT_STATES = [
    "Spedizione consegnata a BRT",
    "In viaggio",
    "In filiale",
    "Spedizione in consegna",
    "Consegnato",
    "In attesa di ritiro",
    "Tentativo di consegna",
    "Spedizione affidata",
    "Spedizione in giacenza",
]

# ──────────────────────────────────────────────────────────────────────────────
# CACHÉ EN MEMORIA  (TTLCache: expira automáticamente)
# ──────────────────────────────────────────────────────────────────────────────
# maxsize=500 → máximo 500 paquetes en caché simultáneamente
_cache: TTLCache = TTLCache(maxsize=500, ttl=CACHE_TTL_SEC)


# ──────────────────────────────────────────────────────────────────────────────
# MODELOS
# ──────────────────────────────────────────────────────────────────────────────
class TrackingEvent(BaseModel):
    date: str
    status: str
    location: str = ""


class TrackingResponse(BaseModel):
    success: bool = True
    parcel_number: str
    current_status: str
    current_date: str
    events: List[TrackingEvent]
    elapsed_ms: int
    cached: bool = False
    source: str = "mybrt.it"


# ──────────────────────────────────────────────────────────────────────────────
# SCRAPING
# ──────────────────────────────────────────────────────────────────────────────
def _fetch_brt(parcel_number: str) -> dict:
    """Hace la consulta a mybrt.it con reintentos automáticos."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
        "DNT": "1",
    })

    url = (
        f"https://www.mybrt.it/it/mybrt/my-parcels/search"
        f"?lang=it&parcelNumber={parcel_number}"
    )

    last_error = None
    for attempt in range(1, 4):  # 3 intentos
        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            if resp.status_code == 200 and len(resp.text) > 5000:
                return _parse_html(resp.text, parcel_number)
            logger.warning(
                f"Intento {attempt}: HTTP {resp.status_code}, {len(resp.text)} chars"
            )
        except requests.Timeout:
            last_error = "Timeout conectando a mybrt.it"
            logger.warning(f"Intento {attempt}: Timeout")
        except requests.RequestException as exc:
            last_error = str(exc)
            logger.warning(f"Intento {attempt}: {exc}")

        if attempt < 3:
            time.sleep(attempt * 1.5)  # backoff: 1.5s, 3s

    raise RuntimeError(last_error or "mybrt.it no respondió correctamente")


def _parse_html(html: str, parcel_number: str) -> dict:
    """Extrae datos de tracking del HTML renderizado por mybrt.it."""
    soup = BeautifulSoup(html, "html.parser")

    # CSRF token
    csrf = None
    csrf_meta = soup.find("meta", attrs={"name": "_csrf"})
    if csrf_meta:
        csrf = csrf_meta.get("content")

    # Parsear texto plano para extraer estados y fechas
    plain_text = soup.get_text(separator="\n")
    lines = [l.strip() for l in plain_text.split("\n") if l.strip()]
    date_re = re.compile(r"\d{2}-\d{2}-\d{4}")

    events = []
    current_status = "Sconosciuto"
    current_date = ""
    in_section = False

    for i, line in enumerate(lines):
        if parcel_number in line:
            in_section = True
        if not in_section:
            continue
        for state in BRT_STATES:
            if state.lower() in line.lower():
                date = ""
                for j in range(max(0, i - 2), min(len(lines), i + 3)):
                    dm = date_re.search(lines[j])
                    if dm:
                        date = dm.group(0)
                        break
                if not any(e["status"] == state and e["date"] == date for e in events):
                    events.append({"date": date, "status": state, "location": ""})
                current_status = state
                current_date = date

    # Detectar si el paquete realmente tiene datos o la página está vacía
    not_found_signals = [
        "non è ancora associata",
        "spedizione non trovata",
        "nessun risultato",
    ]
    if any(s in plain_text.lower() for s in not_found_signals) and not events:
        raise ValueError(f"Paquete {parcel_number} no encontrado en mybrt.it")

    return {
        "parcel_number": parcel_number,
        "current_status": current_status,
        "current_date": current_date,
        "events": events,
        "csrf_token": csrf,
    }


# ──────────────────────────────────────────────────────────────────────────────
# APP FASTAPI
# ──────────────────────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=[RATE_LIMIT])

app = FastAPI(
    title="BRT Italia Tracking API",
    description="Tracking de envíos BRT Italia via mybrt.it",
    version="2.0.0",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


# ── Dependencia: verificar API key (opcional) ─────────────────────────────────
def verify_api_key(x_api_key: Optional[str] = Header(default=None)):
    if not API_KEY:
        return  # Sin API_KEY configurada → acceso libre
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="API key inválida o faltante")


# ── Endpoints ─────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "status": "ok",
        "cache_size": len(_cache),
        "cache_ttl_seconds": CACHE_TTL_SEC,
        "rate_limit": RATE_LIMIT,
        "auth_required": bool(API_KEY),
    }


@app.get(
    "/track/{parcel_number}",
    response_model=TrackingResponse,
    summary="Consultar estado de un envío BRT",
)
@limiter.limit(RATE_LIMIT)
def track(
    request: Request,
    parcel_number: str,
    _: None = Depends(verify_api_key),
):
    """
    Devuelve el estado actual e historial de un envío BRT Italia.

    - Caché automática de **{CACHE_TTL} minutos** por número de paquete.
    - Máximo **{RATE_LIMIT}** por IP.
    - Incluir header `X-API-Key` si el servidor tiene autenticación activada.
    """
    # Validar formato
    if not re.match(r"^\d{12}$|^\d{14}$|^\d{15}$|^\d{19}$", parcel_number):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Número inválido: '{parcel_number}'. "
                "Debe tener 12, 14, 15 o 19 dígitos."
            ),
        )

    # Revisar caché primero
    if parcel_number in _cache:
        cached = dict(_cache[parcel_number])
        cached["cached"] = True
        cached["elapsed_ms"] = 0
        logger.info(f"CACHE HIT: {parcel_number}")
        return TrackingResponse(**cached)

    # Consultar BRT
    t0 = time.time()
    logger.info(f"FETCH: {parcel_number}")

    try:
        data = _fetch_brt(parcel_number)
    except ValueError as exc:
        # Paquete no encontrado
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.error(f"ERROR {parcel_number}: {exc}")
        raise HTTPException(
            status_code=503,
            detail=f"Error consultando mybrt.it: {str(exc)}",
        )

    elapsed = int((time.time() - t0) * 1000)

    result = {
        "success": True,
        "parcel_number": data["parcel_number"],
        "current_status": data["current_status"],
        "current_date": data["current_date"],
        "events": data["events"],
        "elapsed_ms": elapsed,
        "cached": False,
        "source": "mybrt.it",
    }

    # Guardar en caché (solo si hay datos)
    if data["events"]:
        _cache[parcel_number] = result
        logger.info(
            f"OK {parcel_number} → {data['current_status']} "
            f"({elapsed}ms, guardado en caché {CACHE_TTL_SEC}s)"
        )

    return TrackingResponse(**result)


@app.get("/", include_in_schema=False)
def root():
    return {
        "service": "BRT Italia Tracking API v2",
        "docs": "/docs",
        "health": "/health",
        "example": "/track/08454094584657",
    }


# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        workers=1,          # para producción real: usa gunicorn
        access_log=True,
    )
