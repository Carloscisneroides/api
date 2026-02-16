#!/usr/bin/env python3
"""
BRT Italia - Cliente de Tracking
=================================
Flujo real descubierto mediante ingeniería inversa del portal:

  1. services.brt.it/it/process-code?CD=NUMERO
     → Angular SPA que redirige automáticamente a mybrt.it

  2. www.mybrt.it/it/mybrt/my-parcels/incoming?parcelNumber=NUMERO
     → Servidor Spring/Java que renderiza el HTML con los datos
       del tracking incrustados en la variable JS `GEOCCP_PARCELS`
       y también en el propio DOM de la página.

  3. El CSRF token está en <meta name='_csrf' content='TOKEN'>
     y se usa para llamadas AJAX secundarias (notificaciones, etc.)

Instalación:
    pip install playwright requests beautifulsoup4
    playwright install chromium

Uso:
    python brt.py 08454094584657
    python brt.py 08454094584657 --visible   # Abre navegador visible
    python brt.py 08454094584657 --json       # Salida JSON pura
    python brt.py 08454094584657 --fast       # HTTP directo (sin browser)
"""

import asyncio
import json
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import requests
from bs4 import BeautifulSoup
from playwright.async_api import Page, async_playwright

# ──────────────────────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("brt")

# ──────────────────────────────────────────────────────────────────────────────
# CONSTANTES
# ──────────────────────────────────────────────────────────────────────────────
# Punto de entrada: la URL que usa el widget de la home de brt.it
ENTRY_URL = "https://services.brt.it/it/process-code?CD={parcel}"

# Destino final tras las redirecciones (también accesible directamente)
MYBRT_URL = "https://www.mybrt.it/it/mybrt/my-parcels/incoming?parcelNumber={parcel}"

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/121.0.0.0 Safari/537.36"
)

# ──────────────────────────────────────────────────────────────────────────────
# MODELOS DE DATOS
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class TrackingEvent:
    date: str = ""
    status: str = ""
    location: str = ""


@dataclass
class TrackingResult:
    parcel_number: str = ""
    current_status: str = "Desconocido"
    current_date: str = ""
    events: List[TrackingEvent] = field(default_factory=list)
    csrf_token: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    raw_geoccp: Optional[Dict] = None  # Variable JS GEOCCP_PARCELS si está disponible


# ──────────────────────────────────────────────────────────────────────────────
# PARSER DEL HTML DE mybrt.it
# ──────────────────────────────────────────────────────────────────────────────
def parse_mybrt_html(html: str, parcel_number: str) -> TrackingResult:
    """
    Extrae los datos de tracking del HTML renderizado por mybrt.it.

    Estrategia:
      1. Intentar extraer la variable JS `GEOCCP_PARCELS` (más estructurada).
      2. Si falla, parsear el DOM con BeautifulSoup.
    """
    result = TrackingResult(parcel_number=parcel_number)
    soup = BeautifulSoup(html, "html.parser")

    # ── 1. Token CSRF ──────────────────────────────────────────────────────────
    csrf_meta = soup.find("meta", attrs={"name": "_csrf"})
    if csrf_meta:
        result.csrf_token = csrf_meta.get("content")
        logger.info(f"CSRF token: {result.csrf_token[:20]}…")

    # ── 2. Variable JS GEOCCP_PARCELS (más fiable, datos estructurados) ────────
    for script in soup.find_all("script"):
        text = script.string or ""
        if "GEOCCP_PARCELS" in text:
            match = re.search(r"var\s+GEOCCP_PARCELS\s*=\s*(\{.*?\});", text, re.DOTALL)
            if match:
                try:
                    geoccp = json.loads(match.group(1))
                    result.raw_geoccp = geoccp
                    logger.info("Variable GEOCCP_PARCELS extraída del HTML")
                except json.JSONDecodeError:
                    pass
            break

    # ── 3. Parsear DOM ─────────────────────────────────────────────────────────
    # Estado actual (aparece como "Spedizione in consegna" con fecha)
    status_el = soup.select_one(".parcelStatus, .parcel-status, .status-label, .trackStatus")
    if status_el:
        result.current_status = status_el.get_text(strip=True)

    # El estado actual lo extraemos del fallback de texto (más limpio)

    # Historial de eventos - buscar elementos de timeline/tracking
    # mybrt.it usa clases como: .trackingDetail, .event, .parcelEvent, .timeline-item
    event_selectors = [
        ".trackingDetail",
        ".parcelEvent",
        ".timeline-item",
        ".tracking-event",
        "[class*='tracking']",
        "[class*='event']",
        "[class*='history']",
    ]

    events_found = []
    for sel in event_selectors:
        items = soup.select(sel)
        if items:
            for item in items:
                text = item.get_text(separator=" | ", strip=True)
                if text and len(text) > 5:
                    # Intentar extraer fecha (formato dd-mm-yyyy o dd/mm/yyyy)
                    date_match = re.search(r"\d{2}[-/]\d{2}[-/]\d{4}", text)
                    date = date_match.group(0) if date_match else ""
                    events_found.append(TrackingEvent(date=date, status=text[:150]))
            if events_found:
                break

    result.events = events_found

    # ── 4. Fallback: extraer texto libre de la página ─────────────────────────
    if not result.current_status or result.current_status == "Desconocido":
        # Buscar en el texto completo de la página
        full_text = soup.get_text(separator="\n")
        # Patrones de estado típicos de BRT en italiano
        status_patterns = [
            r"Spedizione[^\n]+",
            r"In viaggio[^\n]*",
            r"In filiale[^\n]*",
            r"Consegnato[^\n]*",
            r"In consegna[^\n]*",
        ]
        for pat in status_patterns:
            m = re.search(pat, full_text, re.IGNORECASE)
            if m:
                result.current_status = m.group(0).strip()
                break

    return result


# ──────────────────────────────────────────────────────────────────────────────
# CLIENTE PLAYWRIGHT (NAVEGADOR)
# ──────────────────────────────────────────────────────────────────────────────
class BRTTrackerBrowser:
    """
    Rastrea un envío usando Playwright.
    Navega a services.brt.it y sigue las redirecciones hasta mybrt.it.
    Extrae el HTML renderizado y parsea los datos.
    """

    def __init__(self, headless: bool = True):
        self.headless = headless

    async def track(self, parcel_number: str) -> Optional[TrackingResult]:
        url = ENTRY_URL.format(parcel=parcel_number)
        logger.info(f"Iniciando tracking: {parcel_number}")
        logger.info(f"URL entrada: {url}")

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=self.headless,
                args=["--disable-blink-features=AutomationControlled", "--no-sandbox"],
            )
            context = await browser.new_context(
                user_agent=USER_AGENT,
                viewport={"width": 1366, "height": 768},
                locale="it-IT",
                timezone_id="Europe/Rome",
                extra_http_headers={
                    "Accept-Language": "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
                },
            )

            # Ocultar navigator.webdriver
            await context.add_init_script(
                "Object.defineProperty(navigator,'webdriver',{get:()=>undefined})"
            )

            page = await context.new_page()

            try:
                # Navegar y seguir redirecciones automáticamente
                await page.goto(url, wait_until="networkidle", timeout=45_000)
                await asyncio.sleep(2)

                final_url = page.url
                logger.info(f"URL final: {final_url}")

                # Extraer el HTML completo de la página
                html = await page.content()

                # Extraer cookies para posible uso posterior
                raw_cookies = await context.cookies()
                cookies = {c["name"]: c["value"] for c in raw_cookies}
                logger.info(f"Cookies: {list(cookies.keys())}")

                # Parsear el HTML
                result = parse_mybrt_html(html, parcel_number)
                result.cookies = cookies

                # Si el DOM no tiene eventos estructurados, extraer del texto visible
                if not result.events:
                    body_text = await page.inner_text("body")
                    result = _parse_text_fallback(body_text, parcel_number, result)

                return result

            except Exception as exc:
                logger.error(f"Error: {exc}")
                raise
            finally:
                await browser.close()


# ──────────────────────────────────────────────────────────────────────────────
# CLIENTE HTTP DIRECTO (SIN NAVEGADOR)
# ──────────────────────────────────────────────────────────────────────────────
class BRTTrackerDirect:
    """
    Consulta directa con requests (sin browser).
    Sigue las redirecciones de services.brt.it → mybrt.it.

    NOTA: Este método puede fallar si mybrt.it detecta que no es un browser
    real. En ese caso usa BRTTrackerBrowser.
    """

    def track(self, parcel_number: str) -> Optional[TrackingResult]:
        """
        Flujo HTTP completo (sin browser):
          1. GET mybrt.it/search?parcelNumber=X
          2. 302 → oauth2/authorization/consignee-sso?prompt=none
          3. 302 → login.dpdgroup.com (SSO, prompt=none devuelve login_required)
          4. 302 → mybrt.it/sso/login?error=login_required  ← crea ConsigneeSSOAuthentication
          5. 302 → mybrt.it/search  → 302 → mybrt.it/incoming?parcelNumber=X
          6. 200 con HTML completo del tracking

        requests sigue todas las redirecciones automáticamente,
        incluyendo el SSO. La sesión queda con JSESSIONID + ConsigneeSSOAuthentication.
        """
        session = requests.Session()
        session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;"
                    "q=0.9,image/avif,image/webp,*/*;q=0.8"
                ),
                "Accept-Language": "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
                "Accept-Encoding": "gzip, deflate, br",
                "DNT": "1",
                "Upgrade-Insecure-Requests": "1",
            }
        )

        # URL de entrada al flujo SSO (no la URL directa /incoming que devuelve página vacía)
        url = f"https://www.mybrt.it/it/mybrt/my-parcels/search?lang=it&parcelNumber={parcel_number}"
        logger.info(f"[Direct] Iniciando flujo OAuth2: {url}")

        try:
            resp = session.get(url, timeout=25, allow_redirects=True)
            logger.info(
                f"[Direct] Status: {resp.status_code} | "
                f"URL final: {resp.url} | "
                f"Tamaño: {len(resp.text)} chars | "
                f"Cookies: {list(session.cookies.keys())}"
            )

            if resp.status_code == 200 and len(resp.text) > 5000:
                result = parse_mybrt_html(resp.text, parcel_number)
                result.cookies = dict(session.cookies)
                # Parsear texto plano también (extrae estado y eventos limpios)
                from bs4 import BeautifulSoup as _BS
                plain_text = _BS(resp.text, "html.parser").get_text(separator="\n")
                result = _parse_text_fallback(plain_text, parcel_number, result)
                return result
            else:
                logger.warning(f"[Direct] Respuesta inesperada ({resp.status_code}, {len(resp.text)} chars)")

        except Exception as exc:
            logger.error(f"[Direct] Error: {exc}")

        return None


# ──────────────────────────────────────────────────────────────────────────────
# PARSER DE TEXTO PLANO (FALLBACK)
# ──────────────────────────────────────────────────────────────────────────────
def _parse_text_fallback(
    text: str, parcel_number: str, result: TrackingResult
) -> TrackingResult:
    """
    Extrae datos de tracking del texto visible de la página.
    mybrt.it muestra el historial como líneas con:
      <estado>  <fecha dd-mm-yyyy>
    """
    lines = [l.strip() for l in text.split("\n") if l.strip()]

    # Estados conocidos de BRT Italia
    brt_states = [
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

    date_pattern = re.compile(r"\d{2}-\d{2}-\d{4}")
    events = []
    current_status = result.current_status
    current_date = ""

    # Buscar la sección del paquete específico
    in_parcel_section = False
    for i, line in enumerate(lines):
        if parcel_number in line:
            in_parcel_section = True
        if not in_parcel_section:
            continue

        # Detectar estado
        for state in brt_states:
            if state.lower() in line.lower():
                # Buscar fecha en líneas cercanas
                date = ""
                for j in range(max(0, i - 2), min(len(lines), i + 3)):
                    dm = date_pattern.search(lines[j])
                    if dm:
                        date = dm.group(0)
                        break

                events.append(TrackingEvent(date=date, status=state))

                # El último estado encontrado por fecha = estado actual
                current_status = state
                current_date = date

    # Si no encontramos nada con estados conocidos, buscar líneas con fecha
    if not events:
        for i, line in enumerate(lines):
            dm = date_pattern.search(line)
            if dm and len(line) > 5:
                date = dm.group(0)
                status = line.replace(date, "").strip()
                if status:
                    events.append(TrackingEvent(date=date, status=status))

    # El estado más reciente (último evento del historial)
    if events and (not current_status or current_status == "Desconocido"):
        current_status = events[-1].status
        current_date = events[-1].date

    result.events = events
    result.current_status = current_status
    result.current_date = current_date
    return result


# ──────────────────────────────────────────────────────────────────────────────
# FORMATEO DE SALIDA
# ──────────────────────────────────────────────────────────────────────────────
def format_result(result: TrackingResult) -> str:
    lines = [
        f"\n{'═' * 58}",
        f"  BRT ITALIA — TRACKING",
        f"{'═' * 58}",
        f"  Paquete:   {result.parcel_number}",
        f"  Estado:    {result.current_status}",
    ]
    if result.current_date:
        lines.append(f"  Fecha:     {result.current_date}")

    if result.events:
        lines += [f"\n  HISTORIAL:", f"  {'─' * 50}"]
        seen = set()
        for ev in result.events:
            key = (ev.date, ev.status)
            if key in seen:
                continue
            seen.add(key)
            ts = ev.date or "?"
            lines.append(f"  [{ts}]  {ev.status}")
            if ev.location:
                lines.append(f"           {ev.location}")

    lines.append(f"{'═' * 58}\n")
    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# PUNTO DE ENTRADA
# ──────────────────────────────────────────────────────────────────────────────
async def main():
    args = sys.argv[1:]
    headless = "--visible" not in args
    output_json = "--json" in args
    fast_mode = "--fast" in args
    numbers = [a for a in args if not a.startswith("--")]

    if not numbers:
        print("Uso: python brt.py <numero_seguimiento> [--visible] [--json] [--fast]")
        print("Ej:  python brt.py 08454094584657")
        print("     python brt.py 08454094584657 --fast  (sin browser, más rápido)")
        sys.exit(1)

    parcel = numbers[0]
    result = None

    if fast_mode:
        logger.info("Modo fast: HTTP directo (sin browser)")
        direct = BRTTrackerDirect()
        result = direct.track(parcel)
        if not result:
            logger.warning("HTTP directo falló, intentando con browser...")
            fast_mode = False

    if not fast_mode:
        tracker = BRTTrackerBrowser(headless=headless)
        result = await tracker.track(parcel)

    if not result:
        print("[ERROR] No se pudo obtener información de tracking.")
        print("Sugerencias:")
        print("  - Ejecuta con --visible para depurar visualmente")
        print("  - Verifica que el número de paquete sea válido (12, 14, 15 o 19 dígitos)")
        sys.exit(1)

    # Salida
    if output_json:
        out = {
            "parcel_number": result.parcel_number,
            "current_status": result.current_status,
            "current_date": result.current_date,
            "events": [{"date": e.date, "status": e.status, "location": e.location}
                       for e in result.events],
            "csrf_token": result.csrf_token,
            "cookies": list(result.cookies.keys()),
            "geoccp_parcels": result.raw_geoccp,
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print(format_result(result))

    # Info de sesión siempre útil
    print(f"  CSRF Token: {result.csrf_token or 'No encontrado'}")
    print(f"  Cookies:    {list(result.cookies.keys())}")


if __name__ == "__main__":
    asyncio.run(main())
