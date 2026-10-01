"""
Suite de pruebas automatizadas - Sprint 2 - Grupo 5 (OWASP ZAP + Juice Shop)
=============================================================================
Sistema bajo prueba (SUT): OWASP Juice Shop en http://localhost:3000 (Docker, entorno propio y autorizado).
Herramienta: OWASP ZAP controlado por su API REST (modo daemon, puerto 8080).

Como funciona cada test:
  * Un test PASA si el sistema cumple el criterio de aceptacion definido en el documento de diseno.
  * Un test FALLA si el sistema NO cumple el criterio. Contra Juice Shop (app vulnerable a proposito)
    es esperable que varios tests de seguridad fallen: eso demuestra que la suite detecta problemas.
    El resultado real se registra tal cual aparece, sin modificarlo.

Variables de entorno (todas opcionales):
  TARGET_URL     (defecto http://localhost:3000)
  ZAP_API        (defecto http://localhost:8080)
  ZAP_API_KEY    (defecto vacio; usar la misma clave con la que se inicio ZAP)
  MIN_URLS       (defecto 5)  umbral de cobertura del spider (TC-02)
  USE_AJAX       (defecto 1)  usar tambien el Ajax Spider (Juice Shop es una SPA)
  RUN_ACTIVE     (defecto 0)  poner 1 para ejecutar el escaneo activo (TC-07)
  ACTIVE_MAX_MIN (defecto 10) tiempo maximo del escaneo activo en minutos
  REPORT_DIR     (defecto reportes)
"""
import json
import logging
import os
import pathlib
import time
from datetime import datetime
from urllib.parse import urlparse

import pytest
import requests

log = logging.getLogger("suite_zap")

TARGET = os.getenv("TARGET_URL", "http://localhost:3000").rstrip("/")
ZAP_API = os.getenv("ZAP_API", "http://localhost:8080").rstrip("/")
ZAP_KEY = os.getenv("ZAP_API_KEY", "")
MIN_URLS = int(os.getenv("MIN_URLS", "5"))
USE_AJAX = os.getenv("USE_AJAX", "1") == "1"
RUN_ACTIVE = os.getenv("RUN_ACTIVE", "0") == "1"
ACTIVE_MAX_MIN = int(os.getenv("ACTIVE_MAX_MIN", "10"))
REPORT_DIR = pathlib.Path(os.getenv("REPORT_DIR", "reportes"))
BASELINE = REPORT_DIR / "baseline_alertas.json"
REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ----------------------------------------------------------------------------
# Utilidades
# ----------------------------------------------------------------------------
def zap(path, **params):
    """Llama a la API JSON de ZAP y devuelve el JSON de la respuesta."""
    params["apikey"] = ZAP_KEY
    r = requests.get(f"{ZAP_API}{path}", params=params, timeout=60)
    r.raise_for_status()
    return r.json()


def esperar(condicion, timeout_s, pausa_s=3, descripcion="condicion"):
    """Reintenta 'condicion()' hasta que sea True o se cumpla el timeout."""
    inicio = time.time()
    while time.time() - inicio < timeout_s:
        if condicion():
            return
        time.sleep(pausa_s)
    pytest.fail(f"Timeout de {timeout_s}s esperando: {descripcion}")


# ----------------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------------
@pytest.fixture(scope="session", autouse=True)
def guardia_de_alcance():
    """Marco etico del Sprint 1: solo se prueba un objetivo local autorizado."""
    host = urlparse(TARGET).hostname
    if host not in ("localhost", "127.0.0.1"):
        pytest.exit(f"ALCANCE NO AUTORIZADO: {TARGET}. Solo se permite localhost.", returncode=2)
    log.info("Objetivo autorizado: %s", TARGET)


@pytest.fixture(scope="session")
def exploracion():
    """Explora el SUT con ZAP (spider + ajax spider + espera del escaneo pasivo)."""
    zap("/JSON/core/action/accessUrl/", url=TARGET, followRedirects="true")
    scan = zap("/JSON/spider/action/scan/", url=TARGET, recurse="true")["scan"]
    esperar(lambda: int(zap("/JSON/spider/view/status/", scanId=scan)["status"]) >= 100,
            180, descripcion="fin del spider")
    log.info("Spider finalizado")

    if USE_AJAX:
        try:
            zap("/JSON/ajaxSpider/action/scan/", url=TARGET)
            esperar(lambda: zap("/JSON/ajaxSpider/view/status/")["status"] == "stopped",
                    150, descripcion="fin del Ajax Spider")
        except Exception as e:  # sin navegador compatible el Ajax Spider puede no iniciar
            log.warning("Ajax Spider omitido: %s", e)
            try:
                zap("/JSON/ajaxSpider/action/stop/")
            except Exception:
                pass

    esperar(lambda: int(zap("/JSON/pscan/view/recordsToScan/")["recordsToScan"]) == 0,
            180, descripcion="fin del escaneo pasivo")
    log.info("Escaneo pasivo finalizado")
    return True


def obtener_alertas():
    return zap("/JSON/core/view/alerts/", baseurl=TARGET, start="0", count="5000")["alerts"]


@pytest.fixture(scope="session", autouse=True)
def guardar_reporte_zap():
    """Al terminar la sesion guarda el reporte HTML generado por ZAP (evidencia)."""
    yield
    try:
        r = requests.get(f"{ZAP_API}/OTHER/core/other/htmlreport/", params={"apikey": ZAP_KEY}, timeout=120)
        r.raise_for_status()
        destino = REPORT_DIR / f"reporte_zap_{datetime.now():%Y%m%d_%H%M%S}.html"
        destino.write_bytes(r.content)
        log.info("Reporte de ZAP guardado en %s", destino)
    except Exception as e:
        log.warning("No se pudo guardar el reporte de ZAP: %s", e)


# ----------------------------------------------------------------------------
# TC-01  Disponibilidad del entorno (prueba de humo)
# ----------------------------------------------------------------------------
def test_tc01_entorno_disponible():
    """Juice Shop responde 200 y ZAP responde su version por API."""
    r = requests.get(TARGET, timeout=15)
    assert r.status_code == 200, f"Juice Shop respondio {r.status_code}"
    version = zap("/JSON/core/view/version/")["version"]
    log.info("ZAP version %s / Juice Shop HTTP %s", version, r.status_code)
    assert version


# ----------------------------------------------------------------------------
# TC-02  Cobertura del spider
# ----------------------------------------------------------------------------
def test_tc02_spider_cobertura(exploracion):
    """ZAP descubre al menos MIN_URLS URLs del SUT."""
    urls = zap("/JSON/core/view/urls/", baseurl=TARGET)["urls"]
    log.info("URLs descubiertas: %d (umbral %d)", len(urls), MIN_URLS)
    assert len(urls) >= MIN_URLS, f"Solo {len(urls)} URLs (minimo {MIN_URLS})"


# ----------------------------------------------------------------------------
# TC-03  Cabeceras de seguridad (analisis de configuracion)
# ----------------------------------------------------------------------------
@pytest.mark.parametrize("cabecera", ["Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"])
def test_tc03_cabeceras_seguridad(cabecera):
    """La respuesta del SUT debe incluir la cabecera de seguridad."""
    r = requests.get(TARGET, timeout=15)
    log.info("%s = %s", cabecera, r.headers.get(cabecera))
    assert cabecera in r.headers, f"Falta la cabecera {cabecera}"


# ----------------------------------------------------------------------------
# TC-04  Politica CORS
# ----------------------------------------------------------------------------
def test_tc04_cors_no_comodin():
    """Access-Control-Allow-Origin no debe ser '*' (cualquier origen)."""
    r = requests.get(f"{TARGET}/rest/products/search", params={"q": ""}, headers={"Origin": "http://otro-origen.test"}, timeout=15)
    acao = r.headers.get("Access-Control-Allow-Origin")
    log.info("Access-Control-Allow-Origin = %s", acao)
    assert acao != "*", "CORS permite cualquier origen (*)"


# ----------------------------------------------------------------------------
# TC-05  Login con credenciales invalidas (particion de equivalencia)
# ----------------------------------------------------------------------------
def test_tc05_login_credenciales_invalidas():
    """Un usuario inexistente con clave incorrecta debe recibir 401."""
    r = requests.post(f"{TARGET}/rest/user/login",
                      json={"email": "no_existe@prueba.local", "password": "ClaveIncorrecta#1"}, timeout=15)
    log.info("Login invalido -> HTTP %s", r.status_code)
    assert r.status_code == 401


# ----------------------------------------------------------------------------
# TC-06  Login con entradas maliciosas (valores frontera / inyeccion)
# ----------------------------------------------------------------------------
@pytest.mark.parametrize("email", ["'", "' OR 1=1--"])
def test_tc06_login_entradas_maliciosas(email):
    """El login debe rechazar la entrada con 4xx: ni 200 (acceso) ni 5xx (error no controlado)."""
    r = requests.post(f"{TARGET}/rest/user/login", json={"email": email, "password": "x"}, timeout=15)
    log.info("Login con %r -> HTTP %s", email, r.status_code)
    assert 400 <= r.status_code < 500, f"Respuesta inesperada HTTP {r.status_code} para {email!r}"


# ----------------------------------------------------------------------------
# TC-07  Escaneo activo acotado (quality gate)
# ----------------------------------------------------------------------------
@pytest.mark.skipif(not RUN_ACTIVE, reason="Escaneo activo desactivado: ejecutar con RUN_ACTIVE=1")
def test_tc07_escaneo_activo_sin_alertas_high(exploracion):
    """Tras un escaneo activo acotado no debe haber alertas de riesgo High."""
    scan = zap("/JSON/ascan/action/scan/", url=TARGET, recurse="true")["scan"]
    inicio = time.time()
    while int(zap("/JSON/ascan/view/status/", scanId=scan)["status"]) < 100:
        if time.time() - inicio > ACTIVE_MAX_MIN * 60:
            zap("/JSON/ascan/action/stop/", scanId=scan)
            log.warning("Escaneo activo detenido por limite de %d min", ACTIVE_MAX_MIN)
            break
        time.sleep(10)
    altas = [a for a in obtener_alertas() if a.get("risk") == "High"]
    for a in altas:
        log.info("ALERTA HIGH: %s (%s)", a.get("alert"), a.get("url"))
    assert not altas, f"{len(altas)} alertas High tras el escaneo activo"


# ----------------------------------------------------------------------------
# TC-08  Regresion contra linea base de alertas
# ----------------------------------------------------------------------------
def test_tc08_regresion_alertas(exploracion):
    """No deben aparecer tipos de alerta nuevos respecto de la linea base guardada."""
    tipos = sorted({a["alert"] for a in obtener_alertas()})
    log.info("Tipos de alerta en esta corrida: %d", len(tipos))
    if not BASELINE.exists():
        BASELINE.write_text(json.dumps(tipos, indent=2, ensure_ascii=False), encoding="utf-8")
        log.info("Primera corrida: linea base creada en %s", BASELINE)
        return
    base = set(json.loads(BASELINE.read_text(encoding="utf-8")))
    nuevos = set(tipos) - base
    assert not nuevos, f"Alertas nuevas respecto de la linea base: {sorted(nuevos)}"
