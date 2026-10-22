"""
Suite de pruebas automatizadas - Sprint 3 - Grupo 5 (OWASP ZAP + Juice Shop)
=============================================================================
Sistema bajo prueba (SUT): OWASP Juice Shop en http://localhost:3000 (Docker, entorno propio y autorizado).
Herramienta: OWASP ZAP controlado por su API REST (modo daemon).

Los 8 casos de prueba son los del Sprint 2. El Sprint 3 agrega OPTIMIZACIONES y AUTOMATIZACION:
  1. Sesion limpia de ZAP al inicio (CLEAN_SESSION=1): resultados repetibles entre corridas.
  2. Hallazgos conocidos (H-01 a H-04) marcados como xfail: el CI solo se pone rojo ante algo NUEVO.
     Con KNOWN_FINDINGS=fail la suite se comporta como en el Sprint 2 (los 4 hallazgos fallan).
  3. Puerto de ZAP configurable (ZAP_PORT) y tiempos maximos configurables para spider y Ajax Spider.
  4. Conexion HTTP reutilizada (requests.Session) con reintentos solo ante errores de conexion o timeout.
  5. Linea base de TC-08 versionada en Git (baseline/), para que la regresion funcione en el CI.
  6. Metricas y reportes automaticos (metricas.py + conftest.py): metricas.json, resumen.md, reporte HTML y JSON de ZAP.

Un test PASA si el sistema cumple el criterio de aceptacion; FALLA si no lo cumple.

Variables de entorno (todas opcionales):
  TARGET_URL      (defecto http://localhost:3000)
  ZAP_PORT        (defecto 8080)   puerto de ZAP; si se define ZAP_API se usa ese valor completo
  ZAP_API         (defecto http://localhost:<ZAP_PORT>)
  ZAP_API_KEY     (defecto vacio; la misma clave con la que se inicio ZAP)
  MIN_URLS        (defecto 5)   umbral de cobertura del spider (TC-02)
  USE_AJAX        (defecto 1)   usar tambien el Ajax Spider (Juice Shop es una SPA)
  RUN_ACTIVE      (defecto 0)   poner 1 para ejecutar el escaneo activo (TC-07)
  ACTIVE_MAX_MIN  (defecto 10)  tiempo maximo del escaneo activo en minutos
  SPIDER_MAX_MIN  (defecto 3)   tiempo maximo del spider en minutos
  AJAX_MAX_MIN    (defecto 2)   tiempo maximo del Ajax Spider en minutos
  HTTP_TIMEOUT    (defecto 30)  timeout en segundos de las llamadas al SUT
  POLL_S          (defecto 1)   segundos entre consultas de estado a ZAP
  CLEAN_SESSION   (defecto 1)   crear una sesion nueva de ZAP antes de explorar
  KNOWN_FINDINGS  (defecto xfail) "xfail" = hallazgos conocidos esperados; "fail" = fallan como en Sprint 2
  BASELINE_PATH   (defecto baseline/baseline_alertas.json)
  REQUIRE_BASELINE(defecto 0)   1 = TC-08 falla si falta la linea base (lo usa el CI)
  REPORT_DIR      (defecto reportes)
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
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import metricas

log = logging.getLogger("suite_zap")

TARGET = os.getenv("TARGET_URL", "http://localhost:3000").rstrip("/")
ZAP_PORT = os.getenv("ZAP_PORT", "8080")
ZAP_API = os.getenv("ZAP_API", f"http://localhost:{ZAP_PORT}").rstrip("/")
ZAP_KEY = os.getenv("ZAP_API_KEY", "")
MIN_URLS = int(os.getenv("MIN_URLS", "5"))
USE_AJAX = os.getenv("USE_AJAX", "1") == "1"
RUN_ACTIVE = os.getenv("RUN_ACTIVE", "0") == "1"
ACTIVE_MAX_MIN = int(os.getenv("ACTIVE_MAX_MIN", "10"))
SPIDER_MAX_MIN = int(os.getenv("SPIDER_MAX_MIN", "3"))
AJAX_MAX_MIN = int(os.getenv("AJAX_MAX_MIN", "2"))
HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "30"))
POLL_S = float(os.getenv("POLL_S", "1"))
CLEAN_SESSION = os.getenv("CLEAN_SESSION", "1") == "1"
KNOWN_XFAIL = os.getenv("KNOWN_FINDINGS", "xfail") == "xfail"
REPORT_DIR = pathlib.Path(os.getenv("REPORT_DIR", "reportes"))
BASELINE = pathlib.Path(os.getenv("BASELINE_PATH", "baseline/baseline_alertas.json"))
REQUIRE_BASELINE = os.getenv("REQUIRE_BASELINE", "0") == "1"
REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ----------------------------------------------------------------------------
# Utilidades
# ----------------------------------------------------------------------------
def _crear_sesion_http():
    """Sesion HTTP reutilizable. Reintenta SOLO errores de conexion o timeout; nunca por codigo de estado,
    porque un 500 (por ejemplo H-03) es un resultado que la suite debe observar, no ocultar."""
    reintentos = Retry(total=3, connect=2, read=2, status=0, backoff_factor=0.5,
                       allowed_methods=frozenset(["GET", "POST"]), raise_on_status=False)
    sesion = requests.Session()
    adaptador = HTTPAdapter(max_retries=reintentos)
    sesion.mount("http://", adaptador)
    sesion.mount("https://", adaptador)
    return sesion


HTTP = _crear_sesion_http()


def zap(path, **params):
    """Llama a la API JSON de ZAP y devuelve el JSON de la respuesta."""
    params["apikey"] = ZAP_KEY
    r = HTTP.get(f"{ZAP_API}{path}", params=params, timeout=60)
    r.raise_for_status()
    return r.json()


def esperar(condicion, timeout_s, pausa_s=None, descripcion="condicion"):
    """Reintenta 'condicion()' hasta que sea True o se cumpla el timeout."""
    pausa_s = POLL_S if pausa_s is None else pausa_s
    inicio = time.time()
    while time.time() - inicio < timeout_s:
        if condicion():
            return
        time.sleep(pausa_s)
    pytest.fail(f"Timeout de {timeout_s}s esperando: {descripcion}")


def hallazgo(id_h, detalle):
    """Marca un test como HALLAZGO CONOCIDO (xfail estricto). Con KNOWN_FINDINGS=xfail:
       - el test falla por una asercion  -> estado 'hallazgo_conocido' (el CI sigue en verde);
       - el test pasa (alguien lo corrigio) -> XPASS estricto: el CI se pone rojo para avisar que hay que
         actualizar el hallazgo;
       - falla por OTRA razon (timeout, conexion) -> sigue siendo un fallo real (raises=AssertionError)."""
    return pytest.mark.xfail(KNOWN_XFAIL, reason=f"{id_h} - {detalle}", raises=AssertionError, strict=True)


def obtener_alertas():
    return zap("/JSON/core/view/alerts/", baseurl=TARGET, start="0", count="5000")["alerts"]


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


@pytest.fixture(scope="session", autouse=True)
def sesion_limpia(guardia_de_alcance):
    """OPTIMIZACION: empieza cada corrida con una sesion nueva de ZAP. En el Sprint 2 la sesion acumulada
    produjo timeouts, 88 contra 3926 URLs y alertas distintas entre corridas."""
    if not CLEAN_SESSION:
        log.info("CLEAN_SESSION=0: se reutiliza la sesion actual de ZAP")
        return
    try:
        zap("/JSON/core/action/newSession/", overwrite="true")
        log.info("Sesion nueva de ZAP creada")
    except Exception as e:  # si ZAP no responde, TC-01 lo informa con un mensaje claro
        log.warning("No se pudo crear una sesion nueva de ZAP: %s", e)


@pytest.fixture(scope="session")
def exploracion(sesion_limpia):
    """Explora el SUT con ZAP (spider + ajax spider + espera del escaneo pasivo)."""
    with metricas.fase("spider_s"):
        zap("/JSON/core/action/accessUrl/", url=TARGET, followRedirects="true")
        try:
            zap("/JSON/spider/action/setOptionMaxDuration/", Integer=str(SPIDER_MAX_MIN))
        except Exception as e:
            log.warning("No se pudo limitar la duracion del spider: %s", e)
        scan = zap("/JSON/spider/action/scan/", url=TARGET, recurse="true")["scan"]
        esperar(lambda: int(zap("/JSON/spider/view/status/", scanId=scan)["status"]) >= 100,
                SPIDER_MAX_MIN * 60 + 60, descripcion="fin del spider")
    log.info("Spider finalizado en %s s", metricas.datos["fases"]["spider_s"])

    if USE_AJAX:
        with metricas.fase("ajax_spider_s"):
            try:
                try:
                    zap("/JSON/ajaxSpider/action/setOptionMaxDuration/", Integer=str(AJAX_MAX_MIN))
                except Exception as e:
                    log.warning("No se pudo limitar la duracion del Ajax Spider: %s", e)
                zap("/JSON/ajaxSpider/action/scan/", url=TARGET)
                esperar(lambda: zap("/JSON/ajaxSpider/view/status/")["status"] == "stopped",
                        AJAX_MAX_MIN * 60 + 60, descripcion="fin del Ajax Spider")
            except Exception as e:  # sin navegador compatible el Ajax Spider puede no iniciar
                log.warning("Ajax Spider omitido: %s", e)
                try:
                    zap("/JSON/ajaxSpider/action/stop/")
                except Exception:
                    pass

    with metricas.fase("pscan_s"):
        esperar(lambda: int(zap("/JSON/pscan/view/recordsToScan/")["recordsToScan"]) == 0,
                180, descripcion="fin del escaneo pasivo")
    log.info("Escaneo pasivo finalizado")
    return True


@pytest.fixture(scope="session")
def home():
    """OPTIMIZACION: una sola peticion a la raiz del SUT, compartida por los 3 subcasos de TC-03."""
    return HTTP.get(TARGET, timeout=HTTP_TIMEOUT)


@pytest.fixture(scope="session", autouse=True)
def guardar_reportes_zap():
    """Al terminar la sesion guarda los reportes HTML y JSON generados por ZAP (evidencia automatica)."""
    yield
    marca = f"{datetime.now():%Y%m%d_%H%M%S}"
    for nombre, ruta, ext in (("HTML", "htmlreport", "html"), ("JSON", "jsonreport", "json")):
        try:
            r = HTTP.get(f"{ZAP_API}/OTHER/core/other/{ruta}/", params={"apikey": ZAP_KEY}, timeout=120)
            r.raise_for_status()
            destino = REPORT_DIR / f"reporte_zap_{marca}.{ext}"
            destino.write_bytes(r.content)
            log.info("Reporte %s de ZAP guardado en %s", nombre, destino)
        except Exception as e:
            log.warning("No se pudo guardar el reporte %s de ZAP: %s", nombre, e)


# ----------------------------------------------------------------------------
# TC-01  Disponibilidad del entorno (prueba de humo)
# ----------------------------------------------------------------------------
def test_tc01_entorno_disponible():
    """Juice Shop responde 200 y ZAP responde su version por API."""
    r = HTTP.get(TARGET, timeout=HTTP_TIMEOUT)
    assert r.status_code == 200, f"Juice Shop respondio {r.status_code}"
    version = zap("/JSON/core/view/version/")["version"]
    metricas.datos["version_zap"] = version
    log.info("ZAP version %s / Juice Shop HTTP %s", version, r.status_code)
    assert version


# ----------------------------------------------------------------------------
# TC-02  Cobertura del spider
# ----------------------------------------------------------------------------
def test_tc02_spider_cobertura(exploracion):
    """ZAP descubre al menos MIN_URLS URLs del SUT."""
    urls = zap("/JSON/core/view/urls/", baseurl=TARGET)["urls"]
    metricas.datos["urls"] = len(urls)
    log.info("URLs descubiertas: %d (umbral %d)", len(urls), MIN_URLS)
    assert len(urls) >= MIN_URLS, f"Solo {len(urls)} URLs (minimo {MIN_URLS})"


# ----------------------------------------------------------------------------
# TC-03  Cabeceras de seguridad (analisis de configuracion)
# ----------------------------------------------------------------------------
@pytest.mark.parametrize("cabecera", [
    pytest.param("Content-Security-Policy",
                 marks=hallazgo("H-01", "Content-Security-Policy ausente en la respuesta")),
    "X-Content-Type-Options",
    "X-Frame-Options",
])
def test_tc03_cabeceras_seguridad(cabecera, home):
    """La respuesta del SUT debe incluir la cabecera de seguridad."""
    log.info("%s = %s", cabecera, home.headers.get(cabecera))
    assert cabecera in home.headers, f"Falta la cabecera {cabecera}"


# ----------------------------------------------------------------------------
# TC-04  Politica CORS
# ----------------------------------------------------------------------------
@hallazgo("H-02", "CORS abierto a cualquier origen (Access-Control-Allow-Origin = *)")
def test_tc04_cors_no_comodin():
    """Access-Control-Allow-Origin no debe ser '*' (cualquier origen)."""
    r = HTTP.get(f"{TARGET}/rest/products/search", params={"q": ""},
                 headers={"Origin": "http://otro-origen.test"}, timeout=HTTP_TIMEOUT)
    acao = r.headers.get("Access-Control-Allow-Origin")
    log.info("Access-Control-Allow-Origin = %s", acao)
    assert acao != "*", "CORS permite cualquier origen (*)"


# ----------------------------------------------------------------------------
# TC-05  Login con credenciales invalidas (particion de equivalencia)
# ----------------------------------------------------------------------------
def test_tc05_login_credenciales_invalidas():
    """Un usuario inexistente con clave incorrecta debe recibir 401."""
    r = HTTP.post(f"{TARGET}/rest/user/login",
                  json={"email": "no_existe@prueba.local", "password": "ClaveIncorrecta#1"}, timeout=HTTP_TIMEOUT)
    log.info("Login invalido -> HTTP %s", r.status_code)
    assert r.status_code == 401


# ----------------------------------------------------------------------------
# TC-06  Login con entradas maliciosas (valores frontera / inyeccion)
# ----------------------------------------------------------------------------
@pytest.mark.parametrize("email", [
    pytest.param("'", id="comilla_simple",
                 marks=hallazgo("H-03", "error 500 sin controlar ante una comilla simple")),
    pytest.param("' OR 1=1--", id="tautologia_sql",
                 marks=hallazgo("H-04", "la tautologia SQL concede acceso (token de admin)")),
])
def test_tc06_login_entradas_maliciosas(email):
    """El login debe rechazar la entrada con 4xx: ni 200 (acceso) ni 5xx (error no controlado)."""
    r = HTTP.post(f"{TARGET}/rest/user/login", json={"email": email, "password": "x"}, timeout=HTTP_TIMEOUT)
    log.info("Login con %r -> HTTP %s", email, r.status_code)
    assert 400 <= r.status_code < 500, f"Respuesta inesperada HTTP {r.status_code} para {email!r}"


# ----------------------------------------------------------------------------
# TC-07  Escaneo activo acotado (quality gate)
# ----------------------------------------------------------------------------
@pytest.mark.skipif(not RUN_ACTIVE, reason="Escaneo activo desactivado: ejecutar con RUN_ACTIVE=1")
def test_tc07_escaneo_activo_sin_alertas_high(exploracion):
    """Tras un escaneo activo acotado no debe haber alertas de riesgo High."""
    with metricas.fase("escaneo_activo_s"):
        scan = zap("/JSON/ascan/action/scan/", url=TARGET, recurse="true")["scan"]
        inicio = time.time()
        while int(zap("/JSON/ascan/view/status/", scanId=scan)["status"]) < 100:
            if time.time() - inicio > ACTIVE_MAX_MIN * 60:
                zap("/JSON/ascan/action/stop/", scanId=scan)
                log.warning("Escaneo activo detenido por limite de %d min", ACTIVE_MAX_MIN)
                break
            time.sleep(max(POLL_S, 5))
    altas = [a for a in obtener_alertas() if a.get("risk") == "High"]
    metricas.datos["alertas_high"] = len(altas)
    for a in altas:
        log.info("ALERTA HIGH: %s (%s)", a.get("alert"), a.get("url"))
    assert not altas, f"{len(altas)} alertas High tras el escaneo activo"


# ----------------------------------------------------------------------------
# TC-08  Regresion contra linea base de alertas
# ----------------------------------------------------------------------------
def test_tc08_regresion_alertas(exploracion):
    """No deben aparecer tipos de alerta nuevos respecto de la linea base guardada (versionada en Git)."""
    tipos = sorted({a["alert"] for a in obtener_alertas()})
    metricas.datos["tipos_alerta"] = len(tipos)
    log.info("Tipos de alerta en esta corrida: %d", len(tipos))
    if not BASELINE.exists():
        if REQUIRE_BASELINE:
            pytest.fail(f"Falta la linea base {BASELINE}: debe estar versionada en Git para que la regresion compare.")
        BASELINE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE.write_text(json.dumps(tipos, indent=2, ensure_ascii=False), encoding="utf-8")
        log.info("Primera corrida: linea base creada en %s (revisarla y subirla a Git)", BASELINE)
        return
    base = set(json.loads(BASELINE.read_text(encoding="utf-8")))
    nuevos = set(tipos) - base
    assert not nuevos, f"Alertas nuevas respecto de la linea base: {sorted(nuevos)}"
