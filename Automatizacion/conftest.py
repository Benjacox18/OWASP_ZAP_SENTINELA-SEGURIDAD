"""
Hooks de pytest (Sprint 3): generan reportes automaticos sin que nadie los arme a mano.
Al terminar la corrida escriben:
  reportes/metricas.json  -> datos medibles (duracion total, tiempos por fase, URLs, alertas, resultados)
  reportes/resumen.md     -> resumen legible; el CI lo muestra en la pestaña del workflow
"""
import json
import os
import pathlib
import time
from datetime import datetime

import metricas

REPORT_DIR = pathlib.Path(os.getenv("REPORT_DIR", "reportes"))
_inicio = {"t": time.perf_counter()}


def pytest_sessionstart(session):
    _inicio["t"] = time.perf_counter()
    metricas.datos["inicio"] = datetime.now().isoformat(timespec="seconds")


def _estado(report):
    """Traduce el resultado de pytest a un estado claro para el equipo."""
    if hasattr(report, "wasxfail"):  # xfail: fallo esperado (hallazgo conocido)
        return "hallazgo_conocido" if report.skipped else "xpass"
    if report.skipped:
        return "omitido"
    if report.passed:
        return "paso"
    if "XPASS(strict)" in str(report.longrepr):  # un hallazgo conocido dejo de fallar
        return "hallazgo_corregido"
    return "error" if report.when != "call" else "fallo"


def pytest_runtest_logreport(report):
    # Se registra el resultado del test (fase "call") o el error/omision de su preparacion ("setup").
    if report.when == "call" or (report.when == "setup" and not report.passed):
        metricas.datos["pruebas"].append({
            "test": report.nodeid.split("::", 1)[-1],
            "estado": _estado(report),
            "duracion_s": round(report.duration, 2),
        })


def pytest_sessionfinish(session, exitstatus):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    d = metricas.datos
    d["duracion_total_s"] = round(time.perf_counter() - _inicio["t"], 2)
    d["configuracion"] = {
        "RUN_ACTIVE": os.getenv("RUN_ACTIVE", "0"),
        "CLEAN_SESSION": os.getenv("CLEAN_SESSION", "1"),
        "KNOWN_FINDINGS": os.getenv("KNOWN_FINDINGS", "xfail"),
        "CI": os.getenv("CI", "false"),
        "commit": os.getenv("GITHUB_SHA", "local")[:7],
    }
    conteo = {}
    for p in d["pruebas"]:
        conteo[p["estado"]] = conteo.get(p["estado"], 0) + 1
    d["conteo"] = conteo
    d["exit_status"] = int(exitstatus)
    (REPORT_DIR / "metricas.json").write_text(json.dumps(d, indent=2, ensure_ascii=False), encoding="utf-8")

    lineas = [
        "## Resultado de la suite de seguridad (OWASP ZAP + Juice Shop)",
        "",
        f"- Inicio: {d.get('inicio')} | Duración total: **{d['duracion_total_s']} s**",
        f"- ZAP: {d.get('version_zap')} | URLs descubiertas: {d.get('urls')} | Tipos de alerta: {d.get('tipos_alerta')}",
        f"- Modo: escaneo activo={d['configuracion']['RUN_ACTIVE']}, sesión limpia={d['configuracion']['CLEAN_SESSION']}, "
        f"hallazgos conocidos={d['configuracion']['KNOWN_FINDINGS']}, commit={d['configuracion']['commit']}",
        f"- Conteo: {', '.join(f'{k}={v}' for k, v in sorted(conteo.items())) or 'sin pruebas'}",
        f"- Tiempos por fase (s): {d['fases'] or 'sin datos'}",
        "",
        "| Test | Estado | Duración (s) |",
        "|---|---|---|",
    ]
    lineas += [f"| {p['test']} | {p['estado']} | {p['duracion_s']} |" for p in d["pruebas"]]
    (REPORT_DIR / "resumen.md").write_text("\n".join(lineas) + "\n", encoding="utf-8")
