"""
Metricas de la corrida (Sprint 3).
Guarda datos medibles (tiempos por fase, URLs, tipos de alerta) para poder comparar
"antes vs despues" de las optimizaciones. conftest.py los escribe en reportes/metricas.json
y reportes/resumen.md al terminar la sesion de pytest.
"""
import time
from contextlib import contextmanager

datos = {
    "fases": {},          # segundos por fase (spider, ajax spider, escaneo pasivo, escaneo activo)
    "urls": None,         # URLs descubiertas por ZAP (TC-02)
    "tipos_alerta": None, # cantidad de tipos de alerta (TC-08)
    "alertas_high": None, # alertas High tras el escaneo activo (TC-07)
    "version_zap": None,  # version de ZAP usada
    "pruebas": [],        # resultado y duracion de cada test
}


@contextmanager
def fase(nombre):
    """Mide cuanto tarda un bloque de codigo y lo guarda en datos['fases']."""
    inicio = time.perf_counter()
    try:
        yield
    finally:
        datos["fases"][nombre] = round(time.perf_counter() - inicio, 2)
