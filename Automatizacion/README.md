# Sprint 3 - Grupo 5 - Automatización completa e integración continua (OWASP ZAP + Juice Shop)

![Pruebas de seguridad](https://github.com/Benjacox18/OWASP_ZAP_SENTINELA-SEGURIDAD/actions/workflows/security-tests.yml/badge.svg)

Suite de pruebas de seguridad que corre sola en GitHub Actions y también en cada máquina del equipo.
**Solo se prueba el laboratorio local autorizado (localhost:3000).** La suite aborta si el objetivo no es localhost.

## Qué hace el CI (`.github/workflows/security-tests.yml`)
Se ejecuta en cada push y pull request a `main`, todos los lunes y a pedido (pestaña **Actions → Run workflow**). Pasos:
1. Levanta Juice Shop (Docker) y ZAP en modo daemon con una clave de API aleatoria y una sesión limpia.
2. Ejecuta los 8 casos (TC-01 a TC-08), con escaneo activo acotado (TC-07).
3. Genera los reportes solos y los sube como artefacto (`reportes-zap-<n°>`), y muestra el resumen en la página de la ejecución.

## Cómo interpretar el resultado del CI
| Estado | Significado | ¿El CI queda? |
|---|---|---|
| `paso` | El sistema cumple el criterio de aceptación | Verde |
| `hallazgo_conocido` | Falla esperada de H-01 a H-05 (Juice Shop es vulnerable a propósito) | Verde |
| `fallo` / `error` | Algo nuevo o roto: regresión, entorno caído, alerta nueva en TC-08 | **Rojo** |
| `hallazgo_corregido` | Un hallazgo conocido dejó de fallar: hay que actualizar su marca `hallazgo(...)` | **Rojo** |

Con `KNOWN_FINDINGS=fail` la suite se comporta como en el Sprint 2 (los hallazgos figuran como FAILED).

## Ejecución local (Windows)
1. Juice Shop: `docker run --rm -p 3000:3000 bkimminich/juice-shop`
2. ZAP en modo daemon (desde la carpeta de instalación; si el 8080 está ocupado usar otro puerto): `zap.bat -daemon -port 8090 -config api.key=CLAVE`
3. Dependencias (recomendado en un entorno virtual): `python -m venv venv`, `.\venv\Scripts\Activate.ps1`, `pip install -r requirements.txt`
4. Suite: `ejecutar_suite.bat CLAVE 1 8090` (clave, `1` = incluir escaneo activo, puerto de ZAP; los dos últimos son opcionales).

## Ejecución local con Docker (igual que el CI, Linux/macOS/WSL)
```bash
docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop
docker run -d --name zap --network host -u zap ghcr.io/zaproxy/zaproxy:stable \
  zap-x.sh -daemon -host 127.0.0.1 -port 8080 -config api.key=CLAVE
ZAP_API_KEY=CLAVE RUN_ACTIVE=1 python -m pytest -v
```

## Variables de entorno principales
`ZAP_PORT` (8080), `ZAP_API_KEY`, `RUN_ACTIVE` (0/1), `CLEAN_SESSION` (1), `KNOWN_FINDINGS` (`xfail`/`fail`), `REQUIRE_BASELINE` (0/1),
`SPIDER_MAX_MIN`, `AJAX_MAX_MIN`, `ACTIVE_MAX_MIN`, `HTTP_TIMEOUT`. La lista completa y comentada está al inicio de `test_suite_zap.py`.

## Reportes (carpeta `reportes/`, se generan solos)
- `reporte_pytest.html`, `resultados.xml`, `Ejecucion_Pruebas.log` (con fecha y hora)
- `reporte_zap_<fecha>.html` y `.json` (reportes de ZAP)
- `metricas.json` (duración total, tiempos por fase, URLs, tipos de alerta, resultado de cada test) y `resumen.md`

## Línea base de TC-08 (`baseline/baseline_alertas.json`)
Está versionada en Git para que la regresión compare en el CI. Contiene solo alertas del escaneo pasivo. Para actualizarla a propósito: borrarla, correr la suite, revisar el archivo generado y hacer commit.

## Casos
TC-01 entorno, TC-02 cobertura spider, TC-03 cabeceras (H-01), TC-04 CORS (H-02), TC-05 login inválido, TC-06 entradas maliciosas (H-03, H-04), TC-07 escaneo activo (H-05), TC-08 regresión. Detalle en los documentos de los Sprints 2 y 3.
