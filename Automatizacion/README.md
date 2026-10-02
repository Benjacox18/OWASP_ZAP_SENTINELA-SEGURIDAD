# OWASP ZAP — Grupo 5 "Los Centinelas de Seguridad"

**Instituto de Educación Superior Alfredo Coviello** · Tecnicatura Superior en Desarrollo de Software
Técnicas Avanzadas de Programación (TAP) · 3.º Año · Ciclo 2026
**Proyecto de Especialización en Herramientas de Testing — Security Testing con OWASP ZAP**
Cliente del caso: **FinanceSecure**

Repositorio: https://github.com/Benjacox18/OWASP_ZAP_SENTINELA-SEGURIDAD

## Equipo

| Integrante | Rol | Responsabilidad en el Sprint 2 |
|---|---|---|
| Brandan Joaquin | Security Lead | Alcance, estrategia de prueba, TC-03 y TC-04 |
| Burgos Benjamín | Analista de Escaneo | Ejecución de TC-02 y TC-07 (escaneo activo) |
| Burgos José | Verificador de Hallazgos | Suite pytest, TC-05, TC-06, TC-08 y clasificación de hallazgos |
| Romano Alejo | Documentador y Reportero | Documento, README, bitácora, TC-01 y armado del ZIP |

## Qué contiene el Sprint 2

El Sprint 1 definió el marco ético, instaló OWASP ZAP 2.17.0, montó OWASP Juice Shop en Docker y obtuvo un primer reporte de escaneo pasivo. En el Sprint 2 el equipo diseña ocho casos de prueba con su justificación técnica y los automatiza en una suite **pytest** que controla a ZAP por su API REST y consulta directamente a Juice Shop.

**Sistema bajo prueba:** OWASP Juice Shop en Docker, `http://localhost:3000`, con datos ficticios. La suite incluye una guardia que aborta si el objetivo no es `localhost`. Todo el trabajo se rige por el Acuerdo de Uso Responsable del Sprint 1.

## Estructura del repositorio

```
OWASP_ZAP_SENTINELA-SEGURIDAD/
├── README.md
├── Bitacora_Sprint2_Grupo5.xlsx
├── Documento_Sprint2_Grupo5_OWASP_ZAP.docx
├── Links_Externos.txt
├── Automatizacion/
│   ├── test_suite_zap.py
│   ├── pytest.ini
│   ├── requirements.txt
│   └── ejecutar_suite.bat
└── Carpeta_Evidencias/
    ├── Capturas/
    └── Reportes/
```

| Archivo | Para qué sirve |
|---|---|
| `test_suite_zap.py` | Suite pytest con los 8 casos de prueba (11 tests, contando los subcasos). |
| `pytest.ini` | Genera el log con fecha y hora en `reportes/Ejecucion_Pruebas.log`. |
| `ejecutar_suite.bat` y `requirements.txt` | Ejecución reproducible en Windows. |

## Cómo ejecutar la suite (Windows, PowerShell)

**1. Iniciar Juice Shop** (ventana 1):

```powershell
docker run --rm -p 3000:3000 bkimminich/juice-shop
```

**2. Iniciar ZAP en modo daemon con clave de API** (ventana 2, desde la carpeta de instalación de ZAP):

```powershell
.\zap.bat -daemon -port 8090 -config api.key=clave123
```

Si el puerto 8080 está libre se puede usar `-port 8080`. En el laboratorio del equipo estaba ocupado (Apache u otro programa), por lo que se usó el 8090. Debe esperarse el mensaje de que ZAP está escuchando antes de ejecutar la suite.

**3. Preparar el entorno de Python** (ventana 3):

```powershell
cd C:\Sprint2\Automatizacion
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:ZAP_API="http://localhost:8090"
```

La variable `ZAP_API` solo es necesaria si ZAP no usa el puerto 8080. Si no se define, la suite apunta al 8080.

**4. Ejecutar la suite:**

```powershell
.\ejecutar_suite.bat clave123
```

Para incluir el escaneo activo acotado (TC-07), agregar `1` como segundo argumento:

```powershell
.\ejecutar_suite.bat clave123 1
```

La clave debe coincidir con la de `api.key`. Una corrida sin escaneo activo tarda alrededor de 40 segundos; con escaneo activo, alrededor de 1 minuto.

### Reportes generados

Se guardan en `reportes/`: `reporte_pytest.html`, `resultados.xml`, `Ejecucion_Pruebas.log`, el reporte HTML de ZAP (`reporte_zap_AAAAMMDD_HHMMSS.html`) y `baseline_alertas.json`. El reporte de pytest y el log se sobrescriben en cada corrida; el reporte de ZAP lleva fecha y hora en el nombre. Antes de subirlos al repositorio, cada integrante renombra los suyos con el sufijo `_NOMBRE` (por ejemplo `_JOAQUIN`).

### Problemas frecuentes

| Síntoma | Causa | Solución |
|---|---|---|
| TC-01 falla y TC-02 y TC-08 dan error con HTTP 404 en `localhost:8080` | ZAP corre en otro puerto y no se definió `ZAP_API` | Definir `$env:ZAP_API` con el puerto real y repetir |
| ZAP abre su ventana gráfica y avisa que el puerto está ocupado | Se inició sin `-daemon` o el 8080 está en uso | Cerrarla y ejecutar `zap.bat -daemon -port 8090 ...` |
| `Activate.ps1` no se reconoce | Ruta mal copiada o el `venv` no existe | Verificar la ruta con `dir` o crear el entorno con `python -m venv venv` |
| `pip` falla al instalar dependencias | Instalación de pip dañada | Crear un entorno virtual y usarlo |
| Timeout del spider (180 s) o `ReadTimeout` en TC-04 | Sesión de ZAP acumulada, con miles de URLs | Reiniciar ZAP y Juice Shop y repetir |
| TC-01 falla con conexión rechazada al puerto 3000 | Juice Shop apagado | Levantar Juice Shop y repetir |

## Casos de prueba

| Caso | Aspecto | Categoría OWASP Top 10:2025 | Test automatizado | Responsable |
|---|---|---|---|---|
| TC-01 | Disponibilidad del entorno (prueba de humo) | Precondición | `test_tc01_entorno_disponible` | Alejo Romano |
| TC-02 | Cobertura de la exploración (spider) | Base del análisis | `test_tc02_spider_cobertura` | Benja Burgos |
| TC-03 | Cabeceras de seguridad HTTP (3 subcasos) | A02 Security Misconfiguration | `test_tc03_cabeceras_seguridad` | Joaquín Brandan |
| TC-04 | Política CORS | A02 Security Misconfiguration | `test_tc04_cors_no_comodin` | Joaquín Brandan |
| TC-05 | Login con credenciales inválidas | A07 Authentication Failures | `test_tc05_login_credenciales_invalidas` | José Burgos |
| TC-06 | Login con entradas maliciosas (2 subcasos) | A05 Injection; A10 Mishandling of Exceptional Conditions | `test_tc06_login_entradas_maliciosas` | José Burgos |
| TC-07 | Escaneo activo acotado (quality gate) | A05, A02, A01 según alertas | `test_tc07_escaneo_activo_sin_alertas_high` (con `RUN_ACTIVE=1`) | Benja Burgos |
| TC-08 | Regresión contra línea base de alertas | Transversal | `test_tc08_regresion_alertas` | José Burgos |

Un test pasa cuando el sistema cumple el criterio de aceptación y falla cuando no lo cumple. Contra una aplicación deliberadamente vulnerable es esperable que algunos casos de seguridad fallen: eso demuestra que la suite detecta problemas. No se evalúa carga, denegación de servicio, fuerza bruta, fuzzing masivo, post-explotación ni HSTS (el laboratorio corre sobre HTTP local).

### Resultado típico de la suite (sin escaneo activo)

**4 failed, 6 passed, 1 skipped** (el omitido es TC-07). Los cuatro fallos esperables son:

| Test | Resultado observado |
|---|---|
| `test_tc03_cabeceras_seguridad[Content-Security-Policy]` | `Content-Security-Policy = None` |
| `test_tc04_cors_no_comodin` | `Access-Control-Allow-Origin = *` |
| `test_tc06_login_entradas_maliciosas[']` | HTTP 500 |
| `test_tc06_login_entradas_maliciosas[' OR 1=1--]` | HTTP 200 |

Pasan TC-01 (ZAP 2.17.0 y Juice Shop HTTP 200), TC-02 (88 URLs descubiertas con la sesión limpia), `X-Content-Type-Options = nosniff`, `X-Frame-Options = SAMEORIGIN`, TC-05 (HTTP 401) y TC-08 (crea la línea base con 4 tipos de alerta en la primera corrida).

## Ejecución documentada

Todas las corridas son del 01/10/2026 y se hicieron en la máquina de cada integrante.

| Integrante | Hora | Resultado | Observaciones |
|---|---|---|---|
| Brandan Joaquin | 20:35 | 3 passed, 5 failed, 1 skipped, 2 errors (6,70 s) | La suite apuntó al puerto 8080 por no definir `ZAP_API` (TC-01 falló; TC-02 y TC-08 dieron error) |
| | 20:39 | 6 passed, 4 failed, 1 skipped (41,73 s) | ZAP en el 8090; TC-08 creó la línea base con 4 tipos de alerta |
| Burgos Benjamín | 03:17 | 6 passed, 4 failed, 1 skipped | Primera corrida; TC-08 creó la línea base (4 tipos) |
| | 03:32 | 8 failed, 2 errors | Con Juice Shop apagado (TC-01 falla) |
| | 03:39 | 5 passed, 5 failed, 1 skipped | TC-08 detectó una alerta nueva de CSP (5 tipos) |
| | 03:43 | 4 passed, 4 failed, 3 errors | Timeout del spider (180 s) con la sesión acumulada |
| | 03:51 | 7 passed, 4 failed | Con `RUN_ACTIVE=1`; TC-07 pasó con 0 alertas High; TC-08 pasó con 4 tipos |
| Burgos José | 17:42 | 6 passed, 4 failed, 1 skipped (41,67 s) | TC-08 creó la línea base (4 tipos) |
| | 17:55 | 5 passed, 5 failed, 1 skipped (26,56 s) | TC-08 falló por una alerta nueva de CSP |
| | 19:19 | 5 passed, 5 failed, 1 skipped (75,14 s) | TC-04 falló por `ReadTimeout` (no por CORS); TC-08 falló por la misma alerta nueva |
| Romano Alejo | 21:12 | 8 failed, 1 skipped, 2 errors (38,65 s) | Con Juice Shop apagado: TC-01 falló por conexión rechazada; TC-02 y TC-08 dieron error |
| | 21:14 | 6 passed, 4 failed, 1 skipped (41,42 s) | Con Juice Shop encendido: TC-01 pasó; TC-08 creó la línea base |
| | 21:30 | 7 passed, 4 failed (60,14 s) | Con `RUN_ACTIVE=1`; TC-07 pasó con 0 alertas High; TC-08 pasó con 4 tipos |

**Regresión (TC-08).** La línea base contiene 4 tipos de alerta: Aplicación Web Moderna; Cabecera Content Security Policy (CSP) no configurada; Configuración Incorrecta Cross-Domain; Divulgación de Marcas de Tiempo - Unix. Dos corridas (la de Benja de las 03:39 y la de José de las 17:55) detectaron una alerta nueva, `CSP: Failure to Define Directive with No Fallback`, sin modificar la línea base. Es un resultado válido: la regresión detectó un cambio. Coincide con el hallazgo H-01.

**Dependencia del estado de la sesión de ZAP.** El TC-02 descubrió 88 URLs con la sesión limpia y 3926 con una sesión acumulada. Con la sesión acumulada aparecieron timeouts del spider y del TC-04, además de alertas distintas entre corridas. Conviene reiniciar ZAP antes de cada corrida.

## Hallazgos

| ID | Alerta / test | Severidad | Clasificación | Mitigación sugerida |
|---|---|---|---|---|
| H-01 | TC-03: `Content-Security-Policy` ausente | Media (riesgo Medio en el reporte de ZAP) | Confirmado | Agregar la cabecera `Content-Security-Policy` en el servidor |
| H-02 | TC-04: CORS abierto a cualquier origen | Media (riesgo Medio en el reporte de ZAP) | Confirmado | Restringir `Access-Control-Allow-Origin` a los orígenes necesarios, en lugar de `*` |
| H-03 | TC-06: error 500 ante una comilla simple en el login | Media (criterio del equipo: error 500 sin controlar) | Confirmado | Manejar la entrada inválida en el login y devolver un error 4xx controlado |
| H-04 | TC-06: entrada con tautología SQL no rechazada en el login | Alta (criterio del equipo) | Confirmado | Usar consultas parametrizadas y validar la entrada del login |

El reporte de ZAP de las corridas con sesión limpia muestra 0 alertas de riesgo Alto y 2 de riesgo Medio. En el laboratorio local, José verificó el H-04 con un `POST /rest/user/login` y el correo `' OR 1=1--`: la respuesta fue HTTP 200 con un token de autenticación de `admin@juice-sh.op`, y al decodificarlo indica `role = admin`.

## Videos y commits

| Integrante | Video (5 min) | Commit propio |
|---|---|---|
| Brandan Joaquin | No realizado | _(pendiente)_ |
| Burgos Benjamín | [Google Drive](https://drive.google.com/file/d/1Sl3qVCmgFTsBO7lwrlVoWV9geg9-pvjJ/view?usp=sharing) | _(pendiente)_ |
| Burgos José | [Google Drive](https://drive.google.com/file/d/1FSdiDnIfJo60ttODAl8kzQI2nKYAQxuP/view?usp=drive_link) | _(pendiente)_ |
| Romano Alejo | [Google Drive](https://drive.google.com/file/d/1y6w9IMZlTeJqal-iKTLYYsfA-GyZS3r2/view?usp=sharing) | _(pendiente)_ |

## Diferencias entre lo planeado y lo implementado

- Se prescindió del plan de ZAP Automation Framework (`plan_zap.yaml`), un complemento no exigido por la consigna: la suite en pytest cubre los entregables.
- El puerto 8080 estaba ocupado en varios equipos (Apache u otro programa), por lo que ZAP se ejecutó en el 8090 y se definió `ZAP_API` en cada equipo.
- La suite se ejecutó dentro de un entorno virtual (`venv`) porque `pip` falló en el equipo de Benja.
- El escaneo activo (TC-07) se ejecutó con `RUN_ACTIVE=1` en las máquinas de Benja y Alejo y quedó omitido en las corridas de Joaquín y José.
- El video individual de Joaquín no se realizó.

## Documentación

- `Documento_Sprint2_Grupo5_OWASP_ZAP.docx`: diseño de pruebas, técnicas aplicadas, matriz de trazabilidad, ejecución documentada, hallazgos y lecciones aprendidas.
- `Bitacora_Sprint2_Grupo5.xlsx`: reparto de tareas, decisiones, problemas y soluciones por integrante.
- `Links_Externos.txt`: links a videos y recursos externos.
