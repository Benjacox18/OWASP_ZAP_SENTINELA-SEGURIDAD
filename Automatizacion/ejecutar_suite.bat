@echo off
REM Ejecuta la suite completa. Requisitos: Juice Shop en localhost:3000 y ZAP en modo daemon (ver README).
REM Uso: ejecutar_suite.bat CLAVE [1 para incluir escaneo activo] [PUERTO_DE_ZAP]
REM Ejemplo: ejecutar_suite.bat MI_CLAVE 1 8090
set ZAP_API_KEY=%1
if "%2"=="1" set RUN_ACTIVE=1
if not "%3"=="" set ZAP_PORT=%3
python -m pytest -v --html=reportes\reporte_pytest.html --self-contained-html --junitxml=reportes\resultados.xml
