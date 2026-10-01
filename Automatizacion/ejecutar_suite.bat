@echo off
REM Ejecuta la suite completa. Requisitos: Juice Shop en localhost:3000 y ZAP en modo daemon (ver README).
REM Uso: ejecutar_suite.bat TU_API_KEY [1 para incluir escaneo activo]
set ZAP_API_KEY=%1
if "%2"=="1" set RUN_ACTIVE=1
python -m pytest -v --html=reportes\reporte_pytest.html --self-contained-html --junitxml=reportes\resultados.xml
