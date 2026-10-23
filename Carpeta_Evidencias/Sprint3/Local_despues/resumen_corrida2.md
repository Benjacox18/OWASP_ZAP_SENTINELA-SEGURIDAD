## Resultado de la suite de seguridad (OWASP ZAP + Juice Shop)

- Inicio: 2026-10-22T18:11:08 | Duración total: **23.38 s**
- ZAP: 2.17.0 | URLs descubiertas: 88 | Tipos de alerta: 4
- Modo: escaneo activo=0, sesión limpia=1, hallazgos conocidos=xfail, commit=local
- Conteo: hallazgo_conocido=4, omitido=1, paso=6
- Tiempos por fase (s): {'spider_s': 19.08, 'ajax_spider_s': 1.01, 'pscan_s': 0.0}

| Test | Estado | Duración (s) |
|---|---|---|
| test_tc01_entorno_disponible | paso | 0.01 |
| test_tc02_spider_cobertura | paso | 0.0 |
| test_tc03_cabeceras_seguridad[Content-Security-Policy] | hallazgo_conocido | 0.0 |
| test_tc03_cabeceras_seguridad[X-Content-Type-Options] | paso | 0.0 |
| test_tc03_cabeceras_seguridad[X-Frame-Options] | paso | 0.0 |
| test_tc04_cors_no_comodin | hallazgo_conocido | 0.01 |
| test_tc05_login_credenciales_invalidas | paso | 0.05 |
| test_tc06_login_entradas_maliciosas[comilla_simple] | hallazgo_conocido | 0.05 |
| test_tc06_login_entradas_maliciosas[tautologia_sql] | hallazgo_conocido | 0.06 |
| test_tc07_escaneo_activo_sin_alertas_high | omitido | 0.0 |
| test_tc08_regresion_alertas | paso | 0.0 |
