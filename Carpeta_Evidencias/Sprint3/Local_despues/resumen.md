## Resultado de la suite de seguridad (OWASP ZAP + Juice Shop)

- Inicio: 2026-10-22T18:12:43 | Duración total: **38.67 s**
- ZAP: 2.17.0 | URLs descubiertas: 88 | Tipos de alerta: 4
- Modo: escaneo activo=1, sesión limpia=1, hallazgos conocidos=xfail, commit=local
- Conteo: hallazgo_conocido=4, paso=6, xpass=1
- Tiempos por fase (s): {'spider_s': 18.09, 'ajax_spider_s': 1.01, 'pscan_s': 1.0, 'escaneo_activo_s': 15.05}

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
| test_tc06_login_entradas_maliciosas[tautologia_sql] | hallazgo_conocido | 0.05 |
| test_tc07_escaneo_activo_sin_alertas_high | xpass | 15.17 |
| test_tc08_regresion_alertas | paso | 0.0 |
