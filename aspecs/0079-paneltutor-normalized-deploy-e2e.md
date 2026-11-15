# A.SPEC 0079 — PanelTutor Unsafe-to-Controlled Deployment E2E

## WHY

El auditor, el normalizador y el deployer existían como piezas separadas. Faltaba
una prueba real que empezara con el repositorio público de PanelTutor sin
normalizar, demostrara su bloqueo, normalizara una copia desechable y la dejara
desplegada mediante el runtime controlado de Apps.

## CONTRACT

1. Clonar `luc444s/PanelTutor` en un directorio temporal.
2. Auditar el checkout original con política non-root y exigir errores conocidos.
3. Ejecutar `dangerous_build_normalize.py fix --deployment-copy --apply`.
4. Reauditar y prohibir cualquier error residual.
5. Desplegar con `runtime.deploy`, entorno externo `0600`, ownership labels y
   confinamiento non-root.
6. Verificar en Docker estado, health, usuario/procesos, mounts, namespaces,
   capabilities, privileged y puertos publicados. Los únicos binds admitidos
   son secretos externos de solo lectura bajo `/run/secrets/`.
   Además, consultar `/api/v1/system/health` desde el contenedor `app`; el
   healthcheck Docker normalizado no sustituye esta prueba funcional.
7. Conservar el deployment en éxito. En fallo posterior al deploy, retirar solo
   el proyecto cuya propiedad demuestra su manifest.
8. Escribir evidencia opcional `0600`, sin valores de entorno ni credenciales.
9. En SSH, distinguir una colisión real (`test` devuelve 1) de un fallo de
   transporte/autenticación; este último nunca se presenta como release existente.
10. El override asigna imágenes `spanel-app-*` solo a servicios con `build`.
    Servicios `image:` conservan su referencia upstream, se descargan antes de
    inspeccionar y también deben demostrar un `Config.User` no-root.
11. PanelTutor normalizado declara explícitamente `postgres=postgres` y
    `redis=redis`; no se infieren usuarios desde nombres de imagen. El runtime
    acepta el usuario Compose y prueba después los procesos efectivos.
12. La imagen construida hace el `WORKDIR` legible/atravesable antes de `USER`,
    evitando que modos `0700` del checkout impidan leer plugins o entrypoints.
13. Los `env_file` inseguros se convierten en una marca declarativa y el
    override inyecta únicamente el `app.env` privado staged en esos servicios.
14. Los secretos bind externos permanecen `0600` y su ownership debe permitir
    lectura al UID non-root configurado; nunca se relajan a world-readable.

## INVARIANTS

- El checkout canónico nunca se modifica: solo el clon temporal.
- Un repositorio que no esté inicialmente bloqueado no satisface este E2E.
- Nunca se despliega con errores de auditoría residuales.
- Ningún recurso ajeno al project ID del E2E se inspecciona o elimina.
- Éxito significa deployment todavía `running`; no hay cleanup automático.
- Los errores impresos y la evidencia no contienen valores del env file.

## VERIFICATION

```bash
.venv/bin/python -m pytest \
  scripts/tests/test_dangerous_build_normalize.py \
  scripts/tests/test_e2e_paneltutor_normalized_deploy.py \
  scripts/tests/test_app_deploy.py -q

.venv/bin/python -m ruff check \
  scripts/dangerous_build_normalize.py \
  scripts/e2e_paneltutor_normalized_deploy.py \
  scripts/tests/test_e2e_paneltutor_normalized_deploy.py

SPANEL_LIVE_TESTS=1 \
python3 scripts/e2e_paneltutor_normalized_deploy.py \
  --env-file /secure/paneltutor-e2e.env \
  --transport ssh \
  --evidence /secure/evidence/paneltutor-normalized.json
```

## ROLLBACK

El comando final del E2E muestra la orden ownership-safe para retirar el
deployment. La implementación no altera el repositorio remoto ni hace push.

## Validation Evidence

- Live SSH lab `100.67.5.50`, project
  `paneltutor-normalized-e2e-20261114072201-1f5915`.
- Source commit: `9bb2f9e1a22cfa68eec74a1d6547f9d0db43d2c2`.
- Pre-audit: 12 errores; incluye root final, env files del checkout,
  docker.sock, binds absolutos/sensibles y red externa.
- Post-audit: 0 errores residuales.
- Runtime: `app`, `apps-worker`, `postgres` y `redis` running/healthy y
  non-root; `/api/v1/system/health` responde correctamente desde `app`.
- El deployment permanece running por contrato.

## Change Surface

```yaml
change_surface:
  allowed:
    - aspecs/0079-paneltutor-normalized-deploy-e2e.md
    - scripts/e2e_paneltutor_normalized_deploy.py
    - scripts/tests/test_e2e_paneltutor_normalized_deploy.py
    - scripts/tests/test_e2e_paneltutor_normalized_deploy_live.py
    - scripts/tests/test_app_deploy.py
    - vendor/systutor-core/plugins/apps/backend/runtime/deployment.py
  prohibited:
    - docker-compose.yml
    - Dockerfile
    - .env*
```
