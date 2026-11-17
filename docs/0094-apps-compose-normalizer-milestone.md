> **Retirado en `remove-hardener`:** el normalizador y el hardener ya no forman
> parte del pipeline de Apps. Consulta
> [`apps-sin-hardening-invasivo.md`](apps-sin-hardening-invasivo.md). Este
> documento se conserva como registro histórico del hito 0094.

# Milestone 0094 — POS desplegado sin modificar su repositorio

> Documento de cierre y crónica técnica de la aceptación live de
> `A.SPEC 0094` (Apps Compose Normalizer) sobre `spanel.lab`.

## Resultado

**Conseguido.** `satisfecho/pos` (mirror autorizado `luc444s/pos@6d3c951`) se
despliega completo desde el panel **sin tocar su repo, su Compose ni sus
Dockerfiles**.

Evidencia: `artifacts/apps-compose-normalizer-pos-e2e.json`

| Dato | Valor |
| --- | --- |
| Release firmado | `65d2e37a-a750-46dc-80c9-f0a0ef855ba4` |
| Commit POS | `6d3c95138dd917a8deaaae52f692ed0598b12b56` |
| Servicios | 6 (`back`, `db`, `front`, `haproxy`, `redis`, `ws-bridge`) |
| Duración E2E | 258 s |
| Runtime | non-root, `cap_drop: ALL`, sin binds efectivos, sin puertos publicados |
| Resultado | login → inspect → deploy → release listado → probes → verify → evidence → redeploy → cleanup |

## Qué se implementó

- **N1** `container_name` → alias DNS con scope de proyecto.
- **N2** binds de archivo read-only → metadata firmada + `docker cp` de un
  temporal `0444` entre `create` y `up` (sin binds de host).
- **N3** puertos internos `< 1024` → solo `net.ipv4.ip_unprivileged_port_start=0`.
- **N4** `ports` publicados → `expose`; el ingress externo es del panel.
- **N5** servicios one-shot (`exited 0`, excluidos de estabilidad).
- **H1** hardening de usuario: se respeta `USER` numérico del Dockerfile; si no
  existe, fallback non-root `1000:1000` con `COPY --chown` y `chown` del
  `WORKDIR` final.
- **H2** volúmenes anónimos (`/app/node_modules`) → volumen gestionado con
  nombre determinista `spanel-<servicio>-<hash>`, borrable con `--purge-data`.
- **H3** `release_result` serializable: `tool_versions` está congelado con
  `MappingProxyType`; se usa el cuerpo firmado ya descongelado.

## Crónica: ocho bloqueos hasta el verde

Cada capa tapaba a la siguiente. Los mensajes del pipeline eran genéricos, así
que hubo que instrumentar y reproducir antes de arreglar.

| # | Síntoma visible | Causa raíz | Corrección |
| --- | --- | --- | --- |
| 1 | `front` en restart: `sed: can't create temp file '/app/src/index.html…': Permission denied` | `USER 1000:1000` generado sobre `COPY` root-owned | H1 en `scripts/dangerous_build/dockerfile.py` |
| 2 | `Compose image build failed (exit 1)` intermitente | Disco al 100 % por volúmenes anónimos de `/app/node_modules` (26 uds, ~10 GB) | H2 en `scripts/dangerous_build/compose.py` + limpieza |
| 3 | `haproxy` con `cannot inspect effective process users` (y `Cannot open configuration file …/haproxy.cfg`) | El deploy usaba la ruta **scoped**, que hacía `up -d` sin `create` ni inyección | `releases/scoped_execution.py`: `rm -sf → create → cp → up --no-recreate` |
| 4 | `Compose services failed to create (exit 1)` | Esta versión de Compose no acepta `create --no-deps` | quitar `--no-deps` de `create` (sí se usa en `up`) |
| 5 | `an independent probe command is required` | POS es ambiguo (back/front/haproxy/ws-bridge) y no declara ingress | `haproxy`, `traefik`, `proxy` en `_PROBE_PREFERRED_SERVICES` |
| 6 | `TypeError: internal error` tras deploy correcto | `release_result` copiaba `tool_versions` superficialmente (`mappingproxy` no serializable) | H3 en `releases/pipeline.py` + test |
| 7 | `the signed release is not listed by the API` | Worker reconstruido sin `docker-compose.lab-local.yml` → montaba `spanel_apps_state` en vez de `mailadmin_apps_state` | recrear el worker con el stack completo |
| 8 | Síntomas aleatorios (reinicios, timeouts, `ws-bridge: running none`) | Disco lleno: el mensaje de readiness muestra el último servicio válido, no el que falla | limpieza de disco + mensajes reales de `docker top` |

### Regresión N1-network-loss (2026-11-17)

Revisión del contrato N1: la asignación
`config["networks"] = {"default": {"aliases": [value]}}` reemplazaba
completamente las redes declaradas por el servicio. Un `backend` en
`frontend_net` + `database_net` quedaba solo en `default` y perdía la
conectividad con `db`, sin error visible durante la normalización.

Corrección: `_apply_network_alias` preserva listas y diccionarios, conserva
opciones y aliases previos, y solo añade el alias. Casos límite con warning
estructurado: `network_mode` (no se inyecta `networks`), `networks: []` (no se
interpreta como ausente) y redes `external` (sin alias salvo autorización
explícita vía `authorized_external_networks`, vacía por defecto). Aplicada en
las dos copias del normalizador (`scripts/dangerous_build` y
`vendor/systutor-core/plugins/apps/backend`) con tests de regresión en ambas.

Verificación en `spanel.lab` (2026-11-17): worker reconstruido con el mismo
stack (`--build`) y E2E black-box sobre `luc444s/pos@6d3c951`: **10/10 pasos
OK**, release `ff19035e-69d5-4295-8fdd-b04f12ea41b6`, verify y redeploy
correctos, cleanup confirmado. Evidencia:
`artifacts/apps-compose-normalizer-pos-e2e-n1-networks.json`.

Matiz: el Compose de POS declara `pos2_net` en sus seis servicios y el
normalizador corregido lo preserva (comprobado ejecutándolo directamente), pero
el hardener posterior reescribe las redes a `default internal: true` en el
release firmado. Por tanto el E2E demuestra ausencia de regresión; la
preservación de topología la cubren los tests unitarios.

### Pistas falsas (para no repetirlas)

- `docker top` parecía fallar por carrera en HAProxy. No era eso: el contenedor
  estaba en `restarting` porque no encontraba su configuración.
- El `WORKDIR` root-owned era real, pero solo afectaba a `front`, no a
  `haproxy`.
- El mensaje `ws-bridge: running none` era engañoso: ese estado se acepta.

## Infraestructura del lab (importante)

API y worker deben compartir el **mismo volumen de estado**. El override
`docker-compose.lab-local.yml` fija nombres externos:

- `mailadmin_apps_state` → `/var/lib/spanel/apps` (API **y** worker)
- `mailadmin_pgdata`, `mailadmin_hosting_backups`

Invocación canónica para reconstruir el worker:

```bash
cd /home/lucas/mailadmin
docker compose -p spanel \
  -f docker-compose.yml -f docker-compose.powerdns.yml \
  -f docker-compose.lab-local.yml \
  --env-file .env.docker --env-file .env.powerdns \
  up -d --no-deps apps-worker

# verificación obligatoria
docker inspect spanel-apps-worker-1 \
  --format '{{range .Mounts}}{{.Name}} -> {{.Destination}}; {{end}}'
# debe decir: mailadmin_apps_state -> /var/lib/spanel/apps
```

Sin el override, Compose crea volúmenes nuevos (`spanel_apps_state`,
`spanel_pgdata`) y la API deja de ver releases y manifiestos. `mailadmin-apps-worker-1`
es un stack aparte con su propio Redis: no interfiere con la cola de `spanel`.

## Verificación reproducible

```bash
# hardener / normalizador
.venv/bin/python -m pytest \
  scripts/tests/test_compose_normalizer.py \
  scripts/tests/test_compose_normalizer_networks.py \
  scripts/tests/test_dangerous_build_normalize.py \
  scripts/tests/test_transactional_build_hardener.py -q

# backend Apps (incluye scoped y deploy firmado)
cd vendor/systutor-core && ../../.venv/bin/python -m pytest \
  plugins/apps/backend/tests/test_compose_normalizer.py \
  plugins/apps/backend/tests/test_compose_normalizer_networks.py \
  plugins/apps/backend/tests/test_hardening_engine.py \
  plugins/apps/backend/tests/test_trusted_deploy.py \
  plugins/apps/backend/tests/test_probes.py \
  plugins/apps/backend/tests/test_volume_binds.py \
  plugins/apps/backend/tests/test_one_shot.py \
  plugins/apps/backend/tests/test_scoped_planner.py -q

# estilo y limpieza
.venv/bin/python -m ruff check \
  scripts/dangerous_build/compose.py \
  scripts/dangerous_build/compose_normalizer.py \
  scripts/dangerous_build/dockerfile.py \
  scripts/dangerous_build/hardener.py \
  vendor/systutor-core/plugins/apps/backend/releases/pipeline.py \
  vendor/systutor-core/plugins/apps/backend/releases/scoped_execution.py
git diff --check
```

Resultado actual: **33 + 97 tests**, Ruff limpio, `git diff --check` limpio.

## Lecciones

1. **Comprobar disco primero.** Un `df` al inicio habría evitado dos corridas
   completas y varios diagnósticos falsos.
2. **El error que ves no es el error que hay.** Hay que capturar `stderr` de
   Compose y el traceback del worker; sin eso se depura a ciegas.
3. **Una ruta nueva duplica contratos.** Al añadir la ejecución scoped (0093) se
   perdió la inyección de archivos (0094). Los tests deben cubrir *ambas* rutas.
4. **Congelar datos requiere descongelarlos al persistir.** `MappingProxyType`
   no es serializable; cualquier resultado que vaya a BD debe ser JSON puro.
5. **Reconstruir un servicio exige el mismo stack.** Un `docker compose` con
   menos archivos cambia volúmenes y redes silenciosamente.

## Guardrails propuestos (siguiente entrega)

- Preflight de disco en el worker y en el E2E (fallar con mensaje explícito).
- Incluir `stderr` de `create`/`up` en los `AppDeployError`.
- Formatter del worker con traceback (hoy `logger.exception` lo emite pero el
  formatter lo descarta).
- Smoke deploy barato (~1 min) con app mínima y archivo inyectado, previo a POS.
- Test de contrato que verifique que toda ruta de deploy (trusted y scoped)
  crea, inyecta y arranca en el mismo orden.

## Pendientes

- [x] Commit y push de los cambios (`622783e` en `origin/main`).
- [x] Eliminar volúmenes huérfanos del lab (`spanel_apps_state` 5.9 GB y
      `spanel_pgdata` 49 MB) — hecho; el host pasó de 6.8 GB a 15 GB libres.
- [x] Limpiar imágenes `spanel-app-*` de pruebas y cachés (trivy, pip,
      playwright) — 9 imágenes y ~1.6 GB de caché eliminados.
- [ ] Implementar los guardrails de arriba.

## Referencias

- `aspecs/0094-apps-compose-normalizer.md` — contrato y criterios.
- `artifacts/apps-compose-normalizer-pos-e2e.json` — evidencia del E2E.
- `scripts/e2e_apps_trusted_deploy.py` — black-box real.
