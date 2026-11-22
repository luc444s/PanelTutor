# A.SPEC 0113 — Servicio de métricas vivas, SSE y gráfica en el panel

> `risk: high` — introduce un daemon con socket Unix y token, una ruta SSE y
> una sección de UI en vivo. Requiere `approver:` humano y E2E en laboratorio.

## WHY

A.SPEC 0112 dejó un colector Rust y un CLI que muestran métricas reales de una
celda, pero solo bajo demanda y por terminal. Para operar el panel hace falta
ver la celda **mientras se usa**: RAM, CPU, PIDs, presión e I/O actualizados de
forma continua, sin abrir una terminal.

La v1 del CLI ya demostró que los datos son correctos y baratos de leer. Ahora
toca convertirlo en un servicio permanente y llevarlo al panel:

- daemon Rust read-only con socket Unix;
- SSE desde el backend con RBAC y ámbito de tenant;
- sección “En vivo” en la pestaña **Recursos**.

No se añade histórico, Prometheus ni cuota de disco.

## WHAT

**El binario `spanel-cell-metrics` gana un modo `--serve` que escucha en un
socket Unix, autentica por token y credenciales de par, y transmite samples JSON
por línea; el backend expone un endpoint SSE con ámbito de tenant; y la pestaña
Recursos muestra los valores actuales y una sparkline de los últimos 60 samples,
reconectando si se cae el stream.**

El CLI de 0112 sigue funcionando igual.

## SCOPE

### A. Daemon Rust (`apps/cell-metrics`)

- Nuevo modo:

  ```text
  spanel-cell-metrics --serve \
    --socket /run/spanel/cell-metrics.sock \
    --token-file /run/secrets/cell_metrics_token \
    --allowed-uids 0 \
    [--cgroup-root /sys/fs/cgroup] \
    [--passwd /etc/passwd]
  ```

- El modo sin `--serve` conserva el CLI de 0112 (`--once`, `--watch`, etc.).
- Escucha **solo** en `AF_UNIX`; jamás TCP.
- Crea el socket con permisos `0600` (o `0660` si se configura un grupo) y
  elimina un socket huérfano al arrancar.
- `--allowed-uids`: lista separada por comas de uids de peer permitidos
  (`SO_PEERCRED`). Por defecto `0`.
- `--token-file`: fichero 0600 con el token compartido. Se lee al arrancar y se
  compara en tiempo constante.
- Resuelve el uid de la celda desde `<passwd>` (`/etc/passwd`) buscando el
  usuario `spanel-<slug>`. No parsea `registry.json`.
- Protocolo de texto por línea, sin framing binario y sin parser JSON de
  entrada:

  ```text
  SUBSCRIBE <slug> <interval_ms> <token>\n
  SNAPSHOT <slug> <token>\n
  PING\n
  ```

  Respuestas:
  - `SUBSCRIBE`: una línea JSON por sample, hasta que el cliente cierre.
  - `SNAPSHOT`: una línea JSON y cierre.
  - `PING`: `{"ok":true,"pong":true}\n`.
  - Error: `ERROR <code> <message>\n` y cierre.
- Valida slug, intervalo (250–60000), token y uid resuelto antes de abrir
  cgroups. Un slug con caracteres raros nunca se interpola en rutas.
- Cada conexión tiene su propio `Sampler`; no se comparte estado entre clientes
  en v1. El coste es una lectura de cgroups por segundo y cliente; suficiente
  para el panel. Una caché compartida queda para más adelante.
- Solo lectura: no escribe cgroups, no ejecuta comandos, no abre red.
- El JSON de cada línea es exactamente el de 0112 (mismos campos y semántica).
- Unidad systemd de referencia `apps/cell-metrics/spanel-cell-metrics.service`:
  - `User=root` con `CapabilityBoundingSet=` vacío (solo lectura de cgroups).
  - `ProtectSystem=strict`, `ProtectHome=read-only`,
    `ProtectControlGroups=yes`, `PrivateTmp=true`, `NoNewPrivileges=true`,
    `RestrictAddressFamilies=AF_UNIX`, `MemoryMax=64M`, `CPUQuota=10%`.
  - `Restart=on-failure`, `RestartSec=2`.
  - `ExecStart` apunta a `/usr/local/bin/spanel-cell-metrics` y al token
    configurado por el operador.

### B. Cliente backend y SSE

- Nuevo módulo `vendor/systutor-core/plugins/tenant/backend/metrics_client.py`:
  - abre el socket Unix, envía `SUBSCRIBE <slug> <interval_ms> <token>`, lee
    líneas JSON y las expone como iterador;
  - timeouts acotados, errores tipados (`MetricsUnavailable`, `MetricsDenied`,
    `MetricsProtocolError`);
  - no calcula métricas ni toca cgroups;
  - configuración por entorno:
    - `SPANEL_CELL_METRICS_SOCKET` (defecto `/run/spanel/cell-metrics.sock`);
    - `SPANEL_CELL_METRICS_TOKEN_FILE` (defecto `/run/secrets/cell_metrics_token`);
    - `SPANEL_CELL_METRICS_TIMEOUT` (defecto 5 s).
- Nuevo router `metrics_router.py` en el plugin tenant:
  - `GET /api/v1/plugins/tenant/tenants/{tenant_id}/metrics/stream?interval_ms=1000`;
  - ámbito de tenant: cualquier usuario autenticado puede abrir el stream de
    su propio tenant; solo el administrador de plataforma puede abrir el de
    otro tenant;
  - resuelve el `slug` del tenant en PostgreSQL;
  - responde `503 tenant.metrics_unavailable` si el daemon no está disponible
    antes de abrir el stream;
  - respuesta `text/event-stream` con:
    - `retry: 3000`;
    - `data: <json>\n\n` por muestra;
    - `event: error\ndata: {...}\n\n` y cierre si el daemon falla a mitad;
    - cabeceras `Cache-Control: no-cache`, `X-Accel-Buffering: no`,
      `Connection: keep-alive`;
  - el generador cierra el socket al desconectarse el cliente;
  - no hay keepalive artificial: un sample por segundo mantiene viva la conexión.
- `register.py` incluye el router.
- El contenedor de la app necesita montar el socket y el token (solo lectura).
  La unidad de despliegue y el compose del lab deben reflejarlo; no se publica
  ningún puerto nuevo.

### C. UI: sección “En vivo” en Recursos

- En `TenantResourcePlanPanel`, debajo del plan, una sección **En vivo**:
  - indicador de conexión: `En vivo`, `Reconectando…`, `Sin conexión`;
  - RAM actual / límite y porcentaje;
  - CPU actual / límite y porcentaje;
  - PIDs actuales / límite;
  - presión CPU/RAM/IO (`some avg10`);
  - I/O de lectura/escritura por segundo;
  - hora del último sample;
  - dos sparklines SVG de los últimos 60 samples (CPU % y RAM %), sin librerías
    nuevas.
- Hook `useCellMetrics(tenantId)`:
  - usa `fetch` con `Authorization: Bearer <token>` (EventSource no permite
    cabeceras);
  - lee `response.body` con `ReadableStream`, parsea eventos SSE por `\n\n` y
    líneas `data:` usando helpers puros en
    `apps/web/src/plugins/tenant-metrics.logic.ts`;
  - mantiene un ring buffer de 60 samples;
  - reconecta con backoff (1 s, 2 s, 5 s, 10 s) mientras el componente esté
    montado y el usuario tenga permiso;
  - cancela con `AbortController` al desmontar o cambiar de tenant.
- La sección es solo de lectura; no cambia el plan ni los límites.
- Si el stream no está disponible, muestra un aviso discreto y el resto de la
  pestaña sigue funcionando.
- i18n en `apps/web/src/i18n/es/tenant.ts`.
- Sin uso de disco: el almacenamiento sigue siendo un valor declarado y su
  medición real queda fuera.

### D. Pruebas

- Rust:
  - protocolo `SNAPSHOT`/`SUBSCRIBE`/`PING` con un socket y un árbol cgroup
    falsos;
  - token inválido → `ERROR unauthorized`;
  - uid no permitido → `ERROR peer_denied`;
  - slug inválido, intervalo fuera de rango y usuario `spanel-<slug>` ausente;
  - el daemon no escribe cgroups y cierra al desconectar el cliente;
  - el CLI de 0112 sigue pasando.
- Backend:
  - `metrics_client` con un socket falso: framing, líneas, timeout y errores;
  - endpoint SSE con un cliente falso: `data:` múltiples, `event: error`,
    `503` sin daemon, ámbito de tenant y permiso;
  - tests de que el generador cierra el socket.
- Frontend:
  - parser SSE puro y ring buffer en `tenant-metrics.logic.ts` con vitest;
  - render de la sección con datos fake;
  - `npm test` y `npm run build`.
- E2E de laboratorio:
  - daemon real con socket y token;
  - app con el socket/token montados;
  - `curl -N` al endpoint SSE durante 5 s con carga de CPU en la celda;
  - comprobar varias líneas `data:` con valores distintos, RAM/CPU/PIDs y
    límites correctos;
  - UI servida con los textos nuevos;
  - artefacto `artifacts/0113-cell-metrics-live-e2e.json`.

## OUT OF SCOPE

- Histórico persistente, Prometheus, Grafana, alertas o retención.
- eBPF, perf, ftrace o atribución por proceso/contenedor.
- Medición de espacio ocupado en disco (`du`), cuotas o project quotas.
- Aplicar o verificar límites; el plan agent sigue siendo el único que muta.
- Acceso de tenant admin a métricas de otros tenants.
- WebSocket; SSE es suficiente.
- Nuevos puertos publicados o exposición directa del socket fuera del host.
- Dependencias externas de Cargo o de Python.
- Cambiar la API de planes, el plan agent, Hosting, Filemanager, Core o
  producción.

## CONTRACT

**Precondiciones**:

- binario Rust compilado con el modo `--serve`;
- socket Unix y token compartido accesibles por el daemon y la app;
- la app tiene montados el socket y el token en solo lectura;
- usuario de plataforma con `tenant.tenants.manage`;
- celda en `/etc/passwd` como `spanel-<slug>`.

**Postcondiciones**:

1. `spanel-cell-metrics --serve` escucha en el socket Unix, rechaza TCP y valida
   token y uid de peer.
2. `SNAPSHOT` devuelve un JSON de 0112 y cierra; `SUBSCRIBE` devuelve una línea
   por intervalo hasta que el cliente cierre; `PING` responde.
3. `GET .../metrics/stream` devuelve `text/event-stream` con un `data:` por
   sample y el `slug` correcto del tenant; sin daemon responde 503.
4. La sección **En vivo** muestra RAM, CPU, PIDs, presión e I/O, se actualiza y
   reconecta; no muestra almacenamiento.
5. El CLI de 0112 y el plan de 0111 no cambian de comportamiento.
6. El daemon no escribe cgroups, no abre red y no ejecuta comandos.
7. Al desmontar la UI o cortar el cliente, el backend cierra el socket y el
   daemon termina el sampler de esa conexión.

## INVARIANTS

```yaml
invariants:
  - "El daemon de métricas es de solo lectura: no escribe cgroups ni ficheros de estado."
  - "El socket es AF_UNIX; no se abre ningún puerto TCP."
  - "Token + SO_PEERCRED + allowlist se validan antes de abrir cgroups."
  - "Slug, interval_ms y uid se validan; nunca se interpolan rutas sin validar."
  - "El JSON de cada sample conserva el contrato de 0112."
  - "La API SSE permite el tenant propio a cualquier usuario autenticado y reserva el resto al ámbito de plataforma."
  - "La UI se conecta con Authorization; no se usa EventSource sin cabeceras."
  - "La UI cancela el stream al desmontar y reconecta con backoff acotado."
  - "No se mide almacenamiento ni se introducen cuotas."
  - "El plan agent y la API de planes no cambian."
  - "No se tocan Core, Traefik, MariaDB, phpMyAdmin, PowerDNS, Mailserver ni producción."
```

## VERIFICATION

```bash
# Rust
cd apps/cell-metrics
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test

# Backend
cd ../..
PYTHONPATH=vendor/systutor-core:. python3 -m pytest \
  vendor/systutor-core/plugins/tenant/backend/tests/test_metrics_client.py \
  vendor/systutor-core/plugins/tenant/backend/tests/test_metrics_stream.py -q

# Frontend
cd apps/web && npm test && npm run build

# Laboratorio (con el daemon y la app configurados)
curl -N -H "Authorization: Bearer <jwt>" \
  "http://127.0.0.1:3000/api/v1/plugins/tenant/tenants/<id>/metrics/stream?interval_ms=1000"
```

El E2E de laboratorio se guarda en
`artifacts/0113-cell-metrics-live-e2e.json` con el comando, las primeras
líneas SSE, la carga de CPU real, la UI servida y el Core intacto.

## ROLLBACK

- Parar y deshabilitar `spanel-cell-metrics.service`, retirar el montaje del
  socket/token del contenedor y revertir el router/UI.
- El CLI de 0112 sigue funcionando sin daemon.
- No hay esquema, datos ni límites que deshacer.
- El plan agent no se toca.

## Change Surface

```yaml
change_surface:
  allowed:
    - apps/cell-metrics/Cargo.toml
    - apps/cell-metrics/src/lib.rs
    - apps/cell-metrics/src/main.rs
    - apps/cell-metrics/README.md
    - apps/cell-metrics/spanel-cell-metrics.service
    - scripts/tests/test_cell_metrics_cli.py
    - vendor/systutor-core/plugins/tenant/backend/metrics_client.py
    - vendor/systutor-core/plugins/tenant/backend/metrics_router.py
    - vendor/systutor-core/plugins/tenant/backend/register.py
    - vendor/systutor-core/plugins/tenant/backend/tests/test_metrics_client.py
    - vendor/systutor-core/plugins/tenant/backend/tests/test_metrics_stream.py
    - vendor/systutor-core/plugins/tenant/frontend/api.ts
    - vendor/systutor-core/plugins/tenant/frontend/components/TenantResourcePlanPanel.tsx
    - apps/web/src/plugins/tenant-metrics.logic.ts
    - apps/web/src/plugins/tenant-metrics.logic.test.ts
    - apps/web/src/i18n/es/tenant.ts
    - aspecs/0113-live-cell-metrics-service-sse-ui.md
    - artifacts/0113-cell-metrics-live-e2e.json
  prohibited:
    - scripts/tenant_cell/**
    - vendor/systutor-core/plugins/apps/backend/**
    - vendor/systutor-core/plugins/hosting/backend/**
    - vendor/systutor-core/plugins/filemanager/backend/**
    - apps/web/src/features/auth/**
    - docker-compose.yml
    - scripts/phpmyadmin_up.sh
    - scripts/traefik-lab.sh
    - scripts/powerdns-lab.sh
    - /etc/systemd/**
    - /etc/fstab
    - /opt/stacks/**
```

## Blast Radius

```yaml
blast_radius:
  direct:
    - daemon de métricas y socket Unix
    - endpoint SSE del plugin tenant
    - sección En vivo de la pestaña Recursos
  indirect:
    - operación del panel en tiempo real
    - futura integración Prometheus/histórico
  must_not_affect:
    - plan agent y API de planes
    - CLI de métricas de 0112
    - límites cgroup y contenedores
    - Core y producción
```

## Composition

```yaml
composition:
  requires_aspecs:
    - "0111-tenant-resource-plan-ui-and-capacity"
    - "0112-live-cell-metrics-cli-rust-agent"
  must_compose_with:
    - "0108-rootless-userspace-ram-dry-run"
  systemic_invariants:
    - "El plan agent sigue siendo el único que muta límites."
    - "El colector no gana privilegios de escritura."
    - "La UI no usa EventSource sin Authorization."
  composition_checks:
    - "cd apps/cell-metrics && cargo test"
    - "PYTHONPATH=vendor/systutor-core:. python3 -m pytest vendor/systutor-core/plugins/tenant/backend/tests/test_metrics_client.py -q"
```

## Structural Constraints

```yaml
structural_constraints:
  primary_rule: una responsabilidad coherente y una razón principal de cambio
  entrypoints_must_stay_thin: true
  review_threshold_lines: 500
  extraction_threshold_lines: 800
  preferred_new_logic_locations:
    - apps/cell-metrics/src/lib.rs
    - vendor/systutor-core/plugins/tenant/backend/metrics_client.py
    - vendor/systutor-core/plugins/tenant/frontend/components/TenantResourcePlanPanel.tsx
```

## Traceability

- Requirement: métricas vivas de la celda en el panel; daemon Rust read-only,
  SSE con RBAC y gráfica en la pestaña Recursos.
- owner: lucas
- approver: lucas
- Evidence: `artifacts/0113-cell-metrics-live-e2e.json` (pendiente de la
  implementación y ceremonia en laboratorio).
- Deployment: laboratorio `spanel.lab`; sin producción.

## Definition of Done

- [x] Objetivo satisfecho
- [x] Scope respetado
- [x] Contrato satisfecho
- [x] Verdad falsable e independiente disponible ahora (SSE con samples reales)
- [x] Invariantes preservados
- [x] Verificación Rust/backend/frontend ejecutada
- [x] Rollback honesto (parar daemon, retirar montaje, revertir router/UI)
- [x] Checks de composición ejecutados
- [x] Sin cambios no relacionados
- [x] Restricciones estructurales respetadas
- [x] Trazabilidad establecida
- [x] E2E black-box en laboratorio con SSE y carga real
- [x] Core intacto
