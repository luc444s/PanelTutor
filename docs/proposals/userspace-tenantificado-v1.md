# userspace tenantificado desde spanel — v1 (plan)

> Documento de planificación, **no es una A.SPEC**. Estado: **aprobado con correcciones
> (2026-11-18)**. Basado en `vendor/systutor-core/`, `scripts/tenant_cell/` y en los
> artifacts/experimentos de A.SPEC 0100–0106.

## 0. Correcciones aprobadas (2026-11-18)

El usuario aprobó el plan condicionado a estas correcciones, que son **parte del contrato
de la v1**:

1. **GAP-1: prohibido reparentar `user@UID.service`.** Aplicar `MemoryMax`, `CPUQuota` y
   `TasksMax` con `systemctl set-property` sobre la unidad existente, conservando el slice
   por defecto y `OwnerUID`. Validar límites efectivos con cgroups v2 y carga real. 0109 y
  0110 quedan **bloqueados** hasta que 0108 pase el E2E black-box. Aceptación: contenedor
   rootless arranca, conserva aislamiento y respeta cuotas sin `EPERM`.
2. **Persistencia del runtime y rollback por aplicación.** La bandera global **no** es el
   único mecanismo: cada sitio/despliegue conserva su runtime (`rootful`|`rootless`) y los
   recursos existentes se resuelven por su runtime registrado. La bandera solo habilita
   **nuevas** migraciones. El rollback restaura rutas y runtime. No se eliminan contenedores
   rootful hasta confirmar migración y recuperación de datos. `migrate --all` es secuencial,
   con `dry-run`, excluye Core y se detiene ante el primer fallo. Aceptación: apagar la
   bandera no hace perder la administración de lo ya migrado.
3. **phpMyAdmin global — APROBADO.** Una única instancia global administrada por Core, con
   su hardening actual, `PMA_ARBITRARY=1`, tickets y controles de acceso. Sin PMA por
   tenant, sin migrarlo a rootless, sin debilitar su seguridad. Las DBs rootless nuevas
   entran por el mecanismo de conectividad autorizado. Aceptación: PMA administra DBs
   autorizadas de tenants rootless sin acceso cruzado.
4. **Backups y consistencia obligatorios antes del cutover.** Aunque el motor de backups
   quede fuera del alcance de 0110, su verificación es obligatoria para servicios con
   estado: backups consistentes de DBs y volúmenes, restauración verificada, recursos
   rootful originales retenidos durante la ventana de rollback, sin escrituras simultáneas
   no coordinadas, verificación UID/GID y persistencia, y política explícita para
   escrituras posteriores al cutover. Aceptación: WP migra y se recupera sin pérdida.
5. **Correo: separar Core y tenant.** Docker Mailserver **no** se traslada a celdas
   rootless ni a cgroups. Los recursos del mailserver compartido se diferencian de las
   cuotas RAM/CPU de cada tenant. El mínimo para tenants con correo es un **mínimo
   comercial/contractual**, no un recurso físicamente garantizado salvo que exista un
   mecanismo de reserva comprobado. Los límites de las apps del tenant no pueden caer el
   correo centralizado ni el de otros clientes. Aceptación: un tenant agota su cuota sin
   afectar al mailserver ni a otros tenants.

### Condiciones generales de ejecución

- `SPANEL_TENANTS_ROOTLESS=false` por defecto hasta validación E2E.
- Migración inicial: **página estática → WordPress propio → lotes controlados**.
- PanelTutor Core conserva su capacidad privilegiada de administración.
- Traefik permanece en la red `proxy`; el relay TCP conecta Traefik con las celdas rootless.
- MariaDB compartida, phpMyAdmin, PowerDNS y Docker Mailserver permanecen como
  infraestructura Core.
- No reintroducir hardening invasivo sobre Dockerfiles ni código de aplicaciones.
- Cada A.SPEC incluye tests, E2E black-box y rollback verificable.
- **Regla principal:** migrar las apps de los tenants sin comprometer la infraestructura
  Core ni perder la capacidad de administración de PanelTutor.

## 1. Objetivo y requerimientos

"Primera versión de userspace tenantificado desde spanel": que todo lo que un tenant
administra (WP, estáticos, apps) se ejecute dentro de su **userspace rootless** con daemon
Docker propio, AppArmor, seccomp, límites de RAM y rutas publicadas, sin perder la
capacidad del panel de **ver y gestionar** esos contenedores.

| # | Requerimiento | Aclaración |
|---|---|---|
| 1 | Userspaces rootless con daemon propio, AppArmor, límites, dry-run, compatibilidad visual | **RAM**, no VRAM. Visual = spanel ve/modifica/agrega/quita contenedores del tenant. |
| 2 | Apps rootful → rootless | Deploy apunta al `docker.sock` de la celda; estado persistido por despliegue. |
| 3 | WP/estáticos → rootless + PMA | PMA global único y generalista (corrección 3). |
| 4 | Crear dentro del tenant limitado | La creación nace en la celda con el plan de RAM aplicado. |
| 5 | Sitios con correo, recursos mínimos | Mínimo **contractual**, mailserver y su cgroup se quedan en Core (corrección 5). |

## 2. Estado real del código (hechos verificados)

| Tema | Hoy | Referencia |
|---|---|---|
| Identidad tenant | `Tenant.slug`, `site_suffix`, dominios en PostgreSQL | `kernel/tenants/models.py:20`, `plugins/tenant/backend/models.py:20-58` |
| uid / userns / slice | No está en BD; vive en `/var/lib/spanel/registry.json` y en el host | `apps/backend/runtime/tenant_runtime.py:138-166` |
| Celda rootless | Usuario + subuid/subgid + dockerd rootless + `docker.sock` + AppArmor invertido + seccomp + relay | `scripts/tenant_cell/{cells,executor,apparmor,network,relay,plans}.py` |
| Apps en producción | Rootful: `AppsWorker` sin `runtime_registry` | `apps/backend/tasks.py:39-42`, `worker.py:162-177` |
| Plan de tenant | Implementado, pero el materializador reparenta y rompe runc (GAP-1) | `scripts/tenant_cell/materializer.py:105-147`, `artifacts/0105-gap1-rootless-detection-experiment.json` |
| Límite RAM que funciona | `systemctl set-property` en el slice por defecto: `MemoryMax`, `CPUQuota`, `TasksMax` | experimento GAP-1, `fallback_setproperty_in_place`: PASS |
| Hosting | Rootful por diseño; contenedores `spanel-<slug>-wp/-db/-web` | `hosting/backend/provisioner.py:103-257`, `static.py:134-248` |
| phpMyAdmin | Global, `PMA_ARBITRARY=1`, proxy por tenant con tickets | `scripts/phpmyadmin_up.sh`, `hosting/backend/phpmyadmin_proxy.py` |
| Runtime por recurso | **No existe**: no hay campo que diga dónde corre cada sitio/app | — |
| Ver contenedores | No existe vista; hoy solo dominio publicado (relay → Traefik, 0104/0106) | `apps/backend/rootless_routes.py`, `domains/backend/publisher.py` |
| RAM | No hay VRAM/GPU; el plan ya tiene `memory_bytes`, `cpus`, `pids`, `cpuset` | `apps/backend/schemas.py:372-392` |
| dry-run | Solo en el deploy de apps; no en provisión, planes ni migración | `apps/backend/runtime/types.py:222` |

## 3. Decisiones de diseño

1. **RAM, no VRAM.** Se reutiliza `memory_bytes`; sin GPU/VRAM en v1.
2. **Runtime registrado por recurso (corrección 2).** Nueva tabla del plugin `tenant`:
   `tenant_resource_runtimes` con `(tenant_id, kind, resource_id) → runtime`. Los
   providers de `apps` y `hosting` inventarían los recursos; el runtime se resuelve desde
   esa tabla. Sin fila ⇒ `rootful` (verdad actual). La bandera global solo habilita
   migraciones **nuevas**; nunca decide dónde está un recurso ya registrado.
3. **uid/slice sigue en el registry del host** (no se añaden columnas en BD en v1); se
   consulta de forma acotada por el agente UDS.
4. **Límites vía `set-property`, sin reparentar** (corrección 1). Coste honesto: se pierde
   la agregación rootful+rootless en un mismo slice; se conserva el límite rootless.
5. **Rollout con bandera** `SPANEL_TENANTS_ROOTLESS=false` por defecto; cada spec lleva su
   propia bandera de rollback y su E2E black-box.
6. **PMA global y generalista** (corrección 3), sin cambios a su hardening.
7. **Backups verificados antes de cada cutover con estado** (corrección 4); el motor de
   backups sigue siendo Core.
8. **Correo en Core** (corrección 5): DMS no se mueve a celdas ni a cgroups; el mínimo de
   correo es contractual y se presenta como tal.
9. **Una verdad falsable por A.SPEC**, con tests + E2E black-box + rollback demostrado.

## 4. Secuencia de A.SPECs

```text
0107 Runtime por recurso + inventario/control del tenant   ← ESTA ENTREGA
          │  (compuerta de visibilidad y administración)
          ▼
0108 Materialización userspace con RAM y dry-run (fix GAP-1, set-property)
          │  (compuerta dura: sin E2E black-box verde no se migran 0109/0110)
          ▼
0109 Apps → daemon rootless (persistiendo runtime por despliegue, rollback por app)
          ▼
0110 Hosting WP/estáticos → rootless + PMA global + backups/consistencia
          ▼
0111 Creación en userspace limitado + mínimo contractual de correo (Core intacto)
```

### A.SPEC 0107 — Runtime por recurso e inventario de contenedores del tenant

Ver `aspecs/0107-tenant-resource-runtime-and-inventory.md` (documento de contrato).

- **Verdad:** todo recurso de un tenant tiene un runtime registrado y spanel lo lista y
  gestiona **por ese runtime**, sin exponer `docker.sock` y sin tocar infraestructura Core.
- **Incluye:** tabla `tenant_resource_runtimes`, providers de apps/hosting, API
  `GET /tenants/{id}/resources` + acciones con `dry_run`, UI "Recursos" en el detalle del
  tenant, tests y E2E black-box.
- **Rollback:** bandera `SPANEL_TENANT_RESOURCE_INVENTORY=false` + downgrade de la
  migración 004 ejecutado en VERIFICATION.

### A.SPEC 0108 — Materialización de userspace con RAM y dry-run

- Aplica `set-property` sin reparentar; conserva `OwnerUID`; verifica límites efectivos con
  cgroups v2 y carga real; E2E black-box (contenedor arranca, sin `EPERM`).
- Añade `migrate --all`: secuencial, `dry-run`, exclusión de Core, detención ante fallos.
- **Bloquea 0109 y 0110** si el E2E no pasa.

### A.SPEC 0109 — Apps → daemon rootless

- Inyecta `TenantRuntimeRegistry` en producción. Cada app/despliegue persiste su runtime;
  apagar la bandera no pierde lo migrado. Rollback restaura rutas + runtime, sin borrar
  contenedores rootful hasta confirmar recuperación.
- Criterio E2E simple (definido por el usuario): software para editores en un tenant de
  **512 MB / 1 núcleo**, revisar HTTP 200 y, tras aplicar estrés dentro del tenant, exigir
  que el estrés quede aislado (Core y otros tenants intactos) para dar PASS.
- Impacto en scripts de operador: ver §6 — **`app_deploy.py` será distinto**.

### A.SPEC 0110 — WP/estáticos → rootless + PMA global + consistencia

- Orden: estática → WP propio → lotes. Backups consistentes y restauración verificada
  antes del cutover; retener rootful durante rollback; sin escrituras no coordinadas;
  UID/GID y persistencia verificados. PMA global alcanza las DBs nuevas por el mecanismo
  autorizado, sin tocar su hardening.

### A.SPEC 0111 — Creación limitada + mínimo contractual de correo

- Crear nace dentro del userspace con RAM aplicada. Tenants con correo tienen un mínimo
  **contractual** en el plan (nunca presentado como garantía física sin reserva real).
  DMS, MariaDB compartida, PMA, PowerDNS y Traefik siguen en Core.

## 5. Riesgos y condiciones de éxito

- **Riesgo mayor (compuerta):** GAP-1. Si 0108 no demuestra `OwnerUID` + contenedor vivo
  con cuotas efectivas, **no se migran** apps ni hosting.
- **Riesgo de administración:** si 0107 no registra el runtime por recurso, apagar la
  bandera dejaría recursos rootless inadministrables (corrección 2).
- **Riesgo de datos:** sin backups verificados no se hace cutover de servicios con estado
  (corrección 4).
- **Éxito v1:** tenant con WP + estático + app, todo rootless, RAM efectiva, visible y
  gestionable desde spanel, PMA global alcanzando su DB, mínimo contractual de correo,
  Core intacto, banderas reversibles, producción intacta.

## 6. Impacto en scripts de operador

La 0109 **no modifica ni depreca scripts por contrato** (su `change_surface` no incluye
`scripts/**`), pero el comportamiento no es uniforme:

| Script | Ruta que usa | Efecto de la v1 |
|---|---|---|
| `scripts/spanel_apps.py` | API `/api/v1/plugins/apps` | Sin cambios: hereda el runtime rootless automáticamente, porque pasa por el worker. |
| `scripts/e2e_apps_*.py` (los que usan API) | API | Sin cambios funcionales; pueden añadir asserts de que el socket es el de la celda. |
| **`scripts/app_deploy.py`** | importa `apps.backend.runtime` y construye `Runner(transport)` **directamente** | **Será distinto.** Hoy es un escape hatch rootful que se salta el worker y el registry. Deja de ser la vía de creación directa: se le dará el `docker.sock` de la celda del tenant **o** se limitará a auditoría/depuración y se deprecará para creación. Decisión de alcance pendiente (spec de cierre). |
| `scripts/configure_apps.py`, `configure_apps_release_key.py` | configuración/secretos | Sin cambios. |
| `scripts/tenant_cell/*` (CLI `spanel-tenant`) | host rootless (0108) | Sin cambios; ya es la herramienta del userspace. |
| `scripts/benchmark_domains_global.py`, `scripts/e2e_apps_software_editores.py` | runtime directo, solo pruebas | No son rutas de creación del panel; sin cambios. |

**Consecuencia:** desde el panel (API) "crear app" ya nace en sandbox con 0109. Para que
también sea así desde CLI de operador hay que cerrar explícitamente el caso
`app_deploy.py`; queda registrado aquí como trabajo pendiente, no como efecto colateral
silencioso.

## 7. Estado

- Correcciones incorporadas. A.SPEC 0107 redactada, ejecutada con GENERATOR
  (`openai/gpt-5.6-sol#medium`) y verificada: 79 tests + ruff + tsc PASS, y E2E black-box
  en laboratorio **PASS 7/7** (`artifacts/0107-tenant-resource-runtime-e2e.json`),
  incluyendo dry-run sin mutación, aislamiento por tenant, independencia de la bandera,
  downgrade ejecutado e infraestructura Core intacta (PID/hashes sin cambios).
- 0107 commiteada y pusheada: `8ad6861` + `6398c0f` (trazabilidad).
- 0108 ejecutada con GENERATOR (`gpt-5.6-sol#medium`, reparación incluida) y verificada:
  17 tests + ruff PASS y E2E black-box en laboratorio **PASS 8/8**
  (`artifacts/0108-rootless-userspace-ram-dry-run-e2e.json`). OwnerUID y slice preservados,
  RAM efectiva en cgroups v2 bajo carga, contenedor sin EPERM, dry-run sin mutación,
  `migrate --all` secuencial con DMS excluido y rollback con `systemctl revert`.
  **Compuerta abierta: 0109 y 0110 ya pueden ejecutarse.**
- 0108 commiteada y pusheada: `5d88462` (implementación + reparación de 3 gaps de E2E)
  y `2e118f3` (trazabilidad).
- 0109 ejecutada con GENERATOR (`gpt-5.6-sol#medium`) y reparada por **0109-R**.
  - E2E inicial en `spanel.lab`: FAIL 3/5, pero la compuerta del usuario (estrés aislado)
    **PASS** (`artifacts/0109-apps-rootless-sandbox-e2e.json`); el deploy por API falló por
    falta de red en la celda.
  - Black-box contra `spanel.app` (corregido después a `spanel.lab`): BLOCKED por 409 al
    crear tenant (`artifacts/0109-spanel-app-e2e.json`).
  - Causa raíz del 409 diagnosticada en el lab: `users.is_superadmin` NOT NULL sin DEFAULT
    (drift de esquema); 0109-R añade la migración del kernel, DNS/NAT en la celda y plan
    público de RAM.
  - **E2E black-box final: PASS 9/9, `cleanup_verified: true`**
    (`artifacts/0109-spanel-lab-blackbox-e2e.json`): tenant 201, editor HTTP 200 vía
    relay/Traefik, 2 GB efectivos, socket de celda, Core intacto, limpieza total.
    7 gaps de laboratorio documentados (ver artefacto): cap 512 MB por servicio, NAT
    adicional, AppArmor de build, worker dramatiq, catálogo GitHub tenant-scoped, etc.
  - Pendiente: commit de 0109 + 0109-R sobre `remove-hardener`.

## 8. Post-0109: retirar los controles compensatorios anti-root

**Decisión condicional del usuario:** si la E2E de 0109 pasa (editor en sandbox rootless
con estrés aislado), entonces debemos **quitar todo límite que la app imponía para
contener el root**: el rechazo de binds de host y la prohibición de `docker.sock` en
inyecciones (`apps/backend/runtime/types.py`, `releases/verify.py`), la detección de
`rootful_socket` en probes (`runtime/probes.py`) y los defaults compensatorios
(`cap_drop: ALL`, `no-new-privileges`, `apparmor=docker-default`, seccomp) cuando el
recurso corre dentro de su propio userspace rootless con AppArmor invertido, seccomp
fail-closed y cgroups propios (0105/0108).

**Racional:** con un daemon rootless por tenant, el «root» dentro del contenedor es el
subuid del tenant, no root del host. La frontera la pone el userspace, no el Dockerfile;
mantener esos parches después sería hardening invasivo redundante, que las condiciones
generales de esta v1 prohíben.

**No ejecutar ahora.** Requiere: (1) E2E de 0109 en PASS, (2) hosting migrado (0110) y
creación por defecto (0111), y (3) una A.SPEC propia de cierre (0112) con
`change_surface` explícita, tests, E2E y rollback. Hasta entonces los controles siguen
vigentes para cualquier recurso rootful que quede.
