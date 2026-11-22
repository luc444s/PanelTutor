# Reparar y desplegar plan agent + métricas de celda

Runbook para los tres síntomas que muestra la pestaña **Resources** de un
tenant:

| Síntoma | Causa | Sección |
| --- | --- | --- |
| «Could not read the host capacity» + «The plan agent is not responding» | El agente host desplegado no implementa `capacity` (se añadió en `e9dda25`, A.SPEC 0111) o el socket/token no llega al contenedor | 2, 5 |
| «This tenant does not have a resource plan yet» | Operación `plan_set` huérfana: el host tiene los límites, pero no existe fila en `apps_tenant_plans` | 3, 4 |
| «Live metrics · No connection» | `spanel-cell-metrics` no está instalado o el contenedor no monta su socket/token | 5 |

Todo se ejecuta como root en el host, desde `/opt/spanel` (el checkout de
producción). No se invoca Alembic ni se toca el esquema.

## 0. Precondiciones

```bash
cd /opt/spanel
git status --short            # debe estar limpio
git rev-parse --short HEAD    # anota el commit actual (rollback)
systemctl is-active spanel-plan-agent spanel-edge-relay
test -f /etc/spanel/plan_agent_token && echo "plan token ok"
docker compose ps
```

El contenedor monta `/var/lib/spanel` en solo lectura y encima los volúmenes
`apps_state` y `hosting_backups`. Docker exige que esos puntos de montaje
existan en el host (los volúmenes siguen viviendo en `/var/lib/docker/volumes`):

```bash
install -d -m 0755 /var/lib/spanel/apps /var/lib/spanel/hosting-backups
```

Guarda el SHA actual como `<SHA_ANTERIOR>`.

## 1. Desplegar el commit de la app

El fix de auditoría cross-tenant (`35f6064`) todavía no está en producción; sin
él, guardar el plan desde la UI vuelve a dejar la operación a medias.

```bash
cd /opt/spanel
git fetch origin
git checkout 35f6064
./scripts/deploy.sh app apps-worker
```

Comprueba que el contenedor arrancó:

```bash
docker compose ps app apps-worker
docker logs --tail 50 spanel-app-1
```

## 2. Actualizar el plan agent host

El binario del agente es el checkout de `/opt/spanel/scripts`; el commit nuevo
incluye el op `capacity`. Sin reiniciarlo, `/plan/capacity` seguirá en 503.

```bash
install -m 644 scripts/tenant_cell/deploy/spanel-plan-agent.service \
  /etc/systemd/system/spanel-plan-agent.service
# Sustituye <app-container-uid> solo si no es 0 (la imagen corre como root).
grep -n "ALLOWED_UIDS" /etc/systemd/system/spanel-plan-agent.service
systemctl daemon-reload
systemctl restart spanel-plan-agent
systemctl is-active spanel-plan-agent
```

Verifica el op `capacity` directamente contra el socket (solo lee). Lo más
fiable es hacerlo desde el propio contenedor, porque valida a la vez los
montajes, el token y el agente:

```bash
cd /opt/spanel
docker compose exec -T app python - <<'PY'
import os
from plugins.apps.backend.plans_client import HostPlanMaterializerClient

print("socket:", os.path.exists("/run/spanel/plan-agent.sock"))
print("token:", os.path.exists("/run/secrets/plan_agent_token"))
client = HostPlanMaterializerClient(
    "/run/spanel/plan-agent.sock", "/run/secrets/plan_agent_token"
)
print(client.capacity())
PY
```

Alternativa desde el host (registrando el módulo antes de ejecutarlo, porque
`plans_client` usa `dataclass`):

```bash
python3 - <<'PY'
import importlib.util
import sys

path = "/opt/spanel/vendor/systutor-core/plugins/apps/backend/plans_client.py"
spec = importlib.util.spec_from_file_location("plans_client", path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
client = module.HostPlanMaterializerClient(
    "/run/spanel/plan-agent.sock", "/etc/spanel/plan_agent_token"
)
print(client.capacity())
PY
```

Debe imprimir `memory_bytes`, `cpus`, `storage_bytes` y `read_at`. Si falla,
revisa `journalctl -u spanel-plan-agent -n 80 --no-pager` antes de continuar.

## 3. Cerrar la operación huérfana

El script solo cierra la operación exacta que le indiques y exige que siga
cumpliendo todas las guardas (kind `plan_set`, `queued`, sin `message_id`, sin
`finished_at`, más de 5 minutos idle). No encola nada ni toca el host.

```bash
python3 scripts/repair_plan_orphan.py --tenant miltonarquez
```

Debe listar la operación `23351f6b-89e3-4ccf-a979-2a255cfcf5cc` (o la que
aparezca) con `plan rows: 0`. Aplícala:

```bash
python3 scripts/repair_plan_orphan.py --tenant miltonarquez \
  --apply \
  --operation-id 23351f6b-89e3-4ccf-a979-2a255cfcf5cc \
  --confirm yes
```

Salida esperada: `closed: <id>` y un `next:` recordando volver a guardar el
plan. Si el script sale con código 3, la guarda rechazó la operación: vuelve a
listarla y **no** fuerces SQL a mano.

Referencia de lo que ejecuta (una sola sentencia con CTE y `RETURNING`):

```sql
UPDATE apps_operations o
SET status = 'interrupted', phase = 'done',
    error_code = 'apps_plan_operation_orphaned', finished_at = now()
FROM (SELECT id FROM apps_operations
      WHERE id = '<operacion>' AND kind = 'plan_set'
        AND subject_type = 'tenant_plan' AND status = 'queued'
        AND message_id IS NULL AND finished_at IS NULL
        AND created_at < now() - interval '300 seconds'
      FOR UPDATE) g
WHERE o.id = g.id
RETURNING o.id;
```

## 4. Volver a guardar el plan

En la UI, pestaña **Resources** del tenant: introduce los valores reales
(miltonarquez: 0,4 GiB de RAM, 0,5 CPU, 256 PIDs y el almacenamiento
acordado) y pulsa **Save plan**. La capacidad ya debe leerse en el paso 2, así que el botón
estará habilitado.

El guardado es idempotente: vuelve a aplicar los mismos límites en el host y
crea la fila `apps_tenant_plans` que faltaba. Debe quedar en estado `Applied`.

Verificación:

```bash
docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c \
  "SELECT tenant_id, memory_bytes, cpus, pids, status FROM apps_tenant_plans;"
```

## 5. Instalar métricas de celda y montar sockets

### 5.1 Daemon

```bash
python3 scripts/install_cell_metrics.py --check          # fotografía previa
python3 scripts/install_cell_metrics.py --dry-run        # revisa rutas/uid
python3 scripts/install_cell_metrics.py --slug miltonarquez
```

El instalador:

- compila `apps/cell-metrics` (`cargo build --release`);
- crea `/etc/spanel/cell_metrics_token` en modo `0600` y **no rota** tokens
  existentes;
- renderiza y activa `spanel-cell-metrics.service` con el uid del contenedor;
- verifica `PING` y, con `--slug`, un `SNAPSHOT` real de la celda.

### 5.2 Montajes del contenedor

`docker-compose.yml` ya declara los cuatro puntos de montaje y las variables
`SPANEL_*` que leen los plugins. Solo hay que asegurarse de que ambos tokens
existen en el host antes de recrear el contenedor:

```bash
install -d -m 0755 /etc/spanel /run/spanel
test -f /etc/spanel/plan_agent_token
test -f /etc/spanel/cell_metrics_token
./scripts/deploy.sh app
python3 scripts/install_cell_metrics.py --check           # app_mounts debe ser ok
```

Si `app_mounts` sigue en `FAIL`, revisa que `.env.docker` no esté sobrescribiendo
`SPANEL_AGENT_RUNTIME_DIR`, `SPANEL_PLAN_AGENT_TOKEN_PATH` o
`SPANEL_CELL_METRICS_TOKEN_PATH` con rutas inexistentes.

## 6. Verificación final

En la UI del tenant:

1. **Host capacity** muestra RAM/CPU/disco del host (sin alerta).
2. **Tenant plan** muestra el plan en `Applied`.
3. **Live metrics** pasa a `Live` en menos de ~2 s y dibuja las sparklines.

Por CLI:

```bash
systemctl is-active spanel-plan-agent spanel-cell-metrics
curl -sN -H "Authorization: Bearer <jwt>" \
  "https://<panel>/api/v1/plugins/tenant/tenants/<tenant-id>/metrics/stream?interval_ms=1000" \
  | head -n 3
```

Cada línea debe ser un `event: metrics` con `ts_ms`, `memory`, `cpu` y `pids`.

## 7. Hosting ("Could not load sites")

Si el listado de Hosting falla, normalmente es que el contenedor no ve el
registro de celdas o el dockerd de una celda rootless. El compose nuevo monta:

- `/var/lib/spanel` completo en solo lectura (el `registry.json` se reemplaza
  de forma atómica, así que montar solo el fichero dejaría datos obsoletos);
- `/var/lib/spanel/cells` con escritura (estado privado por uid de celda);
- `SPANEL_TENANTS_ROOTLESS=true` y `SPANEL_TENANTS_DATA_ROOT=/var/lib/spanel`.

Verificación tras recrear la app:

```bash
docker exec spanel-app-1 python - <<'PY'
import json
registry = json.load(open("/var/lib/spanel/registry.json"))
print(sorted(registry.get("allocations", {})))
PY

ls -l /var/lib/spanel/cells/miltonarquez/docker.sock
docker exec spanel-app-1 docker -H unix:///var/lib/spanel/cells/miltonarquez/docker.sock info --format '{{.ID}}'
```

La última orden debe devolver el ID del dockerd de la celda, no un error de
conexión. Si falla, revisa `journalctl -u user@60000` y que el socket exista en
el host.

## 8. Helper universal del file manager

Para sitios estáticos el filemanager usa un helper PHP. Antes se ejecutaba en
el dockerd de cada celda (`--volumes-from`), lo que descargaba una copia de
`wordpress:cli` por tenant y cargaba sus capas contra el plan de RAM del tenant.

Ahora, si el volumen de la celda es visible desde la app (lo es, porque
`/var/lib/spanel/cells` está montado), el helper se ejecuta **una sola vez en el
dockerd rootful** con el volumen montado por ruta del host:

```text
docker run --rm --network none --user 0:0 \
  -v /var/lib/spanel/cells/<slug>/volumes/<volumen>/_data:/data \
  --entrypoint php wordpress:cli -r <script> <payload>
```

Una imagen para todos los tenants; la caché de sus capas queda en el cgroup del
host. Los ficheros nuevos se `chown` al uid de la celda (60000), para que dentro
del namespace sigan apareciendo como root. Si la ruta no fuera accesible, el
código cae automáticamente al helper por celda.

Precarga única en rootful:

```bash
docker pull wordpress:cli
```

Y puedes liberar la copia antigua de la celda (ya no se usa):

```bash
docker -H unix:///var/lib/spanel/cells/<slug>/docker.sock rmi wordpress:cli
```

Verificación: sube un fichero y comprueba el propietario en el host:

```bash
ls -ln /var/lib/spanel/cells/miltonarquez/volumes/*/_data | head
```

Debe aparecer `60000 60000`, y el `memory.current` del user manager debe dejar
de crecer por capas de imagen.

## Rollback

1. Métricas: `systemctl disable --now spanel-cell-metrics`, retira el token y
   vuelve a `./scripts/deploy.sh app` sin los montajes (revierte
   `docker-compose.yml`). El resto del panel sigue funcionando: el SSE vuelve a
   fallar cerrado con 503.
2. Plan: el plan aplicado es idempotente; si hay que retirarlo, usa **Delete
   plan** en la UI (no borres la fila a mano).
3. App: `git checkout <SHA_ANTERIOR> && ./scripts/deploy.sh app apps-worker`.
4. Agente: `git checkout <SHA_ANTERIOR>` y reinstala/reinicia la unidad. El op
   `capacity` desaparece y la UI vuelve a mostrar la alerta de capacidad, pero
   los planes ya aplicados no se pierden.
