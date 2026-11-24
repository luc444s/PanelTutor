# A.SPEC 0115 — Alta de tenant con celda y plan obligatorios

## WHY

El alta pública de tenants crea hoy la organización y su usuario base, pero no
crea la celda rootless ni asigna un plan. Esto permite tenants sin recursos y
obliga a completar el alta manualmente con operaciones separadas.

## WHAT

`POST /api/v1/plugins/tenant/tenants` exige RAM, CPU, PIDs y almacenamiento,
provisiona la celda rootless y aplica el plan antes de confirmar el tenant.

## CONTRACT

- `resource_plan` es obligatorio y contiene `memory_bytes`, `cpus`, `pids` y
  `storage_bytes`, todos mayores que cero.
- La celda usa el slug canónico derivado del slug del tenant.
- El host agent expone una operación acotada `provision`, autenticada con la
  capability existente y sin aceptar rutas, UIDs ni nombres de unidades.
- El alta solo confirma tenant, usuario y plan si la celda y el plan se aplican.
- La sobreventa continúa permitida según A.SPEC 0111.
- Un reintento converge sobre una celda parcialmente o totalmente provisionada.
- El formulario de alta exige los cuatro límites y envía una sola petición.

## VERIFICATION

- Tests de esquema, protocolo host y endpoint de creación.
- Build del frontend.
- E2E black-box en lab usando exclusivamente la API pública: crear tenant,
  consultar su plan, comprobar estado `applied` y verificar la celda/cgroup.

## INVARIANTS

- PostgreSQL sigue siendo la fuente de verdad del plan.
- El backend no ejecuta comandos privilegiados; usa el UDS del agente.
- No se invoca Alembic directamente ni se requiere migración de esquema.
- El almacenamiento sigue siendo declarado, no una cuota de kernel.
