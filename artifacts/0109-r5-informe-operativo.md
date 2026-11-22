# Informe de cierre operativo — Apps (A.SPEC 0109-R5)

Fecha: 2026-11-20
Ámbito: cierre operativo de Apps acordado con el usuario (punto 2)
Resultado: **PASS** — 6/6 drills operativos + deploy/plan + limpieza verificada
Evidencia: `artifacts/0109-r5-operations-e2e.json` (`ok: true`, `result: PASS`)
Commit de la base operativa: `3aaee3a`

## 1. Qué se cerró

Además del E2E funcional R4 (4/4 checks, downgrade 005 y limpieza), se
ejecutaron los drills que faltaban para considerar Apps operable:

| Drill | Resultado | Evidencia |
|---|---|---|
| Dos deploys concurrentes de la misma app | PASS | uno aceptado; el otro `409 Application already has an active operation`; app sana y 3 contenedores |
| Reinicio del worker a mitad de deploy | PASS | operación `interrupted`, app conserva el deployment activo, 3 contenedores `healthy` |
| Soak acotado + retención | PASS | 3 ciclos; `keep=2`; 2 releases finales; 15.9 MB estables por ciclo |
| OOM dentro de la celda | PASS | contenedor de 64 MiB con `OOMKilled=true`, exit 137; servicios de la app intactos |
| Ruta HTTPS | PASS | `websecure` + TLS/redirect en el YAML; HTTP → `301` |
| Backup/restore operativo | PASS | `pg_dump` 3.9 MB; conteos `122|104|1` idénticos; árbol de releases restaurado |
| Plan 2 GiB + deploy | PASS | 3 servicios, plan aplicado (R4) |

La corrida se hizo sobre `e2e0109r5ops5`, con BD clonada, celda rootless real,
API/worker/Redis, plan-agent y edge-relay desechables, y el fixture real
`luc444s/software-de-gestion-para-editores@feature/workflow-diseno`
(`ae33f9d1…`).

## 2. Fallos reales encontrados y corregidos

### 2.1 Heartbeat y fork de Dramatiq

El drill de reinicio dejó una operación `running` para siempre. La causa fue un
`psycopg.errors.DuplicatePreparedStatement` en el hilo de heartbeat: Dramatiq
hace fork después de construir los engines y el hijo heredaba conexiones del
padre con los mismos nombres de prepared statements.

Corrección:

- `tasks.py` registra `os.register_at_fork(after_in_child=...)` y hace
  `engine.dispose(close=False)` sobre el pool del worker y el de la app.
- El heartbeat vuelve a funcionar tras el fork.

### 2.2 Operaciones huérfanas

No había reconcile periódico; el `_recover()` de arranque solo miraba
operaciones con heartbeat mayor a 300 s y no se repetía.

Corrección:

- Hilo `apps-reconcile` cada 15 s (ajustable por
  `SPANEL_APPS_RECONCILE_STALE_SECONDS`, por defecto 300 s).
- Una operación sin heartbeat pasa a `interrupted`, se limpia
  `active_operation_id` y la app mantiene el deployment anterior.
- El drill acepta `interrupted` como estado terminal honesto; no se inventa un
  auto-retry.

### 2.3 Retención de releases

No existía poda: cada deploy dejaba un árbol nuevo.

Corrección:

- `releases/retention.py`: keep-N por aplicación, preservando el deployment
  activo y los que están en `building`.
- Poda del árbol desplegado (`<project>/releases/<id>`).
- Poda del store firmado (`hardened/<tenant>/<app>/<digest>`) con ventana de
  gracia (`SPANEL_APPS_RELEASE_GRACE_SECONDS`, 1 h por defecto).
- El E2E operativo valida el árbol desplegado (`keep=2`, 2 releases estables);
  el store firmado está cubierto por el test unitario de retención.

## 3. Gates

| Gate | Resultado |
|---|---|
| Core suite | **153 passed** |
| Apps + Domains | **584 passed** |
| Frontend tests | **56 passed** |
| Frontend build | OK (warning de chunk >500 kB) |
| `ruff` Apps/Domains/scripts | limpio |
| `pyright` | 0 errors |

## 4. Limpieza

- `deprovision --purge-data`: `state=retired`, `data_kept=false`.
- Celda, home, usuario y BD desechable eliminados.
- `cleanup_errors: []`.
- Los 5 hashes de estado del host son idénticos antes/después
  (`registry.json`, `plans.json`, `audit.jsonl`, `subuid`, `subgid`).
- Core y fixture rootful intactos (comprobado por el arnés R4).

## 5. Límites que quedan como gates manuales

- **Cloudflare/DNS real**: requiere credenciales y un dominio real; no se
  ejecutó. El cliente y los flujos están cubiertos por tests con fakes.
- **Soak de horas**: se hizo un soak acotado de 3 ciclos (15.9 MB estables por
  ciclo). Un soak largo sigue siendo una ventana manual.
- **Multi-host del mismo servicio**: el modelo impone
  `UNIQUE(tenant_id, application_id, service)`; hay un host por servicio.
  Multi-servicio sí está cubierto (3 servicios por deploy). Varios dominios
  para el mismo servicio requeriría cambio de modelo.
- **Push**: los commits son locales; no se hizo push.

## 6. Reproducción

```bash
# En el laboratorio, como root, con el stage en /var/tmp/spanel-e2e-0109r5
python3 scripts/e2e_0109_r5_operations.py \
  --stage /var/tmp/spanel-e2e-0109r5 \
  --slug e2e0109r5ops5 \
  --cycles 3 \
  --evidence /var/tmp/0109-r5-ops5.json
```

Sin `--keep`, el script ejecuta setup + drills + borrado de app + cleanup.

## 7. Referencias

- Evidencia operativa: `artifacts/0109-r5-operations-e2e.json`
- Evidencia funcional R4: `artifacts/0109-r4-host-nat-and-domains-owned-hosts-e2e.json`
- Informe R4: `artifacts/0109-r4-informe-final.md`
- Script operativo: `scripts/e2e_0109_r5_operations.py`
- Retención: `vendor/systutor-core/plugins/apps/backend/releases/retention.py`
- Reconcile/fork: `vendor/systutor-core/plugins/apps/backend/tasks.py`
