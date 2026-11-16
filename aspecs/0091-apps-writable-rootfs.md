# A.SPEC 0091 — Rootfs escribible para Apps

> `risk: high` — relaja una defensa del runtime de todas las releases nuevas.
> Requiere aprobación humana, tests y E2E real con Docker.

## STATUS

Implementada localmente. Pendiente de E2E real con Docker antes de producción.

Sucede únicamente las reglas de rootfs read-only de A.SPEC 0087 y A.SPEC 0089.
El resto de sus contratos permanece vigente.

## WHY

Forzar `read_only: true` rompe imágenes legítimas que escriben configuración,
cachés, PID files o estado efímero durante el arranque. Enumerar cada ruta como
`tmpfs` o volumen requiere conocer internamente todas las imágenes y reduce la
compatibilidad del deploy genérico.

La persistencia y la escritura efímera son responsabilidades distintas:

- la capa del contenedor puede ser escribible para compatibilidad;
- los datos que deben sobrevivir a una recreación usan volúmenes nombrados;
- una app comprometida sigue sin recibir root, capabilities, binds, devices,
  Docker socket, namespaces del host ni puertos publicados.

## CONTRACT

Toda release nueva usa este envelope:

| Protección | Política |
|---|---|
| Runtime | `runc` |
| Usuario | Non-root obligatorio |
| Rootfs | Escribible por defecto (`read_only: false`) |
| Capabilities | `cap_drop: ALL` |
| AppArmor | `docker-default` explícito |
| Seccomp | Perfil `builtin` predeterminado de Docker |
| `no-new-privileges` | Obligatorio |
| Docker socket | Prohibido |
| Host binds / devices | Prohibidos |
| `privileged` | Prohibido |
| CPU / RAM / PIDs | Límites obligatorios |
| Redes | Internas y aisladas por proyecto |
| Persistencia | Volúmenes nombrados |

### Rootfs y persistencia

1. El hardener escribe `read_only: false`; no se deja el valor implícito.
2. La capa escribible es efímera y se pierde al recrear el contenedor.
3. Los volúmenes nombrados declarados se conservan y siguen gestionados por
   A.SPEC 0089.
4. Los binds del host no se convierten en volúmenes automáticamente; se eliminan
   y continúan prohibidos.
5. `/tmp` y las rutas runtime administradas pueden conservar sus `tmpfs` con
   `noexec,nosuid,nodev`; no son necesarias para habilitar escritura general,
   pero mantienen semántica efímera y límites claros.
6. Los helpers internos de probes y volúmenes conservan `--read-only`; este
   cambio aplica a workloads de Apps, no al plano de control desechable.

### AppArmor y seccomp

El compose endurecido declara exactamente:

```yaml
security_opt:
  - no-new-privileges:true
  - apparmor=docker-default
  - seccomp=builtin
```

No se conserva ningún perfil solicitado por el repositorio. `unconfined`, rutas
de perfiles personalizadas y desactivación de NNP son bloqueantes.

El isolation probe exige `AppArmorProfile == docker-default` y las opciones
explícitas de NNP, AppArmor y seccomp. Si el host no soporta el contrato, el
deployment falla cerrado.

### Límites

Cada servicio conserva como mínimo la política administrada actual:

```yaml
pids_limit: 256
mem_limit: 512m
cpus: 1.0
```

El isolation probe comprueba que PIDs, memoria y CPU sean valores positivos y
acotados por la política. Una release no puede omitirlos ni elevarlos mediante
el compose original.

### Migración

- Las releases firmadas existentes no se editan.
- Rollback a una release antigua restaura su rootfs read-only firmado.
- Una aplicación adopta rootfs escribible al generar una release nueva.
- No hay cambio de esquema ni migración de datos.

## INVARIANTS

- `I1` Rootfs escribible no permite root ni capabilities.
- `I2` No se admiten Docker socket, binds, devices, privileged o host namespaces.
- `I3` AppArmor, seccomp y NNP se declaran y verifican explícitamente.
- `I4` CPU, RAM y PIDs siguen limitados.
- `I5` Las redes continúan internas y aisladas por proyecto.
- `I6` La persistencia durable solo se promete sobre volúmenes nombrados.
- `I7` Helpers internos permanecen read-only y con privilegios mínimos.
- `I8` Releases existentes y rollbacks conservan su contrato firmado.
- `I9` Sin cambios de esquema y sin Alembic.

## TESTS

### Unitarios

- Hardener reemplaza `read_only: true`, `false` o ausente por `false` explícito.
- Hardener reemplaza `security_opt` por NNP + AppArmor + seccomp administrados.
- Se mantienen non-root, `cap_drop: ALL`, límites, red interna y prohibiciones.
- Named volumes se conservan; binds y devices se eliminan.
- Evidencia del hardener declara rootfs escribible.

### Probes

- `ReadonlyRootfs: false` pasa; `true` falla.
- AppArmor distinto o vacío falla.
- NNP, `apparmor=docker-default` o `seccomp=builtin` ausentes fallan.
- Límites PIDs, memoria o CPU ausentes/cero/excesivos fallan.
- Root, capabilities, binds, devices, privileged, puertos o red no interna
  continúan fallando.

### E2E real

1. Desplegar una imagen non-root que necesite escribir en una ruta no declarada.
2. Comprobar escritura durante arranque y probes verdes.
3. Escribir un canary en rootfs y otro en volumen nombrado.
4. Recrear el contenedor: el canary de rootfs desaparece y el del volumen sigue.
5. Verificar inspect: runc, non-root, writable rootfs, caps drop, perfiles,
   límites, sin binds/devices/ports y red interna.
6. Probar rechazo de cada escape de aislamiento.
7. Guardar evidencia en `artifacts/0091-writable-rootfs-e2e.json`.

## CHANGE SURFACE

- `scripts/dangerous_build/compose.py`
- `scripts/dangerous_build/hardener.py`
- `scripts/dangerous_build/cli.py`
- `scripts/tests/test_transactional_build_hardener.py`
- `vendor/systutor-core/plugins/apps/backend/runtime/probes.py`
- `vendor/systutor-core/plugins/apps/backend/tests/test_probes.py`
- Documentación de Apps y E2E.

## ACCEPTANCE

- [ ] Releases nuevas contienen `read_only: false` explícito.
- [ ] Non-root, caps drop, NNP, AppArmor y seccomp pasan probes efectivos.
- [ ] CPU, RAM y PIDs están presentes y acotados.
- [ ] Named volumes persisten; rootfs no promete persistencia.
- [ ] Sin regresión en prohibiciones de socket/binds/devices/privileged/red.
- [ ] Tests unitarios e integración verdes.
- [ ] E2E real demuestra compatibilidad y semántica efímera.
- [ ] Sin cambios de esquema y sin Alembic.
