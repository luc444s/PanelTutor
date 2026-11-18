# A.SPEC 0099 — Rootless cell con driver cgroup systemd y límites reales

## Estado
Propuesto — objetivo 1 de la separación acordada en A.SPEC 0098 (no se implementan cuotas agregadas rootful+rootless en este A.SPEC).

## Problema
El `dockerd` rootless por celda se provisionaba como unidad de **sistema** con
`native.cgroupdriver=cgroupfs`. Docker aceptaba `--memory`, `--cpus` y
`--pids-limit`, pero el proceso del contenedor caía en el cgroup del daemon
(`/system.slice/spanel-cell-<slug>.service`) con `memory.max=max`,
`cpu.max=max 100000` y `pids.max=7811`: **ningún límite se aplicaba**. Causa:
la regla *no-internal-process* de cgroup v2 impide habilitar controladores en un
cgroup que ya contiene procesos (el daemon), aunque `Delegate=yes` y el directorio
pertenezca al usuario de la celda.

## Solución
1. El driver por defecto para **celdas nuevas** es `systemd`.
2. El daemon corre como **unidad de usuario systemd** (bajo `user@<uid>.service`,
   que usa `DelegateSubgroup=init.scope` y deja su cgroup principal vacío), con
   `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/<uid>/bus` y `aa-exec` para fijar
   el perfil AppArmor de la celda. El bus del sistema sigue sin usarse.
3. `Delegate=cpu cpuset io memory pids` en
   `/etc/systemd/system/user@.service.d/delegate.conf` (cambio de host,
   idempotente y documentado; afecta a todos los user managers, no solo al de la
   celda).
4. Perfil AppArmor ampliado **solo** con lo demostrado necesario en laboratorio:
   - `dbus (send, receive) bus=session,` — en AppArmor el bus de usuario se llama
     `session`. `send_destination`/`receive_sender` no existen en AppArmor 4.0.1 y
     hacen que el parser rechace el perfil completo.
   - `/proc/[0-9]*/{stat,cmdline,sessionid} r,` — augment de credenciales de
     `busctl --user status`, que runc usa para leer `OwnerUID` y decidir modo
     rootless. Sin esto, runc cae al bus del sistema y el contenedor queda en
     estado `created`.
   - `rwkl` en `/sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service/`
     y su subárbol — `runc` escribe `cgroup.subtree_control` y los límites del
     scope.
5. El socket, data-root, UID/subuid, redes, volúmenes y el perfil AppArmor se
   conservan. La jerarquía de systemd NO se modifica: `user-<uid>.slice` sigue
   colgando de `user.slice` y el manager opera dentro de `user@<uid>.service`.

## Celdas existentes
- El registry guarda `cgroup_driver`. Las celdas sin el campo se consideran
  `cgroupfs` (legacy): **nunca se migran automáticamente**.
- `repair()` respeta el driver guardado: no puede degradar una celda migrada.
- `migrate --slug X --driver systemd` es explícito, por celda, con:
  1. backup de unidad, `daemon.json`, `delegate.conf` y perfil;
  2. parada del daemon actual;
  3. instalación de los artefactos nuevos y arranque;
  4. verificación de límites (contenedor sonda con 128 MiB / 0.5 vCPU / 64 PIDs
     y lectura de `memory.max`, `cpu.max`, `pids.max` del cgroup real, más carga
     controlada);
  5. rollback automático si la verificación falla.

## Criterios de aceptación
- `docker info` reporta `Cgroup Driver: systemd` y `Cgroup Version: 2`.
- `memory.max=134217728`, `cpu.max=50000 100000`, `pids.max=64` en el cgroup del
  contenedor de prueba, y el proceso del contenedor está en **su propio** cgroup.
- Cargas: exceso de memoria provoca `oom_kill`, CPU queda en ~0,5 vCPU y el fork
  por encima de 64 falla con `Resource temporarily unavailable`.
- AppArmor sigue en `enforce` en el daemon **y** en los procesos del contenedor.
- Socket exclusivo del tenant; `cell-h` y rootful quedan intactos.
- Reinicio de la unidad de usuario y `repair()` conservan los límites.

## Despliegue del cambio de perfil
El template AppArmor cambia (nuevas reglas), por lo que `profile_hash` cambia
para todas las celdas. Tras desplegar, hace falta `spanel-tenant repair --slug X`
(o `apparmor install`) en cada celda para reinstallar el perfil y refrescar el
hash guardado; de lo contrario `apparmor verify` reportará `hash_matches=false`.
Las reglas nuevas se incluyen en el perfil de todas las celdas (no solo las
migradas) para que el template sea único, idempotente y `repair()` no tenga que
ramificarse por driver.

## No objetivos
- Cuotas agregadas entre contenedores rootful y rootless bajo un ancestro común.
- Modificar `cell-h`, WordPress, Docker rootful, producción ni la jerarquía de
  `user.slice`.
- Usar Alembic en desarrollo (prohibido por AGENTS.md).
