# A.SPEC 0090 — Runtime gVisor obligatorio (sandbox)

> `risk: high` — permite root dentro del contenedor, sustituye el runtime de
> todas las apps y cambia la frontera de aislamiento. Requiere aprobación humana,
> gVisor instalado y E2E real con Docker.

## STATUS

Pendiente para el futuro. Propuesta. No implementada.

No hay trabajo de implementación iniciado. Se retoma cuando el operador lo
prioricen; hasta entonces `strict` sigue siendo el runtime actual.

Objetivo final: **todas las apps corren en `sandbox`**. `strict` no será un
segundo sistema permanente; solo existe como perfil temporal de migración y
rollback hasta el cutover.

## WHY

El perfil `strict` exige usuario no-root, rootfs read-only, `cap_drop: ALL` y
volúmenes no-root. Protege el host, pero bloquea apps reales que necesitan root
para arrancar, escribir configuración, instalar dependencias o inicializar
datos. Mantener dos motores permanentes multiplica tests, rutas de deploy y
estados de soporte.

La decisión es migrar a un único runtime:

- root **permitido** dentro del contenedor;
- cada app corre bajo **gVisor (`runsc`)**;
- el daño de una app comprometida queda contenido en su red de tenant, sus
  volúmenes y su sandbox;
- nunca hay fallback silencioso a `runc`.

gVisor interpone un kernel en user space entre la app y el kernel del host.
Root dentro del sandbox deja de ser root directo sobre el kernel real. Esa es
la frontera que hace viable permitir root sin entregar la infraestructura.

## WHAT

PanelTutor adopta `sandbox` como runtime objetivo:

- nuevas apps: `sandbox` por defecto;
- apps existentes: migración por olas con releases nuevas;
- `strict`: solo para releases legacy ya firmadas durante la ventana de
  migración; no se aceptan nuevas releases `strict` después del cutover;
- una release `sandbox` se firma con perfil, runtime, capabilities, usuarios,
  volúmenes y **digests de imagen**;
- si `runsc` no está disponible, falla cerrado; nunca se usa `runc` como
  alternativa.

## SCOPE

- Perfil `sandbox` y migración de todas las apps.
- Hardener consciente de gVisor.
- Red de tenant e ingress administrado.
- Contrato de capabilities.
- Preflight y verificación post-deploy de `runsc`.
- Semántica de root y volúmenes en sandbox.
- Separación de probes de aislamiento, salud y estabilidad.
- Firma de digests de imagen/artefactos de build.
- Compatibilidad con `cgroup_parent` y con la futura A.SPEC de cuotas.
- Evidencia y visualización del perfil/runtime.
- Tests unitarios, integración, E2E y migración.

## OUT OF SCOPE

- SSH, terminal web o gateway de acceso. A.SPEC separada.
- Implementación completa de cuotas por tenant. `cgroup_parent` no es una
  cuota; la A.SPEC de cuotas debe demostrar contabilidad agregada.
- Política de egress/allowlist.
- MicroVM Kata/Firecracker.
- Contenedor de bootstrap root (`x-paneltutor-bootstrap`). A.SPEC separada.
- Cambios de esquema SQL o Alembic.
- Permitir `privileged`, devices, host namespaces, binds del host o puertos
  publicados.
- Mantener `strict` como opción permanente.

## CONTRACT

### Perfil y migración

```yaml
x-paneltutor-profile: sandbox
```

Reglas:

1. `sandbox` es el objetivo y el default después del cutover.
2. Antes del cutover, una app nueva sin declaración se asume `sandbox`; una app
   legacy con release `strict` ya firmada puede seguir en `strict` hasta su
   migración.
3. No se aceptan releases `strict` nuevas después del cutover.
4. El perfil es de nivel superior; no hay override por servicio.
5. La clave se conserva en el compose endurecido y queda cubierta por hash y
   firma.
6. Una release firmada no puede degradar de `sandbox` a `strict` en caliente.
7. La migración de una app exige release nueva y revisión de permisos de
   volúmenes.

### Envelope

| Elemento | `sandbox` (objetivo) | `strict` (solo legacy temporal) |
|---|---|---|
| Runtime | `runsc` obligatorio | `runc` |
| Usuario | compose/Dockerfile/imagen; root permitido | no-root obligatorio |
| Rootfs | escribible por defecto, capa efímera | read-only |
| Capabilities | `cap_drop: ALL` + solo las solicitadas y autorizadas | `cap_drop: ALL` |
| `no-new-privileges` | obligatorio | obligatorio |
| Volumen root | permitido | rechazado |
| Socket Docker | prohibido | prohibido |
| `privileged` | prohibido | prohibido |
| Devices | prohibidos | prohibidos |
| Host network/PID/IPC | prohibido | prohibido |
| Binds del host | prohibidos | prohibidos |
| Puertos publicados | prohibidos | prohibidos |
| Red | red de tenant + ingress administrado | red interna |
| Límites CPU/RAM/PIDs | obligatorios | obligatorios |

### Red y ingress

La app **nunca** se conecta a la red de Traefik ni a una red compartida.

Modelo:

```text
Traefik (red edge)
   │
   ▼
Ingress administrado por PanelTutor (edge + red del tenant)
   │
   ▼
Red única del tenant
   ├── app A
   ├── app B
   └── DB/Redis del tenant
```

Reglas:

1. Cada app se conecta a **una única red de tenant**.
2. El ingress es un componente propiedad de PanelTutor, no del compose del
   usuario.
3. El ingress es el único que participa en la red edge y en la red del tenant.
4. Traefik solo habla con el ingress; nunca directamente con las apps.
5. No se permiten `ports`, `network_mode`, redes externas ni redes adicionales
   definidas por el usuario.
6. La configuración del ingress se genera desde deployments firmados.
7. Las apps del mismo tenant pueden alcanzarse entre sí; el aislamiento fuerte
   es entre tenants.
8. El ingress nunca comparte volúmenes con las apps ni expone el socket de
   Docker a la red del tenant.

### Capabilities

Contrato inequívoco:

1. El compose puede **solicitar** capabilities con `cap_add`.
2. Una solicitud fuera de la allowlist **rechaza el deployment**.
3. Una capability autorizada se aplica **solo si fue solicitada**; no se concede
   por defecto.
4. Sin `cap_add`, el servicio corre con `cap_drop: ALL` y sin capabilities.
5. La allowlist es:

```text
CHOWN, DAC_OVERRIDE, FOWNER, FSETID, SETFCAP, SETGID, SETUID,
NET_BIND_SERVICE, SYS_CHROOT
```

6. `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`, `MKNOD`, `NET_RAW` y
   cualquier otra capability fuera de la lista se rechazan.
7. En gVisor las capabilities percibidas por la app son emuladas por el
   sandbox, pero siguen siendo parte del contrato de seguridad interna.
8. Si una imagen falla por una capability que no solicitó, el operador la
   revisa, la añade a la política si corresponde y la app debe declararla. No se
   concede automáticamente por “root”.

### Preflight de gVisor

Tres controles independientes:

| Control | Momento | Condición |
|---|---|---|
| `runsc` registrado, versión mínima y `runtimeArgs` confiables | Preflight inicial, antes de clonar/construir/firmar | Falla cerrado |
| Contenedor mínimo arranca bajo `runsc` | Preparación del host | Falla cerrado |
| Cada contenedor de la app usa `runsc` | Probe posterior al deploy y reconciliaciones | Falla cerrado |

Reglas:

- Se registra `runsc --version` y la plataforma (`ptrace`/`kvm`) en la evidencia.
- `runtimeArgs` debe coincidir con una allowlist del operador.
- Se rechazan flags que habiliten red del host, UDS del host o desactiven el
  sandbox de red.
- Se repite la comprobación inmediatamente antes de `up`.
- Si `runsc` desaparece, falla o deja de estar disponible durante un rollback,
  una recreación o una recuperación, la operación se rechaza.
- **Nunca** se intenta `runc` como fallback.

### Usuario y volúmenes

- No se inyecta `USER` no-root.
- Si el compose declara `user:`, se respeta.
- Si no, se usa el `USER` final de la imagen o su default.
- Root (`0:0`) es válido.
- No se adopta el dueño del volumen para reescribir el usuario.
- Volúmenes root permitidos.
- Volumen nuevo: se inicializa con el usuario numérico declarado si existe; si
  no, se deja como lo cree Docker.
- Volumen existente: nunca se modifica ni se hace `chown`.
- La persistencia solo existe en volúmenes nombrados; la capa escribible es
  efímera.

### Imágenes firmadas

- Cada servicio debe referenciar una imagen por digest o un artefacto de build
  con ID content-addressed.
- La release firma el digest/ID resuelto de cada imagen.
- En el deploy se verifica que la imagen resuelta coincide con la firmada.
- Una etiqueta mutable que resuelve a otra imagen invalida la release.
- El perfil `sandbox` queda asociado a la imagen exacta, no solo al compose.

### Probes

Se separan tres responsabilidades:

1. **Isolation probe** — solo seguridad:
   - `HostConfig.Runtime == "runsc"`;
   - sin `privileged`, devices, binds, port bindings, host PID/IPC/network;
   - exactamente la red del tenant;
   - capabilities dentro de la allowlist solicitada;
   - `no-new-privileges`;
   - root permitido **solo** con `runsc`.

2. **Health probe** — disponibilidad:
   - contenedor `running`;
   - `healthy` si hay healthcheck;
   - probe funcional HTTP independiente.

3. **Stability probe** — operación:
   - `restart_count_delta` dentro de una ventana;
   - un reinicio puntual no invalida el aislamiento;
   - superar el umbral o entrar en crash-loop falla estabilidad, no seguridad.

### Evidencia y firma

El manifest incluye:

```json
{
  "runtime_profile": "sandbox",
  "sandbox_runtime": "runsc",
  "runsc_version": "2026.x",
  "runsc_platform": "kvm",
  "image_digests": {
    "app": "sha256:..."
  },
  "service_runtime": {
    "app": {
      "user": "0:0",
      "user_source": "image-default",
      "capabilities": ["CHOWN"],
      "networks": ["tenant-<id>"],
      "read_only": false,
      "runtime": "runsc"
    }
  },
  "probes": {
    "isolation": {},
    "health": {},
    "stability": {
      "restart_count_delta": 0
    }
  }
}
```

La release firmada cubre perfil, runtime, versión, digests, capabilities,
usuarios, volúmenes y política de red.

### Errores

- `sandbox runtime runsc is not available on this host`
- `runsc version is below the minimum supported version`
- `runsc runtimeArgs enable host access`
- `service app requests a capability outside the sandbox allowlist: SYS_ADMIN`
- `service app image digest does not match the signed release`
- `service app uses a forbidden host feature: privileged`
- `service app is not running under runsc`

## DESIGN

### Orden del pipeline

1. **Preflight inicial**: `runsc` registrado, versión, `runtimeArgs`, contenedor
   mínimo.
2. Clonar y auditar el checkout.
3. Resolver perfil (`sandbox`; legacy `strict` solo durante migración).
4. Resolver usuarios y volúmenes.
5. Endurecer el compose.
6. Construir y resolver digests/IDs de imagen.
7. Firmar release con perfil, runtime, digests y política.
8. **Segundo preflight** inmediatamente antes de arrancar.
9. Crear/inicializar volúmenes.
10. `up -d` con `runtime: runsc`.
11. Probes de aislamiento, salud y estabilidad.
12. Verificar `runsc` en cada contenedor y publicar estado.

### Hardener

- `sandbox`:
  - añade `runtime: runsc`;
  - no fuerza `user`;
  - no inyecta `USER` no-root;
  - deja rootfs escribible;
  - mantiene `no-new-privileges`;
  - aplica `cap_drop: ALL` y solo las capabilities solicitadas/autorizadas;
  - elimina `privileged`, devices, host namespaces, binds y puertos;
  - fuerza la red de tenant y elimina redes externas/adicionales;
  - mantiene límites CPU/RAM/PIDs;
  - conserva `x-paneltutor-profile`.
- `strict` legacy: envelope actual, sin cambios, solo para releases ya
  firmadas durante la migración.

### Red e ingress

- El ingress es un componente administrado que PanelTutor despliega y configura.
- Puede ser un proxy por tenant o un gateway compartido con configuración
  aislada; la implementación concreta se decide en la A.SPEC de ingress.
- No se le da a la app acceso a la red edge.
- El ingress no se considera un servicio de la app para probes de aislamiento.
- La ruta HTTP se genera solo desde releases firmadas.

### gVisor y cgroups

- `runsc` se instala y registra fuera de este cambio.
- La plataforma (`ptrace`/`kvm`) se registra, pero no se fuerza una concreta.
- `cgroup_parent` solo coloca contenedores bajo una jerarquía; **no crea una
  cuota agregada**.
- La A.SPEC de cuotas debe demostrar:
  - cgroups v2;
  - contabilidad de todos los procesos de la app, incluidos Sentry/Gofer;
  - límites agregados por tenant;
  - pruebas bajo presión de memoria;
  - integración correcta con systemd/runsc.
- Hasta que esa A.SPEC esté verificada, no se promete una cuota de 2 GiB.

### Migración

1. Inventario de apps, usuarios, volúmenes, redes y dependencias.
2. Preflight de gVisor en cada host.
3. Piloto con 2–3 apps reales (Gitea, Nextcloud + una app root simple).
4. Migración por olas con releases nuevas; rollback a la release strict
   anterior durante la ventana.
5. Cutover: `sandbox` por defecto; se rechazan nuevas releases `strict`.
6. Retirada de `strict` del código y de la UI.
7. Rollback post-cutover solo a releases `sandbox`.

## INVARIANTS

- Todos los contenedores de apps corren bajo `runsc`.
- `runc` para una app es siempre un error; no hay fallback.
- Root solo es válido con `runsc`.
- La app solo pertenece a la red de su tenant; el ingress es la única frontera.
- Sin socket, privileged, devices, host namespaces, binds ni puertos.
- Solo se aplican capabilities solicitadas y dentro de la allowlist.
- La release firma los digests de imagen y se verifican en el deploy.
- El preflight ocurre al inicio y otra vez antes de `up`.
- Si `runsc` falla o desaparece, rollback/recreación/recuperación fallan
  cerrado.
- Un reinicio operativo no se confunde con una violación de aislamiento.
- `cgroup_parent` no se presenta como cuota de tenant.
- `strict` es temporal y se retira tras la migración.
- No se introduce Alembic ni cambios de esquema.

## VERIFICATION

### Unitarias

- Default de perfil y migración: nueva app → sandbox; estricta legacy →
  bloqueada tras cutover.
- Hardener sandbox: `runtime: runsc`, sin `user` forzado, rootfs escribible,
  capabilities solicitadas, red de tenant, sin hosts/binds/puertos.
- Capabilities: solicitud permitida se aplica; solicitud fuera de allowlist
  rechaza.
- Preflight: sin runsc, versión baja, runtimeArgs peligrosos → rechazo.
- Probes: root+runsc pasa; root+runc falla; red extra falla; ingress no cuenta
  como red de app.
- Digest: tag mutable que resuelve distinto → rechazo.
- Estabilidad: reinicio puntual no rompe aislamiento; crash-loop falla
  estabilidad.
- Evidencia: perfil, runtime, versión, digests, capabilities, usuario y redes.

### Integración

- Contenedor mínimo arranca con `runtime=runsc`.
- `docker inspect` de cada app muestra `HostConfig.Runtime == "runsc"`.
- Nginx con UID 0 bajo runsc arranca.
- UID 0 con runc es rechazado.
- `privileged`, socket, devices, host network y puertos son rechazados.
- `SYS_ADMIN` solicitada es rechazado.
- Volumen root existente conserva datos.
- Rollback a strict durante migración no altera volúmenes.
- `runsc` desinstalado → fail-closed.
- Dos tenants bajo presión de memoria no superan cuotas ni se ven entre sí.
- HTTP detrás de Traefik accesible sin puerto publicado.

### E2E real en lab

1. Instalar/registrar `runsc` y ejecutar preflight.
2. Desplegar app root simple (Nginx) en sandbox.
3. Verificar runtime, root interno, HTTP, probes y ausencia de host features.
4. Desplegar Gitea y Nextcloud en sandbox y medir compatibilidad.
5. Persistencia: datos → `down` → redeploy → datos intactos.
6. Migrar una app strict existente a sandbox y verificar volúmenes/permisos.
7. Rollback a la release strict anterior durante la ventana; datos intactos.
8. Retirar `runsc` y comprobar que un redeploy falla cerrado.
9. Dos tenants bajo presión de memoria y prueba de red cruzada.
10. Guardar evidencia en `artifacts/0090-gvisor-sandbox-e2e.json`.

## ROLLBACK

- Durante la migración: se permite volver a la release strict anterior; no se
  modifican volúmenes.
- Después del cutover: rollback solo a releases `sandbox`.
- Si `runsc` no está disponible, el deploy/rollback/recreación falla cerrado.
- Nunca se usa `runc` como fallback silencioso.
- Las releases ya firmadas no se reescriben.
- Los volúmenes y datos permanecen; no hay migraciones.

## CHANGE SURFACE

- `scripts/dangerous_build/*`: perfil, capabilities, red de tenant, rootfs,
  runtime.
- `vendor/systutor-core/plugins/apps/backend/hardening/contracts.py`: perfil,
  runtime, capabilities, digests.
- `runtime/deployment.py`, `runtime/release_deploy.py`: runtime, evidencia,
  preflight.
- `runtime/volumes.py`: semántica sandbox.
- `runtime/probes.py`: separación isolation/health/stability.
- `releases/scoped_execution.py`: propagar perfil, verificar runsc y digests.
- `worker.py`: preflight, no fallback, errores.
- Ingress: componente administrado y configuración firmada.
- Frontend: perfil, runtime, root, capabilities y estado de migración.
- Tests, fixtures y E2E.
- A.SPEC 0089: marcar sus invariantes no-root como legacy strict hasta la
  retirada.

## BLAST RADIUS

- Todas las apps durante y después de la migración.
- Hosts sin `runsc` no podrán desplegar apps sandbox.
- Cambian probes, evidencia, red de ingress y limites de capabilities.
- `strict` deja de ser soportado tras el cutover.
- No hay impacto en Hosting, correo o dominios.

## DEFINITION OF DONE

- [ ] Preflight de runsc al inicio y antes de `up`.
- [ ] Contenedor mínimo bajo runsc verificado.
- [ ] Todos los contenedores de app usan runsc; nunca runc.
- [ ] Root permitido solo en sandbox.
- [ ] Red de tenant + ingress administrado; sin puertos publicados.
- [ ] Capabilities: solo solicitadas y en allowlist; resto rechazado.
- [ ] Digests de imagen firmados y verificados.
- [ ] Probes separados: isolation, health, stability.
- [ ] `cgroup_parent` documentado como placement, no cuota.
- [ ] Migración de apps por olas y cutover sin `strict` nuevo.
- [ ] Rollback a strict durante la ventana sin tocar volúmenes.
- [ ] fail-closed si runsc desaparece.
- [ ] E2E con Nginx root, Gitea, Nextcloud, dos tenants y Traefik.
- [ ] Sin cambios de esquema ni Alembic.
