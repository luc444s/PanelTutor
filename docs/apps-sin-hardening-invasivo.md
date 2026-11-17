# Apps sin hardening invasivo

**Decisión arquitectónica (esta entrega):** PanelTutor deja de modificar el
interior de las aplicaciones. El aislamiento pertenece a la infraestructura, no
al Dockerfile del cliente.

Estado: implementado en la rama `remove-hardener`. El runtime rootless por
tenant y el Docker socket por tenant **siguen fuera de alcance** y no se han
implementado.

---

## 1. Qué se retiró

### Canal obligatorio de despliegue

| Antes | Ahora |
| --- | --- |
| `worker` llamaba a `normalize_compose()` y **sobrescribía** el Compose del checkout. | El checkout se audita tal cual se clonó; ningún archivo se reescribe. |
| `ReleaseExecution.harden_checkout()` ejecutaba `dangerous-build-normalize harden --apply` como subproceso. | `ReleaseExecution.prepare_release()` firma el árbol original; no hay subproceso. |
| `resolve_runtime_volumes()` preparaba usuarios/volúmenes y `prepare_runtime_volumes()` hacía `chown`/`chmod` con capacidades. | No se genera política de volúmenes para releases nuevos. La rutina solo atiende releases firmados antes del retiro. |
| `scoped_execution` recreaba contenedores (`rm -s -f` + `create`) para inyectar archivos `x-spanel-readonly-files`. | Ese ciclo solo se ejecuta si el release firmado contiene esas marcas (releases antiguos). Los nuevos van directo a `up`. |

### Componentes eliminados

- `scripts/dangerous_build/` (motor transaccional, `compose.py`, `dockerfile.py`,
  `compose_normalizer.py`, `cli.py`, caché, gates).
- `scripts/dangerous_build_normalize.py` y su wrapper en la imagen Docker
  (`/usr/local/bin/dangerous-build-normalize`), junto con `trivy`/`hadolint`,
  que solo se usaban en ese gate.
- `backend/compose_normalizer.py` (copia duplicada del normalizador).
- `backend/hardening/engine.py` (`CommandHardeningEngine`) y
  `HardenedCandidate` con toda su evidencia de transformación.
- Tests que afirmaban transformaciones: hardener, normalizador, cómputo de
  redes del hardener y E2E que normalizaba un checkout inseguro.

Concretamente desaparecieron: inyección de `USER`, `--chown`, usuarios/grupos
artificiales, `RUN chown/chmod`, reescrituras de `COPY`/`ADD`/`WORKDIR`/
`ENTRYPOINT`/`CMD`/`HEALTHCHECK`, `read_only`, `tmpfs`, `cap_add`,
`no-new-privileges`, `init`, conversiones de volúmenes, `volume.nocopy` y
reescrituras de redes.

---

## 2. Qué se conserva

### Validaciones de seguridad (política de host)

Se mantienen igual y siguen siendo bloqueantes:

- `runtime/audit.py` + `runtime/docker_audit.py`: socket Docker, mounts
  sensibles/absolutos, `privileged`, `cap_add`, `devices`, host namespaces,
  `container_name`, puertos publicados, `user: root`, `security_opt` inseguro,
  `env_file` del checkout, secretos, redes externas no autorizadas y builds con
  `network: host` / entitlements.
- `releases/verify.py`: firma HMAC, expiración, hash del artefacto, digest del
  árbol, hash de Compose/Dockerfiles, política administrada y
  `_assert_compose_hardened` (sin mounts de host, sin namespaces de host, sin
  `user: root`, sysctls permitidos, marcas `x-spanel-readonly-files` válidas en
  releases antiguos).
- `runtime/probes.py::check_isolation` y `_image_users`: el contenedor en
  ejecución debe tener un usuario no-root **declarado por la imagen o por el
  Compose**, sin capacidades añadidas ni acceso a mount de host.
- `_override()` sigue aplicando política de runtime **en un archivo separado**
  (`override.yaml`), nunca sobre el Compose original: `cap_drop: ALL`,
  `no-new-privileges:true` cuando el Compose no los declara, red `internal` y
  etiquetas de propiedad. No inyecta `user`, `read_only`, `tmpfs`, `init` ni
  modifica entrypoint/command/volúmenes/redes del desarrollador.

### Compatibilidad

- Formato del release firmado sin cambios: `source_tree_sha256` y
  `hardened_tree_sha256` valen lo mismo para releases nuevos (el árbol no se
  transforma), por lo que releases antiguos siguen verificándose y
  haciéndose rollback.
- Se conservan los endpoints `/hardening`, `/deployments` y
  `hardened_operation_id`. El campo `hardening` se valida, pero sus campos
  `service_users`/`writable_paths` ya no se aplican: solo se registran como
  evidencia heredada. Las redes autorizadas (`authorized_external_networks`,
  `egress_networks`) sí se siguen enforcing en la verificación.
- No se inventa UID/GID cuando la app no declara usuario: se respeta el `USER`
  de la imagen y la comprobación de no-root lo valida; si es root, el release
  se rechaza con un mensaje explícito.

---

## 3. Pipeline resultante

1. Clonar y materializar el adaptador de fuente.
2. Auditar estáticamente el checkout original.
3. Comprobar restricciones de seguridad (rechazo explícito si falla).
4. **No hay fase de transformación**: solo se calcula la política de redes.
5. Firmar y persistir el artefacto original.
6. Desplegar con el runtime existente (override mínimo y auditable).
7. Verificar healthchecks/aislamiento.
8. Registrar release, logs, operaciones y rollback.

---

## 4. Pruebas

- `vendor/systutor-core/plugins/apps/backend/tests/test_no_invasive_hardening.py`:
  preservación byte-a-byte, ausencia de subproceso hardener, ausencia de
  marcas/inyecciones, validaciones de seguridad activas, rechazo explícito y
  verificación de releases.
- Se actualizaron `test_worker_github.py`, `test_scoped_planner.py`,
  `test_symlink_digest.py` y `test_volume_runtime_users.py` para el nuevo
  contrato (sin `hardening_engine`, sin recreación de contenedores, sin UID
  inventado).

Comandos ejecutados (ver detalle en el entregable de la sesión):

```sh
.venv/bin/python -m pytest vendor/systutor-core/plugins/apps/backend/tests -q
.venv/bin/python -m ruff check vendor/systutor-core/plugins/apps/backend
.venv/bin/python -m pytest scripts/tests -q
```

---

## 5. Limitaciones pendientes

- No hay daemon Docker rootless por tenant ni socket Docker exclusivo: el
  acceso al socket rootful del host permanece bloqueado.
- Sin sandbox de tenant, una aplicación que requiere root se rechaza; no se
  reduce la barrera actual para aceptarla.
- Las políticas de host se aplican mediante el runtime actual (cap_drop,
  no-new-privileges, red interna), no mediante un sandbox de nueva generación.
- La UI y la CLI siguen exponiendo el formulario de "hardening" por
  compatibilidad de API; sus campos de usuario/permisos son evidencia heredada.
