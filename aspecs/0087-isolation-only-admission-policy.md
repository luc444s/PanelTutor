# A.SPEC 0087 — Isolation-Only Admission Policy

## STATUS

Implementado en código. E2E live pendiente de corrida contra el laboratorio.

Sucede y reemplaza a A.SPEC 0086. Cambia la admisión de Apps a **solo
aislamiento**: Trivy y Hadolint salen del pipeline. La seguridad interna de la
aplicación es responsabilidad exclusiva de quien la sube.

## WHY

Hoy el pipeline bloquea por CVEs y estilo de Dockerfile. Eso mezcla dos
responsabilidades que no son de la plataforma:

1. **La plataforma** garantiza que una app comprometida no alcance el host, el
   Docker socket, el panel, otros tenants ni la red del sistema.
2. **El dueño de la app** elige qué instala dentro de su contenedor: PHP 5,
   dependencias viejas, código inseguro. Si eso se compromete, el daño debe
   quedar contenido en su contenedor y sus datos.

Bloquear por un `axios` desactualizado en un lockfile que ni se instala no
protege la raíz. Solo impide desplegar apps reales. La línea roja es el
aislamiento, no el conteo de CVEs.

## CONTRACT

> Una aplicación se admite si y solo si su aislamiento está demostrado, la
> release está firmada y los probes pasan. El contenido de la app no se evalúa.

Corolarios:

1. **No hay gate de CVEs.** Trivy y Hadolint no participan de `harden` ni de la
   admisión. Pueden existir como herramienta manual del operador, fuera del
   pipeline.
2. **No hay gate de estilo.** Dockerfile sin pin, `CMD` en shell, imágenes base
   viejas: no bloquean.
3. **No hay “insecure” por vulnerabilidades.** Se elimina el override de
   Trivy/Hadolint. `insecure` deja de existir como concepto de admisión.
4. **Bloqueo duro**: privilegios, root, Docker socket, host namespaces, binds
   al host, paths sensibles, puertos publicados, red externa/egress no
   autorizado, rootfs escribible, capabilities, `no-new-privileges`, firma,
   probes.
5. **Build**: el build real del deployment debe producir imagen. El gate de
   `harden` no construye; no necesita `skip_build`.
6. **Healthcheck opcional**: si Compose o la imagen declaran uno, debe reportar
   `healthy`. Sin healthcheck, la estabilidad exige `running` y siempre
   `RestartCount == 0`; el probe funcional independiente sigue siendo
   obligatorio.
7. Lo que ocurra dentro del contenedor —CVEs, auth, uploads, PHP obsoleto— es
   riesgo del tenant. La plataforma solo garantiza contención.

## SCOPE

Motor y gate:

- `harden`: el gate queda reducido a auditoría de aislamiento sobre el
  candidato endurecido. No ejecuta Trivy, Hadolint ni BuildKit.
- `compose.py`: mantener el envelope de aislamiento y los writable paths
  efímeros como `tmpfs`.
- `scan` puede seguir existiendo como diagnóstico manual, pero no se invoca
  desde `harden`.
- Eliminar `skip_trivy`, `skip_hadolint`, `skip_build` y todo el bloque `gate`
  de la política de hardening.

Backend/releases:

- `HardeningPolicy` vuelve a la forma de 0083: `service_users` y
  `writable_paths`, sin `gate`.
- Eliminar `HardeningGateRequest` y el guard
  `SPANEL_APPS_ALLOW_INSECURE_HARDENING`.
- Release descriptor: solo `isolation` y `probes`. Sin advisories, sin
  `risk_policy`, sin `insecure`.
- `catalog._deployment_view`: exponer `isolation`/`probes`; no CVEs.
- El router rechaza cualquier política con campos de gate (422) por schema.

Frontend:

- Sin badge de CVEs ni advertencias de dependencias.
- Deployments muestra release, probes e isolation.
- El botón Deploy solo se bloquea por isolation/source/operación activa.
- Nota visible: “la seguridad interna de la app es responsabilidad del
  proveedor de la app; la plataforma garantiza el aislamiento”.

E2E:

- `scripts/e2e_apps_trusted_deploy.py` ya no usa `--insecure-gate` ni
  `--insecure-skip-*`. No hay gate de CVEs que saltar.
- El fixture `software-de-gestion-para-editores` debe desplegar con su PHP/
  dependencias reales, siempre que el aislamiento pase.
- La evidencia valida aislamiento/probes, no CVEs.

## OUT OF SCOPE

- Política de egress (allowlist/proxy). `internal: true` sigue siendo el
  default; una app que necesita salir requiere una A.SPEC posterior.
- Corrección de dependencias de las apps.
- Escaneo de vulnerabilidades como servicio del panel.
- Cambios de modelos o migraciones.

## DESIGN

### 1. Decisión de admisión

```text
admit =
  signature_verified
  and isolation_verified
  and probes_passed
  and build_succeeded
```

No hay ninguna otra condición. El contenido de la app no se inspecciona.

### 2. `harden`

```text
1. copiar checkout a candidato
2. aplicar envelope de aislamiento (non-root, read-only, cap_drop,
   no-new-privileges, tmpfs /tmp, writable paths, red interna, sin binds,
   sin puertos, sin docker.sock)
3. auditar el candidato SOLO por hallazgos de aislamiento
4. si pasa: firmar y publicar
5. si falla: rechazar sin release
```

No hay Trivy, no hay Hadolint, no hay build aislado. El build real ocurre en el
deployment.

### 3. Clasificación de aislamiento

Bloquean:

```text
compose_privileged
compose_cap_add
compose_devices
compose_host_network_mode
compose_host_pid
compose_host_ipc
compose_host_uts
compose_host_userns
compose_host_cgroup
compose_docker_socket
compose_bind_absolute
compose_bind_escape
compose_mount_sensitive
compose_published_ports
compose_root_user
compose_security_opt_unsafe
compose_external_resource
compose_build_network_host
compose_build_privileged
compose_build_secrets
dockerfile_final_user_root
```

No bloquean (ni se evalúan como admisión):

```text
CVEs de cualquier severidad
Hadolint (DL3008, DL3025, etc.)
imágenes base viejas
lenguajes obsoletos (PHP 5, Python 2, etc.)
lockfiles desactualizados o muertos
estilo de Dockerfile
```

### 4. Probes

Se mantienen los tres niveles:

1. **Aislamiento**: non-root, `cap_drop`, `no-new-privileges`, read-only, sin
   privileged/devices/host namespaces, sin binds, sin puertos, red interna.
2. **Funcional**: HTTP/TCP/command independiente, imagen fijada por digest.
3. **Estabilidad**: ventana con N chequeos, servicio `running`, healthcheck
   `healthy` cuando exista y `RestartCount == 0`.

El probe de aislamiento es la autoridad final. El healthcheck puede venir de la
imagen y es opcional; si existe no se ignora un estado fallido.

### 5. Release

```json
{
  "release_id": "...",
  "isolation": {
    "verified": true,
    "probes": "passed"
  },
  "commit": "...",
  "artifact_sha256": "...",
  "hardened_tree_sha256": "...",
  "signature": "..."
}
```

No hay `advisories`, `risk_policy` ni `insecure`.

### 6. UI

- Deployments: release, hashes, probes, isolation.
- Sin badge de CVEs.
- Nota de responsabilidad: “la seguridad interna de la app es del dueño”.
- Deploy habilitado si aislamiento/source/operación lo permiten.

## INVARIANTS

- `I1` Trivy y Hadolint no se ejecutan en `harden` ni bloquean.
- `I2` Ningún hallazgo de aislamiento se ignora.
- `I3` Una app comprometida no alcanza host, Docker socket, panel ni otros
  tenants.
- `I4` La release no contiene advisories ni `insecure`.
- `I5` Los probes son la autoridad final de aislamiento.
- `I6` Un build real fallido bloquea el deploy.
- `I7` El contenido de la app (CVEs, PHP obsoleto, auth, uploads) es riesgo del
  tenant y no se evalúa.

## CHANGE SURFACE

```yaml
change_surface:
  allowed:
    - aspecs/0087-isolation-only-admission-policy.md
    - aspecs/0085-apps-trusted-deploy-frontend-e2e.md
    - scripts/dangerous_build/cli.py
    - scripts/dangerous_build/hardener.py
    - scripts/dangerous_build/compose.py
    - scripts/tests/test_dangerous_build_normalize.py
    - scripts/tests/test_transactional_build_hardener.py
    - scripts/e2e_apps_trusted_deploy.py
    - scripts/tests/test_e2e_apps_trusted_deploy.py
    - vendor/systutor-core/plugins/apps/backend/hardening/**
    - vendor/systutor-core/plugins/apps/backend/schemas.py
    - vendor/systutor-core/plugins/apps/backend/router.py
    - vendor/systutor-core/plugins/apps/backend/worker.py
    - vendor/systutor-core/plugins/apps/backend/catalog.py
    - vendor/systutor-core/plugins/apps/backend/releases/**
    - vendor/systutor-core/plugins/apps/backend/runtime/probes.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_hardening_engine.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_deploy_source.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_worker_github.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_manifest_flow.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_probes.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_service_lifecycle_secrets.py
    - vendor/systutor-core/plugins/apps/frontend/**
    - apps/web/src/i18n/es/apps.ts
  prohibited:
    - vendor/systutor-core/plugins/apps/backend/models.py
    - vendor/systutor-core/plugins/apps/backend/migrations/**
    - Dockerfile
    - docker-compose.yml
    - .env*
```

## PHASES

| Fase | Entrega | Gate |
|---|---|---|
| P0 | `harden` sin Trivy/Hadolint/BuildKit; auditoría solo de aislamiento | pytest |
| P1 | Política sin `gate`; release sin advisories/insecure | pytest |
| P2 | Probes/healthcheck de imagen por defecto | pytest |
| P3 | UI sin CVEs; muestra isolation/probes | tsc + vitest |
| P4 | E2E editores sin `--insecure-*` | live |
| P5 | Documentar egress como deuda aparte | doc |

## VERIFICATION

```bash
.venv/bin/python -m pytest \
  scripts/tests/test_dangerous_build_normalize.py \
  scripts/tests/test_transactional_build_hardener.py \
  scripts/tests/test_e2e_apps_trusted_deploy.py \
  vendor/systutor-core/plugins/apps/backend/tests -q

npm --prefix apps/web run build
npm --prefix apps/web run test

.venv/bin/python -m ruff check \
  scripts/dangerous_build \
  vendor/systutor-core/plugins/apps/backend \
  scripts/e2e_apps_trusted_deploy.py

git diff --check
```

Casos obligatorios:

- App con PHP 5/dependencias viejas pero aislamiento correcto → **deploy**.
- App con `docker.sock`, root, privileged o host network → **bloqueada**.
- App con build real roto → **bloqueada**.
- Probes de aislamiento fallidos → **rollback**.
- App sin healthcheck pero estable y con probe funcional verde → **deploy**.
- App con healthcheck declarado en estado `unhealthy` → **rollback**.
- `harden` no ejecuta Trivy/Hadolint (test que verifica que no se invocan).
- Release no contiene `advisories`/`insecure`.

## IMPACTO ESPERADO

- `software-de-gestion-para-editores` despliega sin `--insecure-gate`.
- `PHP 5`, `PyJWT 2.10.1`, `python-multipart 0.0.9`, `axios 1.15.1` dejan de
  bloquear.
- Solo root, docker.sock, privileged, binds, host namespaces y egress no
  autorizado bloquean.
- El panel muestra aislamiento/probes, no CVEs.

## ROLLBACK

Volver a 0083/0086. No hay migraciones ni cambios de datos.

## DEFINITION OF DONE

- [ ] `harden` no ejecuta Trivy ni Hadolint.
- [ ] No existe `gate`/`insecure`/advisories en la política ni en la release.
- [ ] Aislamiento, probes, firma y build real siguen bloqueando.
- [ ] UI sin CVEs; muestra isolation/probes.
- [ ] E2E editores sin `--insecure-*`.
- [ ] Suites, build, ruff y `git diff --check` en verde.
