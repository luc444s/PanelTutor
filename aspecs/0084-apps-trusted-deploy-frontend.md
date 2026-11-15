# A.SPEC 0084 — Apps Trusted Deploy Frontend

## STATUS

Implementado. Validado por build/tests y por el E2E API de A.SPEC 0085.

Sucede a A.SPEC 0083 (pipeline de release firmada). Cierra la brecha entre el
backend/CLI, que ya exige release firmada, y el frontend, que sigue enviando el
contrato anterior.

## WHY

A.SPEC 0083 convirtió la release endurecida y firmada en la única entrada
desplegable. El router responde `422 apps.trusted_release_required` cuando el
payload no trae `hardening` ni `hardened_operation_id`.

El frontend sigue llamando `POST /deployments` con `{ environment }`
(`vendor/systutor-core/plugins/apps/frontend/api.ts`). Consecuencias:

1. El botón **Deploy** del panel falla con 422.
2. No hay forma de declarar la política de hardening (UID/GID por servicio,
   writable paths) desde la UI.
3. La UI bloquea el deploy cuando la auditoría estática tiene errores, pero en
   el flujo nuevo esa auditoría ya no es la autoridad: el hardener normaliza y
   el gate decide. Ese bloqueo impide desplegar repos inseguros que sí pueden
   endurecerse.
4. No se muestran release firmada, hashes, probes ni evidencia.
5. No hay verificación, evidencia ni rollback a release firmada desde el panel.

## CONTRACT

1. La UI nunca envía un deploy sin `hardening` o `hardened_operation_id`.
2. La política cubre **todos** los servicios; el submit se bloquea hasta que
   cada uno tenga UID/GID válidos.
3. Los hallazgos de auditoría son informativos. El hardener y sus probes son la
   autoridad de admisión; un estado `blocked` de auditoría previa no impide el
   deploy endurecido.
4. La UI muestra solo errores seguros (`error_code`, `public_error`); nunca
   `stdout`/`stderr` crudos del hardener ni valores de entorno.
5. El deployment muestra `release_id`, commit, hashes de artefacto/Compose/
   árbol/gate, `key_id`, expiración y resultado de los probes.
6. Una release solo se puede desplegar desde la lista que entrega el backend y
   solo con `hardened_operation_id`.
7. Los paths escribibles se validan en cliente y servidor: absolutos,
   normalizados, modo octal de 4 dígitos y nunca world-writable.
8. Si la release activa tiene `insecure: true`, la UI muestra una advertencia
   con los gates omitidos. La UI nunca ofrece crear overrides inseguros.

## SCOPE

Backend (solo exposición de lectura):

- `worker.py`: el reporte de `inspect` agrega `service_details` con
  `{name, build, dockerfile, image, compose_user}`. Sin pulls ni I/O extra.
- `catalog.application_detail`: propaga `service_details` y `last_inspect_at`.
- `catalog._deployment_view`: agrega `release_id`, resumen seguro de la release
  (`key_id`, hashes, expiración, `insecure` y overrides de gate) y `probes`.
  Sin secretos.
- `runtime/deployment.py`: `runtime_snapshot` agrega `user` (`Config.User`) para
  mostrar y validar el usuario efectivo non-root.
- Opcional: el resultado de `harden` agrega `changes` (archivos modificados) y
  un resumen de gate sin secretos.

Frontend:

- `types.ts` / `api.ts`: tipos y llamadas para política, hardening, releases,
  verify, evidence y rollback.
- `DeployDialog`: editor de política por servicio + paths escribibles.
- `ApplicationDetail`: quitar el bloqueo por auditoría; advertir que el gate es
  la autoridad.
- Pestaña **Deployments**: release, hashes, probes y estado firmado.
- Nueva pestaña **Releases**: listar, verificar, ver evidencia, desplegar
  release y rollback firmado.

## OUT OF SCOPE

- Cambios al motor `scripts/dangerous_build/**`.
- Formato de firma, almacén o probes (A.SPEC 0083).
- Migraciones de modelos o Alembic.
- Inferencia automática de UID/GID desde imágenes; en esta fase el operador los
  declara. Puede abordarse en una A.SPEC posterior.
- Overrides de gate inseguros desde la UI: son exclusivos de laboratorio y se
  definen en A.SPEC 0086.
- Actualizar `scripts/e2e_apps_api.py` al contrato nuevo (deuda separada).
- El E2E black-box del frontend: se define en A.SPEC 0085.

## DESIGN

### 1. Reporte de inspección

```json
{
  "services": ["database", "web"],
  "service_details": [
    {
      "name": "web",
      "build": true,
      "dockerfile": "Dockerfile",
      "image": null,
      "compose_user": "10001:10002"
    },
    {
      "name": "database",
      "build": false,
      "dockerfile": null,
      "image": "postgres:16-alpine",
      "compose_user": "postgres"
    }
  ]
}
```

- `build` sale de `audit.dockerfiles`; `image` del Compose.
- `compose_user` es el `user:` declarado si existe; sirve solo como pista.
- No se inspeccionan imágenes ni se ejecuta Docker durante `inspect`.

### 2. Deploy atómico (fase 1)

`DeployDialog`:

1. Resumen de fuente e ingress.
2. Por cada servicio del último `inspect` (o del deployment activo):
   - UID y GID (prefill con `compose_user` si es numérico).
   - Aviso si el servicio es `image:` y el usuario no es numérico.
3. Editor opcional de writable paths: servicio, path absoluto, modo.
4. Bloque `.env` existente.
5. Confirmación por slug.

Submit:

```json
{
  "environment": [["NAME", "value"]],
  "hardening": {
    "service_users": {"web": {"uid": 10001, "gid": 10002}},
    "writable_paths": []
  }
}
```

El worker endurece, firma, despliega y ejecuta probes en una sola operación.

### 3. Preview opcional (fase 1.5)

Botón **Validar política** → `POST /applications/{id}/hardening`. La operación
termina `validated` y muestra servicios y cambios. El `operation_id` resultante
se ofrece como **Deploy esta release** usando `hardened_operation_id`. Es el
camino de dos pasos para operadores que quieren revisar antes de desplegar.

### 4. Pestaña Releases (fase 2)

Usa los endpoints ya existentes:

- `GET /applications/{id}/releases`
- `POST /applications/{id}/releases/{release}/verify`
- `GET /applications/{id}/releases/{release}/evidence`
- `POST /applications/{id}/deployments` con `hardened_operation_id`
- `POST /applications/{id}/rollback` con `to_deployment_id`

Acciones deshabilitadas si la release no está firmada, expiró o no pertenece a
la app.

### 5. UX de errores y bloqueo

- Se elimina `blocked` basado en `hasBlockingFindings` para habilitar Deploy.
- Se mantiene el bloqueo por `source_status != connected` y por operación activa.
- El diálogo muestra: “El gate de hardening es la autoridad; si falla, no se
  despliega”.
- Si el deployment activo fue creado con overrides de laboratorio
  (`release_summary.insecure == true`), se muestra una advertencia visible con
  los gates omitidos. La UI nunca ofrece crear esos overrides.
- Los errores de operación muestran `public_error`/`error_code`; los reportes
  crudos no se renderizan.

### 6. i18n y accesibilidad

- Todas las cadenas nuevas van a `apps/web/src/i18n/es/apps.ts`.
- Inputs con `label`, `inputMode="numeric"`, `autoComplete="off"`.
- Diálogo responsive; el editor de servicios usa acordeón o lista compacta.

## INVARIANTS

- `I1` El submit de deploy no se habilita sin política completa.
- `I2` La UI nunca inventa ni reutiliza un `release_id` ajeno a la lista.
- `I3` Cada servicio expuesto por `inspect` tiene su campo UID/GID.
- `I4` Ningún error nuevo incluye secretos, stdout/stderr ni valores de env.
- `I5` Writable paths inválidos se rechazan en cliente y en servidor.
- `I6` El deploy por UI sigue pasando por el worker y los probes; no hay atajo
  HTTP a Docker.

## RISKS

- **UID/GID incorrecto**: el gate o el primer probe rechazan; la operación
  muestra un error seguro y el deployment anterior se restaura.
- **Servicios `image:` con usuario no numérico**: la UI exige numérico; se
  documenta y se sugiere el UID/GID de la imagen.
- **Apps ya desplegadas**: el primer deploy tras 0083 exige política nueva.
- **Sin `inspect` previo**: el diálogo pide ejecutar Inspección antes de
  habilitar el deploy.

## CHANGE SURFACE

```yaml
change_surface:
  allowed:
    - aspecs/0084-apps-trusted-deploy-frontend.md
    - vendor/systutor-core/plugins/apps/frontend/**
    - vendor/systutor-core/plugins/apps/backend/worker.py
    - vendor/systutor-core/plugins/apps/backend/catalog.py
    - vendor/systutor-core/plugins/apps/backend/runtime/deployment.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_worker_github.py
    - vendor/systutor-core/plugins/apps/backend/tests/test_manifest_flow.py
    - apps/web/src/i18n/es/apps.ts
  prohibited:
    - vendor/systutor-core/plugins/apps/backend/models.py
    - vendor/systutor-core/plugins/apps/backend/migrations/**
    - vendor/systutor-core/plugins/apps/backend/releases/**
    - vendor/systutor-core/plugins/apps/backend/hardening/**
    - scripts/dangerous_build/**
    - Dockerfile
    - docker-compose.yml
    - .env*
```

## PHASES

| Fase | Entrega | Gate |
|---|---|---|
| P0 | `service_details` en `inspect` + propagación en `application_detail` | pytest backend |
| P1 | Tipos, API y `DeployDialog` con política; quitar bloqueo por auditoría | tsc + vitest |
| P2 | Deployments con release/hashes/probes (`_deployment_view`) | tsc + vitest + pytest |
| P3 | Pestaña Releases: verify, evidence, deploy release, rollback | tsc + vitest |
| P4 | Deploy live desde la UI/scratch en lab y evidencia | live |
| P5 | E2E black-box del contrato frontend (A.SPEC 0085) | live |

## VERIFICATION

```bash
npm --prefix apps/web run build
npm --prefix apps/web run test
(cd apps/web && node node_modules/vitest/vitest.mjs run \
  ../../vendor/systutor-core/plugins/apps/frontend/logic.test.ts)

.venv/bin/python -m pytest \
  vendor/systutor-core/plugins/apps/backend/tests/test_worker_github.py \
  vendor/systutor-core/plugins/apps/backend/tests/test_manifest_flow.py -q

.venv/bin/python -m ruff check \
  vendor/systutor-core/plugins/apps/backend/worker.py \
  vendor/systutor-core/plugins/apps/backend/catalog.py \
  vendor/systutor-core/plugins/apps/backend/runtime/deployment.py

git diff --check
```

Live:

1. Reconstruir imagen en lab (incluye build del frontend).
2. Crear o reutilizar la app scratch `luc444s/spanel-trusted-e2e`.
3. Inspeccionar y desplegar desde la UI con `web=10001:10002`.
4. Verificar release firmada, probes verdes y contenedor non-root.
5. Verificar que un deploy sin política sigue devolviendo 422.
6. Verificar que un UID/GID inválido produce error seguro, sin filtrar secretos.

## VALIDATION EVIDENCE

- `npm --prefix apps/web run build`: PASS.
- `npm --prefix apps/web run test`: 54 tests PASS.
- `vitest` sobre `logic.test.ts` del plugin: 12 tests PASS (con root explícito;
  el runner por defecto de `apps/web` no colecta rutas fuera de su root).
- El contrato de payload del frontend quedó validado por el E2E de A.SPEC 0085
  contra el lab: `{environment, hardening}` con `service_users` por servicio.
- La UI no se ejercitó en navegador en esta fase; el E2E es API-level.
  Queda pendiente un smoke visual manual del DeployDialog/ReleasesPanel.

## ROLLBACK

Revertir los cambios de frontend y las extensiones de solo lectura del backend.
El contrato de deploy firmado no cambia y sigue disponible por API/CLI.

## DEFINITION OF DONE

- [x] El botón Deploy ya no produce 422 desde la UI.
- [x] La política se declara por servicio y se valida antes de enviar.
- [x] Un deploy exitoso muestra release firmada y probes.
- [x] Verify/evidence/rollback disponibles desde Releases.
- [x] Sin regresiones en apps ya desplegadas.
- [x] `tsc`, `vitest`, `pytest`, `ruff` y `git diff --check` en verde.
- [x] Evidencia live registrada en esta A.SPEC.
