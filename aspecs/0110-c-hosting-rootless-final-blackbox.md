# A.SPEC 0110-C — Cierre final black-box de Hosting rootless por tenant

> `risk: high` — ceremonia final de aceptación de 0107–0110. Ejecuta creación,
> migración, administración, backups, phpMyAdmin y borrado sobre celdas rootless
> reales. Un PASS honesto cierra oficialmente la migración a userspaces por
> tenant; cualquier check omitido o fallido mantiene el cierre abierto.

## WHY

0110-A define altas/migración de WordPress y estáticos; 0110-B conserva un
phpMyAdmin Core compartido. Las suites unitarias no demuestran juntas que:

- todos los caminos de Hosting resuelven el mismo daemon rootless;
- los datos sobreviven a file manager, configuración, lifecycle y backup/restore;
- WordPress, MariaDB, estáticos e ingress están realmente en la celda del tenant
  y ausentes del daemon rootful;
- phpMyAdmin abre un relay temporal hacia la DB correcta y lo limpia;
- rollback, borrado y cleanup no afectan Core ni otro tenant;
- el producto puede instalarse/probarse de principio a fin sin comandos manuales
  ocultos ni evidencia fabricada.

Hace falta una sola prueba reproducible y autocontenida que use superficies
públicas para las funciones de producto y observación del host únicamente para
demostrar aislamiento/ubicación y realizar cleanup.

## WHAT

**Crear `scripts/e2e_0110_c_hosting_rootless_closure.py`: un arnés black-box,
autocontenido y autorreparable para prerrequisitos desechables. El script crea
un WordPress y un estático, prueba exhaustivamente Hosting, File Manager,
backup/restore y phpMyAdmin, demuestra que los recursos viven en una celda
rootless real y limpia todo. Solo `PASS` sin skips cierra oficialmente la
migración a tenants.**

“Autorreparable” no significa modificar el producto hasta que pase: significa
detectar y reconciliar de forma acotada el entorno desechable. El script nunca
parchea código, relaja seguridad ni convierte un error funcional en PASS.

## DEPENDENCIES

- A.SPEC 0107, 0108 y 0109-R4/R5 en PASS.
- A.SPEC 0110-A y 0110-B implementadas, con sus suites verdes.
- Host de laboratorio con cgroups v2, systemd, rootlesskit, Docker rootful,
  runtime de migraciones de plugins y permisos para crear una celda desechable.
- Imágenes fijadas o registradas en el lock de la prueba; acceso de red solo para
  pulls declarados durante setup.
- Prohibido ejecutar contra producción.

## SCRIPT ÚNICO

Crear:

```text
scripts/e2e_0110_c_hosting_rootless_closure.py
```

Interfaz:

```bash
sudo python3 scripts/e2e_0110_c_hosting_rootless_closure.py \
  --stage /var/tmp/spanel-e2e-0110c \
  --slug e2e0110c \
  --evidence artifacts/0110-c-hosting-rootless-final-e2e.json

# Diagnóstico/reanudación sin pasos manuales
--phase preflight|setup|seed|exercise|attest|cleanup|all
--resume
--keep-on-failure
--json
```

- Default: `--phase all`, cleanup incluso ante excepción/señal.
- `--keep-on-failure` solo para diagnóstico explícito y deja
  `cleanup_verified=false`; una corrida así nunca puede ser PASS oficial.
- Cada fase escribe un journal atómico en `stage/state.json`; `--resume` valida
  IDs/ownership antes de reutilizar recursos.
- El script registra comandos redactados, tiempos, retries y reparación aplicada.
- Exit `0`: PASS + cleanup; exit `1`: fallo de check/producto; exit `2`:
  precondición/seguridad; exit `3`: pruebas pasaron pero cleanup incompleto.

## FRONTERA BLACK-BOX

### Permitido

- API HTTP pública del panel para tenants, planes, Hosting, Domains,
  File Manager y phpMyAdmin proxy.
- CLI pública de 0110-A para migrar/rollback/finalize.
- CLI pública del host para provision/status/repair/plan/reconcile/deprovision.
- HTTP por los dominios publicados y login HTTP real de WordPress.
- Observación host read-only: `docker ps/inspect/info`, socket, procesos, uid_map,
  cgroups, listeners, logs de auditoría y hashes de configuración.
- DB clonada y servicios desechables únicamente durante setup, antes de comenzar
  los checks de producto.

### Prohibido

- Importar `HostingService`, provisioners o drivers para saltarse la API.
- Escribir directamente filas de sitios/runtime durante `exercise`/`attest`.
- Crear rutas, NAT, contenedores o volúmenes a mano para hacer pasar un check.
- Montar volúmenes de usuario desde el host para alterar/verificar contenido.
- Usar `/var/run/docker.sock` para operar recursos que el runtime marca rootless.
- Parchar checkout, editar perfiles AppArmor/seccomp, abrir DBs o falsear evidencia.
- Marcar `skip`, `expected failure`, `warning` o retry exitoso como sustituto de
  la postcondición final.

## ENTORNO AUTOCONTENIDO

El script crea y posee, con prefijo/labels únicos:

- una copia desechable de la DB del panel, nunca la DB viva;
- API, worker y dependencias necesarias apuntando a esa copia;
- tenant administrador y segundo tenant “intruso” para pruebas de aislamiento;
- celda rootless, plan **2 GiB / 1 CPU / PIDs acotados**, NAT y relay;
- sufijo/dominios `.lab` únicos;
- un sitio WordPress y un sitio estático;
- archivos, usuario/password y contenido fixture necesarios;
- store de backups y broker PMA desechables;
- evidencia, logs y journal bajo `--stage`.

Antes de setup captura:

- PID + hash de Config de Traefik, PMA Core, PowerDNS, mail y DB del panel;
- hashes de registry/planes/subuid/subgid/audit baseline;
- contenedores, listeners y rutas con el prefijo E2E;
- denied AppArmor/audit baseline;
- recursos del segundo tenant.

## AUTORREPARACIÓN ACOTADA

En `preflight/setup`, el script puede:

1. eliminar **solo** residuos con slug, labels, IDs y dominios exactos del fixture;
2. ejecutar el runtime migrador normal de systutor-core/plugins; nunca Alembic CLI;
3. provisionar o `repair` la celda fixture y reaplicar su plan por APIs/CLI
   soportadas;
4. reconciliar ingress, edge relay, DB broker y operaciones E2E huérfanas;
5. reiniciar únicamente API/worker/broker desechables creados por el script;
6. repetir una operación idempotente ante timeout/transitorio, máximo dos
   intentos con backoff y evidencia de ambos;
7. recuperar una descarga/ticket expirado creando una sesión/ticket nuevo, sin
   reutilizar credenciales ni alterar TTL.

No puede autorreparar:

- código o migraciones defectuosas;
- datos del sitio después de un restore incorrecto;
- runtime registrado falso;
- fuga cross-tenant;
- contenedor encontrado en daemon rootful;
- puerto DB permanente;
- DENIED/EPERM nuevo;
- cleanup de un recurso cuyo ownership no puede demostrar.

Cualquiera de esos casos es FAIL y queda descrito en `gaps[]`.

## FIXTURES Y FLUJO

### Fase 1 — Alta rootful y migración real

Para demostrar el migrador, el script arranca la API desechable con nuevas
migraciones rootless deshabilitadas y crea por API:

- `wordpress`: dominio `wp-<slug>.lab`;
- `static`: dominio `static-<slug>.lab`, perfil builtin `nginx`.

Siembra datos exclusivamente por superficies públicas:

- archivo marcador y árbol de directorios mediante File Manager;
- password conocido y verificable del usuario WordPress mediante endpoint;
- configuración editable (`WP_DEBUG=false`, `TZ=UTC` o valor válido);
- página/asset visible por HTTP.

Captura hashes/conteos lógicos. Luego habilita rootless en los procesos
desechables y ejecuta el CLI 0110-A para ambos sitios, en orden
`static → wordpress`. Debe quedar `retained`, nunca `finalized` todavía.

### Fase 2 — Administración completa post-migración

Ejecuta la matriz funcional descrita abajo sobre los dos mismos sitios ya
rootless.

### Fase 3 — Alta nueva rootless

Después de validar y borrar/finalizar de forma segura los fixtures migrados,
recrea los mismos dos nombres/dominios con la bandera activa. Deben nacer
rootless sin pasar por el daemon global. Se ejecuta un smoke de HTTP, runtime,
File Manager y delete. Esto demuestra tanto migración legacy como altas nuevas.

## MATRIZ FUNCIONAL OBLIGATORIA

Todos los checks aplicables deben pasar. Los `409 hosting_site_wrong_kind` del
estático son resultados positivos solo cuando se verifica que no mutaron nada.

### Ambos sitios

1. **Auth/RBAC/scope:** login real, permisos efectivos, `scope=tenant` aislado,
   `scope=all` exclusivo de plataforma y auditoría de mutaciones; JWT inválido y
   tenant intruso no obtienen metadata del recurso.
2. **Create/list/domain:** 201, aparecen solo en su tenant y HTTP público 200 con
   contenido esperado; el tenant intruso obtiene 404/403 sin metadata útil.
3. **Lifecycle:** stop vuelve el sitio no disponible, start recupera HTTP 200 y
   restart conserva contenido; estados y auditoría coherentes.
4. **Logs:** endpoint devuelve líneas del contenedor correcto, sin secretos.
5. **File Manager completo:**
   - list;
   - mkdir;
   - upload;
   - read/write de texto con control de versión;
   - rename;
   - download directo;
   - download ticket de un uso;
   - zip + extract;
   - delete individual + delete batch;
   - path traversal/absolute path rechazados;
   - contenido servido por HTTP después de escribir y preservado tras restart.
6. **Backup completo:** export, ticket/download ZIP, mutación posterior,
   import con confirmación, restauración del archivo/contenido original y
   rechazo de ticket consumido/confirmación incorrecta.
7. **Delete (fase 3):** sobre las altas nuevas recreadas después de finalizar los
   fixtures migrados, retira ruta, fila y solo recursos propios; HTTP deja de
   responder; otro sitio/tenant y Core permanecen intactos.

### WordPress

8. **Config:** GET, PATCH de whitelist, recreate en la celda, persistencia tras
   restart; variable DB/no-whitelist rechazada sin mutación.
9. **Database:** credenciales del sitio resueltas, `Cache-Control: no-store`, DB
   gestionada correcta y ningún puerto `3306` publicado.
10. **Usuarios:** listar admin; reset con password explícito y generado; probar
   login HTTP WordPress; respuesta y logs sin password.
11. **Salts:** rotar, demostrar cambio sin exponer valores, sesión previa deja de
    ser válida y WordPress vuelve a HTTP 200.
12. **Backup DB + archivos:** antes de export fija password A y marcador A;
    después cambia a password B/marcador B; tras import, A autentica, B falla y
    marcador A reaparece. Así se prueba restore de MariaDB y volumen sin SQL
    directo desde el arnés.
13. **phpMyAdmin Core compartido:** crear sesión, navegar por el proxy, comprobar
    la DB del sitio, bloquear re-login/cambio de servidor, cerrar sesión y
    demostrar listener/conector `0 → 1 → 0`; sesión del tenant intruso rechazada.
14. **WP-only guards:** endpoints WordPress operan en el runtime rootless y no
    recrean recursos en Docker global.

### Estático

15. **Perfiles estáticos:** list/get del builtin y CRUD completo de un perfil E2E
    desechable con permiso platform-only; conflicto/en-uso y validaciones se
    rechazan sin mutar el builtin.
16. **Perfil/health:** marker y web root del perfil correctos antes/después de
    migración, lifecycle y restore.
17. **Guards:** config, database, usuarios, reset, salts y PMA devuelven el error
    contractual WordPress-only sin crear DB, relay o recursos adicionales.

## ATESTACIÓN DE CELDA REAL

El PASS exige evidencia convergente, no solo una columna `runtime=rootless`:

1. API de inventario devuelve `runtime=rootless` para ambos `site.id`.
2. `docker info` del socket de celda declara daemon rootless y socket bajo
   `<data_root>/cells/<slug>/docker.sock`.
3. WordPress, MariaDB, estático e ingress aparecen por nombre/labels en el daemon
   de la celda y están ausentes del daemon rootful.
4. Labels `spanel.tenant`, `spanel.site`, `spanel.managed` y `cell-infra` son
   exactas; no hay recursos extranjeros en sus redes/volúmenes.
5. PID de dockerd pertenece al UID asignado, `uid_map` es no identidad y netns
   difiere del host.
6. `memory.max`, `cpu.max` y `pids.max` efectivos corresponden al plan agregado;
   contenedores cuelgan de la jerarquía del UID/celda.
7. Un solo endpoint/relay sirve simultáneamente ambos Hosts mediante el ingress.
8. MariaDB no expone `3306`; solo aparece un conector PMA durante su sesión.
9. No existen contenedores/volúmenes rootful sombra tras `finalize` ni al terminar
   las altas nuevas.
10. Core y segundo tenant conservan PID/hash/HTTP antes y después.

## ROLLBACK Y FINALIZE

- Antes del `finalize`, inducir una vez un fallo de verificación/ruta controlado
  mediante la superficie de test prevista por 0110-A, ejecutar rollback y
  demostrar HTTP/datos rootful restaurados.
- Repetir la migración limpiamente y verificarla.
- Ejecutar `finalize --confirm-domain` solo después de toda la matriz
  post-migración y del backup válido.
- Confirmar eliminación exacta de originales rootful y continuidad rootless.
- No se acepta simular rollback cambiando solo la fila runtime.

## EVIDENCIA

Escribir atómicamente:

```text
artifacts/0110-c-hosting-rootless-final-e2e.json
artifacts/0110-c-informe-cierre-tenants.md
```

JSON mínimo:

```json
{
  "spec": "0110-C",
  "result": "PASS|FAIL|BLOCKED",
  "ok": false,
  "environment": {},
  "baseline": {},
  "repairs": [],
  "fixtures": {},
  "checks": [],
  "runtime_attestation": {},
  "rollback": {},
  "finalize": {},
  "delta_denied": 0,
  "gaps": [],
  "cleanup": {},
  "cleanup_verified": false
}
```

- Cada check contiene `id`, `surface`, `expected`, `observed`, `pass`, duración y
  evidencia redactada.
- `result=PASS` requiere todos los checks `pass=true`, `gaps=[]`,
  `delta_denied=0`, rollback/finalize demostrados y `cleanup_verified=true`.
- No guardar JWT, passwords, cookies, capabilities, dumps, env files ni contenido
  sensible de clientes.

## CLEANUP

En `finally` y handlers de SIGINT/SIGTERM:

1. cerrar sesiones/relays/conectores PMA;
2. borrar sitios por API cuando sea posible;
3. reconciliar y retirar rutas/ingress del fixture;
4. eliminar solo contenedores, volúmenes y backups con ownership E2E exacto;
5. deprovisionar celda con purge del fixture;
6. retirar usuario/tenant/DB clonada y servicios desechables;
7. comparar hashes/listeners/Core con baseline;
8. dejar el artefacto fuera del directorio que se purga.

Si no puede demostrar ownership, no borra y reporta el recurso en
`cleanup.errors`; el resultado no puede ser PASS.

## OUT OF SCOPE

- Corregir bugs de producto dentro del script.
- Producción, DNS/ACME público real o datos de clientes.
- UI/browser automation; se prueban contratos HTTP/API y contenido público.
- Soak de horas, carga masiva o alta disponibilidad multi-host.
- Correo y migración del stack Core.
- Añadir nuevas funciones de Hosting: los defectos encontrados vuelven a
  0110-A/B para reparación y luego se repite 0110-C completa.

## CONTRACT

1. Una ejecución desde host limpio prepara todo sin pasos manuales y termina con
   un artefacto honesto.
2. Un WordPress y un estático rootful se migran conservando datos; luego la misma
   clase de sitios nace directamente rootless con la bandera activa.
3. Toda la matriz Hosting/File Manager/backup/PMA aplicable pasa después de la
   migración.
4. Atestación independiente demuestra daemon, UID, uid_map, netns, cgroups,
   labels, ausencia rootful y cero puerto DB permanente.
5. Rollback y finalize reales preservan/retiran los originales en el momento
   correcto.
6. Segundo tenant y Core permanecen intactos; no hay secretos ni DENIED nuevos.
7. Cleanup devuelve el host al baseline para todos los recursos propiedad del
   fixture.

## INVARIANTS

```yaml
invariants:
  - "El E2E usa API/CLI publicas; no llama servicios internos para saltarse contratos."
  - "Autorreparacion solo reconcilia recursos desechables propios; nunca parchea producto ni relaja seguridad."
  - "PASS exige todos los checks, cero skips, cero gaps, delta_denied=0 y cleanup verificado."
  - "Runtime se demuestra por registro y observacion del daemon/cgroup/netns real."
  - "MariaDB no publica 3306 y PMA deja cero relay/conector tras cada sesion."
  - "Backups restauran archivos y DB mediante comportamiento observable, no inspeccion directa."
  - "Rollback conserva rootful hasta verificar; finalize es explicito y posterior a la matriz."
  - "El tenant intruso y Core no cambian."
  - "No se capturan secretos en evidencia o logs."
  - "Sin produccion y sin Alembic CLI manual."
```

## VERIFICATION

Antes del E2E:

```bash
python3 -m pytest scripts/tests/test_e2e_0110_c_harness.py -q
ruff check \
  scripts/e2e_0110_c_hosting_rootless_closure.py \
  scripts/tests/test_e2e_0110_c_harness.py
```

Ejecución oficial:

```bash
sudo python3 scripts/e2e_0110_c_hosting_rootless_closure.py \
  --stage /var/tmp/spanel-e2e-0110c \
  --slug e2e0110c \
  --evidence artifacts/0110-c-hosting-rootless-final-e2e.json
```

El test unitario del arnés cubre al menos: redacción, journal/resume, retries
acotados, selección por ownership, signal cleanup, agregación FAIL y prohibición
de PASS con skip/gap/cleanup incompleto.

## Change Surface

```yaml
change_surface:
  allowed:
    - scripts/e2e_0110_c_hosting_rootless_closure.py
    - scripts/tests/test_e2e_0110_c_harness.py
    - artifacts/0110-c-hosting-rootless-final-e2e.json
    - artifacts/0110-c-informe-cierre-tenants.md
    - aspecs/0110-c-hosting-rootless-final-blackbox.md
  prohibited:
    - vendor/systutor-core/**
    - apps/web/**
    - scripts/tenant_cell/apparmor.py
    - docker-compose.yml
    - /opt/stacks/**
```

Si el E2E descubre un bug, se detiene, se amplía/reabre 0110-A o 0110-B de forma
explícita y se implementa allí. Después se ejecuta 0110-C completa desde cero;
no se amplía silenciosamente el change surface de la ceremonia.

## Traceability

- Requirement: aceptación final autocontenida/autorreparable de Hosting rootless
  y cierre oficial de la migración a tenants.
- Depends on: 0107, 0108, 0109-R4/R5, 0110-A y 0110-B.
- owner: lucas
- approver: pendiente
- Commit: pendiente
- Evidence: pendiente
- Deployment: exclusivamente `spanel.lab` hasta PASS.

## Criterio de cierre oficial

La migración a tenants se considera **oficialmente terminada** solo cuando:

1. el commit de 0110-A/B usado por la corrida está identificado;
2. `artifacts/0110-c-hosting-rootless-final-e2e.json` tiene `result=PASS` y
   `ok=true`;
3. todos los checks pasan sin skips/gaps;
4. rollback, finalize, PMA y backup/restore están demostrados;
5. `delta_denied=0` y `cleanup_verified=true`;
6. `artifacts/0110-c-informe-cierre-tenants.md` queda firmado/aprobado.

La existencia de esta spec o del script, por sí sola, no cierra la migración.

## Definition of Done

- [ ] Script único implementado, testeado y sin pasos manuales.
- [ ] Autorreparación acotada y journal/resume demostrados.
- [ ] WordPress + estático migrados y creados nuevos en celda real.
- [ ] Matriz completa Hosting/File Manager/backups/PMA en PASS.
- [ ] Atestación runtime/cgroup/netns/labels/ausencia rootful en PASS.
- [ ] Rollback y finalize reales en PASS.
- [ ] Segundo tenant y Core intactos, `delta_denied=0`.
- [ ] Cleanup verificado y evidencia/informe oficiales aprobados.
- [ ] Migración a tenants declarada cerrada oficialmente.
