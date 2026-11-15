# Plan del CLI de instalación y migración

## Objetivo

Construir un CLI para instalar la base de PanelTutor y migrar cargas desde
servidores cPanel, Plesk o Linux bare metal hacia contenedores administrados por
PanelTutor.

La primera etapa cubre:

- descubrimiento e inventario normalizado;
- migración de WordPress;
- migración de sitios estáticos;
- aprovisionamiento de cuentas en Docker Mailserver;
- sincronización de buzones por IMAP;
- planificación, reanudación y verificación.

El módulo DNS se integrará después mediante un contrato estable. Su
implementación no forma parte de esta etapa.

## Arquitectura del entrypoint

`installer/install.sh` será deliberadamente pequeño. Sus responsabilidades:

1. validar que exista Python;
2. crear o actualizar un entorno virtual;
3. instalar las dependencias bloqueadas del CLI;
4. ejecutar `python -m paneltutor_installer` con los argumentos recibidos.

La lógica de negocio, conexiones, inventarios, estado y migraciones vivirá en
Python. No se implementarán migraciones complejas en Bash.

Ejemplos esperados:

```bash
./installer/install.sh doctor
./installer/install.sh source add
./installer/install.sh discover
./installer/install.sh inventory list
./installer/install.sh plan
./installer/install.sh migrate wordpress sitio-123 --apply
./installer/install.sh migrate mail dominio-123 --apply
./installer/install.sh status
./installer/install.sh resume migracion-123
./installer/install.sh verify migracion-123
```

Las operaciones serán de solo lectura o plan por defecto. Todo cambio requerirá
`--apply` u otra confirmación explícita.

## Estructura propuesta

```text
installer/
├── install.sh
├── pyproject.toml
├── baseline/
└── src/paneltutor_installer/
    ├── __main__.py
    ├── cli.py
    ├── config.py
    ├── state.py
    ├── runner.py
    ├── models/
    │   └── inventory.py
    ├── providers/
    │   ├── base.py
    │   ├── cpanel.py
    │   ├── plesk.py
    │   └── baremetal.py
    ├── discovery/
    │   ├── wordpress.py
    │   ├── static.py
    │   └── mail.py
    ├── migration/
    │   ├── wordpress.py
    │   ├── static.py
    │   └── mail.py
    └── verification/
        ├── web.py
        ├── mail.py
        └── dns.py
```

## Proveedores de origen

### Bare metal

Será el primer proveedor real porque se puede desarrollar y probar sin software
propietario. Operará por OpenSSH y descubrirá:

- virtual hosts Apache/Nginx;
- document roots;
- instalaciones WordPress y `wp-config.php`;
- bases de datos relacionadas;
- versiones y extensiones PHP;
- páginas estáticas;
- cron jobs y certificados observables;
- datos necesarios para conectar a servidores IMAP.

### cPanel

Orden de preferencia:

1. WHM API y cPanel UAPI con token de acceso;
2. SSH como fallback autorizado.

Descubrirá cuentas, dominios, document roots, WordPress, bases MySQL, buzones,
alias, forwarders, cuotas, versiones PHP y cron jobs.

PanelTutor y el entorno de desarrollo no requieren una licencia cPanel. Las API
se ejecutarán únicamente contra el servidor de origen que ya tenga una licencia
válida.

### Plesk

Usará API REST/XML y, cuando corresponda, la CLI remota mediante SSH. Expondrá
suscripciones, dominios, instalaciones WordPress, bases, buzones, alias y
forwarders en el mismo modelo normalizado.

## Desarrollo sin licencias propietarias

cPanel y Plesk se desarrollarán contra fixtures versionados y servidores HTTP
falsos:

```text
installer/tests/fixtures/
├── cpanel/
│   ├── accounts.json
│   ├── domains.json
│   ├── wordpress.json
│   ├── databases.json
│   ├── email-accounts.json
│   └── forwarders.json
└── plesk/
    ├── subscriptions.json
    ├── domains.json
    ├── wordpress.json
    ├── databases.json
    └── mailboxes.json
```

Los tests cubrirán autenticación, paginación, timeouts, errores, respuestas
incompletas y diferencias entre versiones. Cuando exista acceso autorizado a un
servidor real, se podrán capturar respuestas anonimizadas como fixtures de
regresión.

No se instalará, emulará ni eludirá el licenciamiento de cPanel/Plesk.

## Inventario normalizado

Todos los proveedores producirán los mismos recursos:

```json
{
  "source": {},
  "domains": [],
  "sites": [],
  "databases": [],
  "mailboxes": [],
  "aliases": [],
  "forwarders": [],
  "certificates": [],
  "warnings": []
}
```

El motor de migración trabajará con este inventario y no dependerá directamente
de la API del proveedor.

## Clasificación de sitios

```text
wordpress
static
php-generic
proxy/application
unknown
```

Solo `wordpress` y `static` se migrarán automáticamente en la primera etapa.
Una aplicación PHP no debe clasificarse como estática; `php-generic`,
`proxy/application` y `unknown` producirán un plan de revisión manual.

## Migración WordPress

1. Descubrir versión PHP, extensiones, tamaño, dominio y multisite.
2. Obtener un dump consistente mediante WP-CLI o `mysqldump`.
3. Copiar archivos y preservar `wp-content`/uploads.
4. Aprovisionar WordPress y MariaDB aislados.
5. Importar la base.
6. Aplicar `wp search-replace` para datos serializados.
7. Publicar en un dominio temporal y verificar.
8. Ejecutar una sincronización final.
9. Solicitar el cutover de dominio/DNS.
10. Mantener el origen intacto para rollback.

El CLI nunca eliminará automáticamente el sitio de origen.

## Migración de sitios estáticos

1. Detectar document root, rewrites y redirects.
2. Copiar HTML, CSS, JavaScript y assets conservando metadatos necesarios.
3. Generar el contenedor Nginx administrado por PanelTutor.
4. Probar con dominio temporal.
5. Comparar respuestas, recursos y enlaces.
6. Solicitar el cutover y verificar HTTPS.

## Migración de correo

### Aprovisionamiento

- descubrir dominios, buzones, alias, forwarders y cuotas;
- crear cuentas equivalentes en Docker Mailserver;
- generar o solicitar contraseñas nuevas cuando sea necesario;
- no asumir que los hashes de cPanel/Plesk son compatibles con DMS.

### Sincronización

Se usará `imapsync` en varias pasadas:

1. copia inicial completa;
2. validación de carpetas y cantidades;
3. sincronización incremental previa al cutover;
4. cambio de MX mediante el futuro módulo DNS;
5. última sincronización delta;
6. verificación SMTP, Submission e IMAPS.

Se preservarán carpetas, flags y fechas. Sieve, autorespuestas y filtros
específicos del proveedor necesitarán conversores independientes.

## Estado y reanudación

SQLite mantendrá estado en:

```text
/var/lib/paneltutor-installer/state.db
```

Registrará fuentes, inventarios, planes, jobs, checkpoints, verificaciones y
errores. No almacenará contraseñas, tokens ni claves privadas.

Cada operación debe ser idempotente y reanudable. Un fallo en un recurso no
debe obligar a repetir migraciones ya verificadas.

## Seguridad

- OpenSSH del sistema, preferentemente con claves.
- Tokens y contraseñas por prompt, archivo `0600` o variables efímeras.
- Nunca incluir secretos en argumentos, logs, SQLite o JSON de inventario.
- Redacción centralizada de logs.
- Timeouts y límites para comandos remotos.
- Host keys verificadas; no usar `StrictHostKeyChecking=no` por defecto.
- `--apply` obligatorio para escrituras.
- El origen nunca se modifica ni elimina automáticamente.
- Plan y artefactos firmados o identificados por checksum antes de aplicar.

## Tecnologías

- Typer para comandos y subcomandos.
- Rich para tablas, progreso y errores legibles.
- Pydantic para configuración y modelos.
- SQLite para estado local.
- OpenSSH mediante subprocess para acceso remoto.
- httpx para APIs.
- WP-CLI y herramientas nativas de base de datos.
- imapsync para buzones.

Paramiko queda fuera del MVP; OpenSSH soporta mejor agentes, ProxyJump,
configuración del usuario y políticas de host keys.

## Integración futura con DNS

El CLI no conocerá detalles internos del módulo DNS. Consumirá un contrato como:

```text
dns.inspect(domain)
dns.plan(records)
dns.apply(plan_id)
dns.verify(domain, expected_records)
dns.rollback(plan_id)
```

Mientras no exista esa integración, el CLI generará el plan de registros y
pausará el job en `awaiting_dns_cutover`. El operador podrá continuar con:

```bash
./installer/install.sh resume migracion-123 --dns-confirmed
```

## MVP

1. Shell bootstrap y CLI Python.
2. Modelos de inventario y SQLite.
3. `doctor` y proveedor bare metal por SSH.
4. Fixtures y mocks cPanel/Plesk.
5. Inventario JSON saneado y comando `plan`.
6. Migración de un WordPress.
7. Migración de un sitio estático.
8. Migración de una cuenta IMAP.
9. `status`, `resume` y `verify`.
10. Integración con el módulo DNS cuando su contrato esté disponible.

## Fuera del MVP

- migraciones masivas sin revisión;
- borrado automático del origen;
- aplicaciones PHP arbitrarias;
- conversión universal de filtros de correo;
- automatización dependiente de una licencia local cPanel/Plesk;
- gestión interna del proveedor DNS.
