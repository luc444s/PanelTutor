# A.SPEC 0120 — No adjuntar la BD de un sitio rootless a `spanel-db`

## Problema

En producción (vmi3461574), al crear un sitio Hosting en una celda rootless,
el panel responde:

```
The site could not be provisioned: docker network: Error response from daemon: network spanel-db not found
```

Causa raíz: `vendor/systutor-core/plugins/hosting/backend/provisioner.py:181-186`
ejecuta incondicionalmente `network connect spanel-db <bd>` cuando están
activos `SPANEL_PHPMYADMIN_ARBITRARY` y `SPANEL_PHPMYADMIN_DB_NETWORK`.

`Provisioner.command()` (líneas 60-67) delega en `runtime.command` cuando el
sitio tiene un `ContainerRuntimeHandle`: en una celda rootless eso apunta al
**socket de la celda**, no al daemon rootful. La red `spanel-db` existe en el
daemon rootful; la celda solo tiene su red privada `spanel-<slug>-…`. El attach
falla y `Provisioner.create()` hace `cleanup()`, por lo que no queda rastro.

Además, el attach es innecesario en rootless: el acceso de phpMyAdmin a una BD
de una celda se hace mediante el relay efímero del host-agent
(`phpmyadmin_broker.py`, A.SPEC 0110-B). El propio
`service.py:1023-1024` ya documenta que *"A rootless site is reached only
through the ephemeral relay; it must never be attached to the rootful
phpMyAdmin network"*, pero `Provisioner` no respeta esa regla.

## Contrato

1. En `vendor/systutor-core/plugins/hosting/backend/provisioner.py`, dentro de
   `Provisioner.create()`, sustituir el bloque de attach (líneas 181-186) por:

   ```python
   db_network = self.settings.phpmyadmin_db_network.strip()
   rootless = self.runtime is not None and self.runtime.runtime == "rootless"
   if (
       not rootless
       and multi_database_enabled(self.settings.phpmyadmin_arbitrary, db_network)
   ):
       try:
           self.command(*connect_args(db_network, names.db))
       except ValueError as exc:
           raise Fallo(f"The database network is invalid: {exc}") from exc
   ```

   Se usa el mismo patrón `runtime is not None and runtime.runtime == "rootless"`
   que ya emplea el archivo en las líneas 156 y 321. No se modifica
   `multi_database_enabled()` ni `connect_args()` (`backend/network.py`).

2. El comportamiento rootful queda **byte-for-byte idéntico**: con
   `SPANEL_PHPMYADMIN_ARBITRARY=true` y `SPANEL_PHPMYADMIN_DB_NETWORK=spanel-db`,
   el daemon rootful sigue haciendo `network connect spanel-db <bd>`.

3. El comportamiento rootless: se omite el `network connect` y el sitio se
   crea usando la red privada de la celda. El acceso a phpMyAdmin sigue por el
   broker (`SPANEL_HOSTING_ROOTLESS_PMA_BROKER`, default `true`).

4. No se toca la validación de nombre de red: sigue ocurriendo en rootful y
   sigue lanzando `Fallo("The database network is invalid: …")` si el nombre es
   inválido.

## Criterios de aceptación

- Un sitio rootless con `phpmyadmin_arbitrary=True` y
  `phpmyadmin_db_network="spanel-db"` se crea sin intentar el attach y sin
  el error `network spanel-db not found`.
- Un sitio rootful con la misma configuración sí ejecuta
  `network connect spanel-db <bd>`.
- `cleanup()` sigue eliminando la red privada en rootless y no intenta borrar
  `spanel-db`.
- No se modifica el esquema; no se invoca Alembic ni el runtime migrador.

## Pruebas

Añadir tests unitarios (sin Docker real, usando el fake de runtime existente):

- En `vendor/systutor-core/plugins/hosting/backend/tests/test_network_attach.py`
  o `test_rootless_0110.py`: un caso con runtime `rootless` que asserted que
  **no** se llama a `network connect spanel-db`, y un caso rootful que asserted
  que **sí** se llama.
- Los tests existentes de `test_network_attach.py`, `test_rootless_0110.py`,
  `test_phpmyadmin_rootless_broker.py` y `test_database_alias.py` deben seguir
  pasando.

Comandos de verificación:

```bash
cd /data/data/com.termux/files/home/Proyectos/mailadmin
python3 -m pytest vendor/systutor-core/plugins/hosting/backend/tests -q
```

## Notas

- No hacer commit: el revisor (agente principal) integra y commitea.
- No desplegar en producción; el cambio se valida primero en `spanel.lab`.
- No tocar el archivo `aspecs/0110-b…` ni la configuración de env del panel.
