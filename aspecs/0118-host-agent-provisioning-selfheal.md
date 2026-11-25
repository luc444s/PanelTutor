# A.SPEC 0118 — Host agent provisioning self-heal

## Problema

La creación de tenants (`df3074f`) añadió la operación `provision` al
`spanel-plan-agent.service`, pero la unit del host seguía con el sandbox de la
época en que el agente solo aplicaba planes:

- `ProtectSystem=strict` + sin `/etc` escribible → `groupadd` falla con
  `cannot lock /etc/group` (exit 10).
- `ProtectHome=true` → falla `install -d ... /home/spanel-<slug>`.
- `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` → `nft` no puede abrir
  NETLINK_NETFILTER y falla con exit 3.
- `CapabilityBoundingSet=CAP_SETUID CAP_SETGID` → falla `install -o` (CAP_CHOWN)
  y la carga de perfiles AppArmor.

Además, el 502 del panel ocultaba el `PlanAgentError` original, por lo que
diagnosticar exigía sondas manuales desde el contenedor app.

## Contrato

1. La unit `spanel-plan-agent.service` genera todo lo que `provision` necesita:
   usuarios/grupos y subids, directorios de celda y home, reglas nftables
   (skuid), perfiles AppArmor, cgroups y el socket del daemon rootless. La
   autorización sigue siendo peer-cred + capability HMAC + gate local.
2. `install_tenant_agents.py --force` reescribe las units desde
   `scripts/tenant_cell/deploy/` y reinicia solo lo que cambió. `scripts/deploy.sh`
   lo ejecuta en cada deploy (con `SPANEL_SKIP_HOST_AGENTS=1` se puede omitir en
   máquinas de desarrollo sin systemd/root).
3. `spanel-agents-reconcile.{service,timer}` reaplica las units 2 minutos
   después del arranque y una vez al día. Los drop-ins (`*.service.d/`) son
   propiedad del operador y nunca se modifican.
4. `POST /plugins/tenant/tenants` responde 502
   `tenant.cell_provision_failed` con el `code` y mensaje acotado del agente,
   para que el fallo se diagnostique desde el panel.
5. El timeout del cliente del agente es de 60 s por defecto (override con
   `SPANEL_PLAN_AGENT_TIMEOUT`), porque `provision` tarda mucho más que
   `apply`/`verify`: crea usuario/grupo, directorios, reglas nftables, perfil
   AppArmor y espera a logind. Con 5 s el panel mostraba
   `timeout: host agent timed out`.

## Criterios de aceptación

- `install_tenant_agents.py --check` reporta las cuatro units y el timer activo.
- Tras `scripts/deploy.sh`, el host queda listo para crear tenants sin
  `systemctl edit` ni sondas Python: el deploy ya reaplica las units y habilita
  el timer.
- Un fallo de provisión muestra en la UI el motivo real (p. ej.
  `agent_error: ...`), no solo el texto genérico.

## Pruebas

- `scripts/tests/test_install_tenant_agents.py` verifica capacidades,
  `AF_NETLINK`, `ProtectSystem=off`, render del timer y su arranque.
- `vendor/systutor-core/plugins/tenant/backend/tests/test_tenant_create_resources.py`
  verifica que el mensaje del 502 incluye el código y detalle del agente.
