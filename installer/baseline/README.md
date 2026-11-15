# Base reproducible de PanelTutor

Esta base conserva únicamente la plataforma necesaria para una instalación
nueva. No intenta copiar usuarios, buzones, sitios ni aplicaciones del servidor
analizado.

## Incluido

- Traefik `v3.7.8`, sin dashboard público.
- Docker Mailserver `15.1.0` con SMTP, Submission e IMAPS.
- Roundcube `1.7.2` publicado por Traefik.
- phpMyAdmin `5.2.3` interno y con puerto diagnóstico en loopback.
- El Compose raíz de PanelTutor: app, worker, PostgreSQL 16 y Redis 7.
- Certificados web por Traefik y certificado SMTP/IMAP por Certbot.

## Excluido deliberadamente

- BIND: se recomienda DNS administrado externamente.
- POP3, puertos 110/995 y el puerto alternativo 994.
- Dashboard público de Traefik.
- Sitios WordPress/estáticos y aplicaciones existentes.
- Datos, contraseñas y certificados del servidor original.

## Contrato para el futuro `install.sh`

1. Validar Ubuntu 24.04/Debian 12, DNS, PTR, puertos y mínimo 4 GB RAM.
2. Instalar Docker Engine y Compose.
3. Crear `proxy` y `spanel-db` (`spanel-db` debe ser interna).
4. Crear bajo `PLATFORM_STATE_DIR` los directorios de Traefik, ACME, correo y
   Roundcube; crear `traefik/acme.json` con modo `0600`.
5. Levantar Traefik y `acme-webroot`.
6. Instalar Certbot, emitir el certificado de `MAIL_HOST` mediante webroot y
   configurar renovación con el agente existente de PanelTutor.
7. Levantar Docker Mailserver y crear la primera cuenta con `setup email add`.
8. Levantar Roundcube y phpMyAdmin.
9. Generar `.env.docker`, la clave de Apps y secretos aleatorios; levantar el
   Compose raíz pasando este archivo también como `--env-file` para interpolar
   `SPANEL_DOMAIN`.
10. Ejecutar verificaciones HTTPS, SMTP, Submission, IMAPS y healthchecks.

## Prueba manual del manifiesto

```bash
cp installer/baseline/.env.example installer/baseline/.env
# Editar dominios y correo ACME.

docker network inspect proxy >/dev/null 2>&1 \
  || docker network create proxy
docker network inspect spanel-db >/dev/null 2>&1 \
  || docker network create --internal spanel-db

docker compose \
  --env-file installer/baseline/.env \
  -f installer/baseline/compose.yml \
  config
```

El servicio de correo no arrancará hasta que exista el certificado Certbot en
`/etc/letsencrypt/live/MAIL_HOST/`. Esa secuencia será responsabilidad del
`install.sh`, para evitar certificados autofirmados en producción.

## Criterios de aceptación

- Solo Traefik publica `80/443`.
- Mailserver publica únicamente `25/465/587/993`.
- PostgreSQL, Redis y phpMyAdmin no son públicos.
- Los tres dominios tienen certificados válidos.
- Roundcube conecta a DMS por la red interna usando el hostname del certificado.
- PanelTutor crea/lista cuentas DMS y aprovisiona sitios mediante Docker.
