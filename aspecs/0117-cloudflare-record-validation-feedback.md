# A.SPEC 0117 — Registros DNS de Cloudflare: feedback real y ejemplo de IP

## WHY

En producción, crear un registro `A` con `content: "test2.systutor.com"` produjo
un HTTP 422 de la API de Cloudflare. El backend descartó el cuerpo de error y
tradujo cualquier 400/422 a `CloudflareValidation("Cloudflare rejected the
request")`. El frontend, a su vez, muestra para **todo** 422 el texto
"Cloudflare is not configured correctly on this server. The OAuth client may
not be registered yet.". El operador culpó al cliente OAuth, que estaba
correctamente registrado y con todos los scopes.

Además, el campo de contenido no ofrecía ninguna pista sobre el formato
esperado, así que era fácil confundir `A` con `CNAME`.

## WHAT

1. El cliente HTTP conserva un **detalle acotado y sanitizado** del primer
   `errors[].message` de Cloudflare en `CloudflareError.detail`. Nunca guarda el
   cuerpo crudo, tokens ni identificadores de cuenta.
2. `_translate()` emite `domains.dns.cloudflare.upstream_validation` con el
   detalle sanitizado cuando hay un error de validación 400/422 de Cloudflare.
   Sin detalle, el mapeo existente permanece intacto.
3. El frontend usa ese detalle en el toast, en vez del texto genérico de OAuth.
4. Validación local de `A` (IPv4) y `AAAA` (IPv6) antes de llamar a la API, con
   mensajes accionables en español.
5. El textbox de contenido muestra un **placeholder tenue** con un ejemplo por
   tipo de registro (`203.0.113.10` para A, `2001:db8::1` para AAAA, etc.).

## CONTRACT

- `CloudflareError.detail` es `None` o un string de como máximo 160 caracteres,
   sin caracteres de control, JWTs, tokens `Bearer` ni IDs de 32 hexadecimales.
- `cloudflareErrorMessage(422)` sin código sigue devolviendo el mensaje
  genérico actual; el nuevo mensaje solo aparece con
  `code === "domains.dns.cloudflare.upstream_validation"` y un detalle no vacío.
- La validación local solo rechaza A/AAAA; los demás tipos siguen siendo
  validados por Cloudflare.
- No hay cambios de esquema ni migraciones (Alembic queda prohibido en dev).

## VERIFICATION

- `test_cloudflare_upstream_detail.py`: sanitización (canarios, JWT, 32-hex,
  truncamiento, cuerpo inválido) y mapeo `_translate`.
- `test_cloudflare_router.py`: un 422 con detalle llega al cuerpo de la
  respuesta con el código nuevo; los 422 sin detalle no cambian.
- `domains-cloudflare.logic.test.ts`: detalle en el toast, ejemplos por tipo y
  validación A/AAAA.
- `ruff check .`, `python3 -m pyright`, `python3 -m pytest tests -q` y
  `npm --prefix apps/web test` en verde.
