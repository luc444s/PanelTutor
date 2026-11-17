# A.SPEC 0095 — Apps Network Topology Preservation (N2)

> `risk: high` — cambia el aislamiento de red del Compose que se firma y
> ejecuta. Requiere spec, tests unitarios y E2E real antes de declarar
> compatibilidad general con Docker Compose.

## STATUS

Implementada y validada en `spanel.lab` (2026-11-17). N1 (`bb40f57`) se
conserva: corrige la destrucción de redes en el normalizador, pero su alcance
termina ahí. El hardener (`scripts/dangerous_build/compose.py`) aplanaba toda
la topología a una única red `default internal: true`; N2 lo corrige y el
release firmado conserva las redes de la aplicación.

Durante el E2E se encontró y corrigió un fallo adicional: en un deploy
parcial, el probe funcional solo inspeccionaba los servicios cambiados y
podía elegir una red donde el target del probe no resolvía. Ahora, cuando el
target está fuera del conjunto inspeccionado, la red se deriva de la topología
firmada. Cubierto por un test de regresión.

## PRINCIPIO — Network Security Contract v2

> Una aplicación puede conservar múltiples redes privadas, siempre que todas
> sus conexiones estén autorizadas, que no se amplíe involuntariamente su
> conectividad y que el aislamiento pueda verificarse.

Esto distingue cuatro decisiones que hoy están mezcladas en una sola regla:

1. **Aislamiento entre servicios** — qué servicios comparten red.
2. **Acceso a redes externas** — si un servicio puede alcanzar redes ajenas.
3. **Exposición pública** — ingress gestionado por Traefik, propiedad del panel.
4. **Redes externas autorizadas** — recursos con `external: true` admitidos
   explícitamente por el administrador.

## WHY

El defecto N1 se corrigió en el normalizador, pero el E2E de POS no podía
detectar el problema de fondo: el hardener elimina `services.<svc>.networks` y
sustituye el bloque superior por `networks: {default: {internal: true}}`. Un
stack legítimo con `frontend_net` y `database_net` queda, tras el harden, con
los tres servicios en la misma red: `frontend` puede alcanzar `db` aunque el
autor del Compose quiera lo contrario.

La segmentación de red es parte del contrato de la aplicación, no un detalle
de implementación. Aplanarla silenciosamente amplía la conectividad y rompe
aplicaciones válidas.

## DECISIONES DE RED

| Entrada | Comportamiento propuesto |
| --- | --- |
| Compose sin redes declaradas | Crear `default` con `internal: true`. |
| Compose con redes internas | Preservar nombres, membresías y aliases. |
| Servicio en múltiples redes | Conservar **todas** sus conexiones. |
| `networks: []` | No añadir conexiones implícitas sin política explícita. |
| `external: true` | Requiere autorización explícita (`authorized_external_networks`). |
| `network_mode: host` | Rechazar por seguridad. |
| `network_mode: service:` | Validar o rechazar explícitamente; nunca degradar en silencio. |
| `internal: false` | Evaluar conforme a política de salida (`egress_networks`); sin modificación silenciosa. |

**Advertencia:** no convertir automáticamente todas las redes existentes en
`internal: true`. Una red declarada `internal: false` debe conservarse solo si
la política de salida la autoriza; en caso contrario el harden falla con un
error explícito. La ausencia del campo `internal` sí significa "sin salida" y
puede fijarse a `true` con seguridad.

## CONTRATO

### Política de red

`HardeningPolicy` incorpora dos campos nuevos, firmados y verificados como el
resto de la política:

```json
{
  "authorized_external_networks": ["shared_net"],
  "egress_networks": ["upstream_net"]
}
```

- Ambos son listas de claves de red del Compose (no nombres Docker generados).
- Por defecto están vacíos: fail-closed. No existe autorización implícita.
- Un nombre declarado en la política pero no presente en el Compose es un error
  explícito, no una entrada ignorada.
- `name:` sobre una red autorizada `external` se permite solo si la red está en
  `authorized_external_networks`; en cualquier otra red sigue prohibido.

### Reglas del hardener

- `networks` ausente en un servicio: si existe el alias normalizado, se crea
  `default` con ese alias (comportamiento N1); si no, no se añade nada.
- `networks` como lista o diccionario: se convierte a diccionario conservando
  **todas** las redes, opciones y aliases; los aliases de N1 se fusionan sin
  duplicar ni sobrescribir.
- Toda red referenciada por un servicio debe estar declarada en el bloque
  superior; una referencia no declarada falla explícitamente.
- Bloque superior: se conservan las redes declaradas; `internal` ausente →
  `true`; `internal: true` → se conserva; `internal: false` → solo si la red
  está en `egress_networks`; `external` → solo si está en
  `authorized_external_networks`; `name` → solo para redes externas
  autorizadas; `driver: host` → rechazo explícito.
- `network_mode` presente → rechazo explícito. `host` y `container:*` por
  peligrosos; `service:*` porque comparte namespace y rompe la verificabilidad
  por servicio. Nunca se elimina en silencio.
- `networks: []` se conserva vacío: el servicio queda sin red, con su warning
  de evidencia. No se le asigna `default` "de forma conveniente".

### Verificación

- `audit_project` distingue recursos externos autorizados de no autorizados.
- `check_isolation` valida el flag `Internal` de cada red contra el Compose
  firmado: las redes `internal: false` solo son aceptables si el release
  firmado las declara así.
- `run_probes` ya no exige "exactamente una red": elige, para cada servicio,
  una red compartida con el objetivo del probe, y registra la topología usada.
- `deployment._override` etiqueta las redes propias con `OWNER_LABEL` y no
  intenta etiquetar redes externas autorizadas.
- Redeploy y rollback reutilizan el release firmado; no recreen mecanismos.
- Las pruebas de aislamiento usan **conexiones TCP reales** y `docker inspect`,
  no solo resolución DNS: que un hostname no resuelva no demuestra por sí solo
  que la red esté aislada.

## CRITERIOS DE ACEPTACIÓN

1. El Compose normalizado mantiene su topología.
2. El hardener no elimina ni fusiona redes autorizadas.
3. El release firmado conserva las membresías de red.
4. Docker verifica frontend → backend → db, y frontend **no** alcanza db.
5. Redeploy y rollback conservan el mismo aislamiento.
6. Las configuraciones incompatibles fallan explícitamente, sin degradarse a
   una red compartida.

## FUERA DE ALCANCE

- Cambiar los mecanismos de firma, redeploy o rollback.
- Hacer propiedad del panel una red externa autorizada.
- Soportar drivers de red arbitrarios o mallas multi-host.
- Exponer redes internas mediante publicación de puertos (sigue prohibido).
- Modificar el ingress de Traefik.

## TESTS

### Unitarios

- Topología preservada desde `networks` lista y diccionario.
- `internal` ausente → `true`; `internal: false` sin política → error;
  con política → conservado.
- `external: true` sin política → error; con política → conservado; `name:`
  solo con autorización.
- `network_mode: host` / `service:` / `container:` → error explícito.
- `networks: []` → sin conexiones implícitas.
- Aliases originales y añadidos presentes en cada red.
- Política rechazada si nombra redes no declaradas; firma y verificación
  incluyen la política de red.

### E2E live

Fixture de tres servicios y dos redes:

- `frontend` → `frontend_net`
- `backend` → `frontend_net` + `database_net`
- `db` → `database_net`

Debe demostrar:

1. `frontend` conecta por TCP con `backend` (alias original y alias N1).
2. `backend` conecta por TCP con `db` (alias original y alias N1).
3. `frontend` **no** conecta por TCP con `db`.
4. `docker inspect` muestra las membresías esperadas.
5. El Compose del release firmado conserva las dos redes.
6. Redeploy y rollback repiten 1–5 con la misma topología.

## ROLLBACK

Revertir los archivos de esta A.SPEC y reconstruir el worker. Los releases
firmados con la política anterior siguen verificando porque su política forma
parte del artifact firmado.

## Referencias

- `aspecs/0094-apps-compose-normalizer.md` — N1 y su alcance real.
- `bb40f57` — corrección N1 conservada.
- `docs/0094-apps-compose-normalizer-milestone.md` — evidencia del E2E de POS.
