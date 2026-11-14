# A.SPEC 0081 — Verified Hardener Cache and Performance

## WHY

El hardener ejecuta trabajo pesado fuera de Python: pull de imágenes, Trivy,
BuildKit y smoke Compose. En apply repetía el gate completo tras haber publicado
exactamente el candidato ya validado. Una caché ingenua por tag o por ruta podría
ocultar cambios; la optimización debe conservar el contrato fail-closed.

## WHAT

1. Ejecutar Trivy filesystem y Hadolint en paralelo después del auditor interno.
2. Resolver imágenes externas a digest y cachear únicamente resultados Trivy
   asociados a digest inmutable, versión/política y TTL.
3. Evitar consultar el registry durante un TTL corto solo si el tag conserva una
   resolución local válida y la evidencia cacheada corresponde al mismo digest.
4. Después de apply, calcular un hash Merkle determinista del checkout y del
   staging, excluyendo únicamente metadatos `.git` y backups externos declarados.
   Previews, bytecode y cualquier otro archivo que pueda entrar en el contexto de
   build sí participan. Si coinciden, reutilizar el gate completo del staging.
5. `--revalidate-after-apply` fuerza el segundo gate completo para auditorías.
6. Exponer en JSON hit/miss de caché y timings sanitizados.

## CONTRACT

- Nunca cachear un tag mutable como identidad; la clave de scan es el digest.
- Cache miss, corrupción, versión/política distinta o TTL vencido ejecutan Trivy.
- Archivos de caché regulares `0600` bajo directorio `0700`; symlinks se ignoran.
- Reutilización post-apply requiere igualdad Merkle staging/fuente.
- Diferencia Merkle provoca rollback, no re-scan sobre estado incierto.
- El operador puede desactivar caché con `--no-image-cache`.

## INVARIANTS

```yaml
invariants:
  - id: P1
    statement: tags mutables nunca identifican resultados Trivy cacheados.
    proof: clave de scan incluye RepoDigest sha256.
  - id: P2
    statement: cache corrupta o expirada falla hacia ejecución real, no hacia éxito.
    proof: fixtures JSON inválido/TTL.
  - id: P3
    statement: post-apply solo reutiliza evidencia para árboles idénticos.
    proof: hash Merkle igual; mismatch revierte.
  - id: P4
    statement: modo forzado conserva doble gate completo.
    proof: --revalidate-after-apply y conteo de invocaciones.
  - id: P5
    statement: concurrencia no cambia resultados ni filtra stdout/stderr.
    proof: payload consolidado equivalente y salidas capturadas.
```

## CHANGE SURFACE

```yaml
allowed:
  - aspecs/0081-hardener-performance-cache.md
  - scripts/dangerous_build/**
  - scripts/tests/test_transactional_build_hardener.py
  - scripts/tests/test_dangerous_build_normalize.py
prohibited:
  - docker-compose.yml
  - Dockerfile
  - vendor/**
```

## VERIFICATION

```bash
.venv/bin/python -m pytest \
  scripts/tests/test_dangerous_build_normalize.py \
  scripts/tests/test_transactional_build_hardener.py \
  scripts/tests/test_app_deploy.py -q
.venv/bin/python -m ruff check scripts/dangerous_build scripts/tests
git diff --check
```

## DEFINITION OF DONE

- [x] Cache por digest y TTL probada.
- [x] Pull TTL probado.
- [x] Trivy/Hadolint paralelos.
- [x] Reutilización Merkle post-apply y revalidación forzada probadas.
- [x] Benchmark cold/warm ejecutado en lab.

## VALIDATION EVIDENCE

Benchmark lab sobre `odoo:18.0` ya presente en Docker, con caché propia vacía:

| Ejecución | Wall | Gate | Fase imagen | Pull | Scan |
|---|---:|---:|---:|---|---|
| cache cold | 8.850 s | 8.635 s | 5.230 s | registry | miss |
| cache warm | 2.803 s | 2.566 s | 0.026 s | cache | hit |
| cache disabled | 7.257 s | 7.062 s | 4.651 s | registry | miss |

La mejora warm fue ~68% en wall. El auditor Python tardó 0.003–0.008 s;
no es el cuello de botella. Trivy filesystem/Hadolint ocuparon 2.4–3.4 s y la
fase pull/Trivy image 4.7–5.2 s sin caché.

Apply real con fixture scratch: un gate completo, publicación, Merkle idéntico y
`gate_after_apply.status=reused`; wall 9.242 s, sin segundo build/scan/smoke y sin
recursos efímeros. Evidencias `0600`:

- `/home/lucas/lab-evidence/odoo-18-hardener-speed.json`
- `/home/lucas/lab-evidence/odoo-18-hardener-cold.json`
- `/home/lucas/lab-evidence/odoo-18-hardener-warm.json`
- `/home/lucas/lab-evidence/transactional-hardener-merkle-reuse.json`
