# A.SPEC 0092 — Apps source-only Node-RED adapter

## STATUS

Implemented and pending live revalidation against `luc444s/node-red`.

## WHY

The real black-box run against upstream Node-RED reached the Apps worker but
failed before audit because the source repository intentionally contains no
Dockerfile or Compose file. Requiring application owners to add deployment
files would mutate their repository and defeats source-only testing.

## CONTRACT

> When a checkout has no selected or discoverable Compose file, PanelTutor may
> materialize a deterministic, platform-owned overlay for an explicitly
> supported source layout. The overlay is audited, hardened, hashed and signed
> with the release; the GitHub checkout is never pushed or modified remotely.

For this slice, support is deliberately narrow:

- `package.json` name is exactly `node-red`;
- `package-lock.json`, `scripts.build`, `scripts.start`, and a compatible
  `engines.node >=N` declaration are mandatory;
- Node 24 builds the source using the upstream documented `npm ci`,
  `npm run build`, and `npm start` flow;
- runtime is non-root `1000:1000`, HOME and persistent data live under `/data`,
  and the only exposed container port is Node-RED's 1880;
- generated files are the root `.spanel-compose.yaml`, a Dockerfile under
  `.spanel-generated/`, and a conservative `.dockerignore`; any collision fails closed;
- an explicitly selected non-generated Compose path is never replaced.

No database migration or Alembic operation is required.

## PROOF

- Unit tests prove deterministic generation, existing-Compose precedence,
  explicit-selection preservation, and fail-closed metadata/collision cases.
- The mandatory live proof is inspect, build, signed deployment, non-root and
  isolation probes, redeploy, and cleanup through `spanel.lab`.
