# A.SPEC 0093 — Apps worker requires Compose v5

## STATUS

Implemented; pending live Node-RED deployment proof.

## WHY

The real black-box Node-RED run passed inspect, hardening, signing and image
build, then failed at container creation with:

```text
opening seccomp profile (builtin) failed: open <release>/source/builtin: no such file or directory
```

Docker Compose 2.32.4 resolves every labelled `security_opt` profile as a
checkout-relative **file**, including `seccomp=builtin`, `seccomp=default` and
`seccomp=runtime/default`. Docker Engine and Compose 5.x accept `builtin`
correctly. The platform was shipping a Compose version that cannot apply its
own mandatory seccomp envelope.

## CONTRACT

> The Apps worker must ship Docker Compose v5 or newer. The pinned version is
> part of the image and is asserted by packaging tests. Downgrading below v5
> is a release-blocking change.

## SCOPE

- Bump `DOCKER_COMPOSE_VERSION` to a current v5 release.
- Add a packaging regression test that rejects Compose 2.x and 3.x/4.x pins.
- Keep the hardening envelope unchanged: `seccomp=builtin` remains the
  required, Docker built-in profile.

No database migration or Alembic operation is required.

## PROOF

- Packaging tests pass.
- Live proof: unchanged `luc444s/node-red` must inspect, build, start
  non-root, pass isolation/functional/stability probes, redeploy and clean up.
