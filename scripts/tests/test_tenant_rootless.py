"""Unit/integration tests for the tenant-rootless runtime (A.SPEC 0096).

Run from the repository root:

    .venv/bin/python -m pytest scripts/tests/test_tenant_rootless.py -q
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CORE = ROOT / "vendor" / "systutor-core"
for candidate in (CORE, CORE / "src"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from plugins.apps.backend.releases.admission import (
    AdmissionRejected,
    admit_compose,
    admit_compose_file,
)
from plugins.apps.backend.runtime.probes import (
    ProbeFailed,
    build_rootless_evidence,
    check_tenant_rootless_isolation,
    rootless_daemon_evidence,
)
from plugins.apps.backend.runtime.runner_factory import (
    RUNTIME_HARDENED,
    RUNTIME_TENANT_ROOTLESS,
    TenantSocketMissing,
    build_tenant_runner,
    resolve_runtime,
    runner_for,
    socket_for_tenant,
    tenant_environment,
)
from plugins.apps.backend.runtime.tenant_daemon import (
    TenantDaemonConfig,
    TenantPreflightError,
    check_socket_health,
    preflight,
    render_apparmor_profile,
    render_systemd_unit,
    validate_tenant,
)
from plugins.apps.backend.runtime.types import AppDeployError


class Result:
    def __init__(self, returncode: int = 0, stdout: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


class FakeRunner:
    transport = "local"

    def __init__(self, responses: dict[str, Result] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[list[str]] = []

    def run(self, argv, *, check=True, **_kwargs):
        self.calls.append(list(argv))
        joined = " ".join(argv)
        for key, value in self.responses.items():
            if key in joined:
                return value
        return Result(0, "")


class InspectRunner:
    transport = "local"

    def __init__(self, payload: dict, *, top_uid: str = "10001") -> None:
        self.payload = payload
        self.top_uid = top_uid

    def run(self, argv, *, check=True, **_kwargs):
        if argv[:3] == ["docker", "container", "inspect"]:
            return Result(0, json.dumps([self.payload]))
        if argv[:2] == ["docker", "top"]:
            return Result(0, f"PID UID\n1 {self.top_uid}\n")
        return Result(0, "")


def config(tenant: str = "acme") -> TenantDaemonConfig:
    return TenantDaemonConfig.for_tenant(tenant, proxy_ip="192.168.18.11")


# --- profile selection ------------------------------------------------------


def test_default_profile_is_hardened() -> None:
    assert resolve_runtime({}) == RUNTIME_HARDENED
    assert resolve_runtime({"SPANEL_APPS_RUNTIME": ""}) == RUNTIME_HARDENED


def test_global_and_per_tenant_profile_selection() -> None:
    assert resolve_runtime({"SPANEL_APPS_RUNTIME": RUNTIME_TENANT_ROOTLESS}) == RUNTIME_TENANT_ROOTLESS
    env = {
        "SPANEL_APPS_RUNTIME": RUNTIME_HARDENED,
        "SPANEL_APPS_RUNTIME_TENANT_BETA": RUNTIME_TENANT_ROOTLESS,
    }
    assert resolve_runtime(env, "beta") == RUNTIME_TENANT_ROOTLESS
    assert resolve_runtime(env, "alpha") == RUNTIME_HARDENED


def test_unknown_profile_fails_closed() -> None:
    with pytest.raises(AppDeployError):
        resolve_runtime({"SPANEL_APPS_RUNTIME": "runc"})


def test_tenant_env_never_reuses_global_docker_host() -> None:
    env = {"DOCKER_HOST": "unix:///var/run/docker.sock"}
    a = tenant_environment("alpha", env)
    b = tenant_environment("beta", env)
    assert a["DOCKER_HOST"] == "unix:/run/spanel/tenants/alpha/docker.sock"
    assert b["DOCKER_HOST"] == "unix:/run/spanel/tenants/beta/docker.sock"
    assert a["DOCKER_HOST"] != b["DOCKER_HOST"]
    assert env["DOCKER_HOST"] == "unix:///var/run/docker.sock"


def test_tenant_runner_is_fail_closed_on_missing_socket() -> None:
    env = {"SPANEL_APPS_RUNTIME": RUNTIME_TENANT_ROOTLESS}
    with pytest.raises(TenantSocketMissing):
        build_tenant_runner("acme", env, config=config("acme"))


def test_tenant_runner_binds_to_socket_when_present(tmp_path: Path) -> None:
    cfg = TenantDaemonConfig.for_tenant("acme", socket_root=str(tmp_path))
    cfg.socket.parent.mkdir(parents=True, exist_ok=True)
    cfg.socket.touch()
    env = {"SPANEL_APPS_RUNTIME": RUNTIME_TENANT_ROOTLESS}
    try:
        runner = build_tenant_runner("acme", env, config=cfg)
        assert runner.environ["DOCKER_HOST"] == f"unix:{cfg.socket}"
        assert runner.runtime_profile == RUNTIME_TENANT_ROOTLESS
    finally:
        cfg.socket.unlink()


def test_runner_for_hardened_uses_legacy_factory() -> None:
    seen = {}

    def factory(transport, environ):
        seen["transport"] = transport
        return Result(0, "legacy")

    runner = runner_for("acme", {}, transport="ssh", legacy_factory=factory)
    assert runner.returncode == 0
    assert seen == {"transport": "ssh"}


def test_tenant_validation_and_ingress_paths() -> None:
    with pytest.raises(AppDeployError):
        validate_tenant("../host")
    assert socket_for_tenant("a") != socket_for_tenant("b")


# --- AppArmor profile generation -------------------------------------------


def test_apparmor_profile_template_is_complete() -> None:
    text = render_apparmor_profile(config())
    for token in ("capability,", "network,", "mount,", "umount,", "pivot_root,",
                  "ptrace,", "signal,", "unix,", "file,", "dbus,"):
        assert token in text
    assert "profile spanel-tenant-acme" in text
    assert str(config().data_root) in text
    assert "deny /etc/shadow rwk," in text


def test_apparmor_deny_rules_never_use_ix() -> None:
    text = render_apparmor_profile(config(), deny_paths=("/secret/**",))
    assert "deny /secret/** rwk," in text
    assert "ix" not in text.split("# Paths denied")[1]
    with pytest.raises(AppDeployError):
        render_apparmor_profile(config(), deny_paths=("/secret/** ix",))
    # A path that merely contains the letters "ix" is not an ix qualifier.
    assert "deny /prefix/** rwk," in render_apparmor_profile(
        config(), deny_paths=("/prefix/**",)
    )


def test_systemd_unit_uses_aa_exec_and_spike_flags() -> None:
    unit = render_systemd_unit(config())
    assert "aa-exec -p spanel-tenant-acme --" in unit
    assert "--iptables=false" in unit
    assert "DOCKERD_ROOTLESS_ROOTLESSKIT_DETACH_NETNS=0" in unit
    assert "SLIRP4NETNS_SANDBOX=false" in unit
    assert "--bridge=none" not in unit


# --- preflight fail-closed --------------------------------------------------


def test_preflight_requires_every_prerequisite() -> None:
    good = {
        "runsc": Result(0),
        "rootlesskit": Result(0),
        "aa-exec": Result(0),
        "apparmor_parser": Result(0),
        "apparmor/profiles": Result(0),
        "cgroup.controllers": Result(0, "cpu memory pids io"),
        "nft list ruleset": Result(0),
    }
    evidence = preflight(FakeRunner(good), config())
    assert evidence["fail_closed"] is True
    assert evidence["prerequisites"]

    for missing in ("runsc", "apparmor/profiles", "nft list ruleset"):
        broken = dict(good)
        broken[missing] = Result(1)
        with pytest.raises(TenantPreflightError):
            preflight(FakeRunner(broken), config())


def test_preflight_rejects_incomplete_cgroup_delegation() -> None:
    good = {
        "runsc": Result(0), "rootlesskit": Result(0), "aa-exec": Result(0),
        "apparmor_parser": Result(0), "apparmor/profiles": Result(0),
        "cgroup.controllers": Result(0, "cpu io"), "nft list ruleset": Result(0),
    }
    with pytest.raises(TenantPreflightError, match="cgroup"):
        preflight(FakeRunner(good), config())


def test_socket_health_requires_rootless() -> None:
    runner = FakeRunner({"info": Result(0, '["name=rootless","name=seccomp"]')})
    assert check_socket_health(runner, config())["rootless"] is True
    runner = FakeRunner({"info": Result(0, '["name=seccomp"]')})
    with pytest.raises(TenantPreflightError):
        check_socket_health(runner, config())


# --- admission --------------------------------------------------------------


def compose(**service):
    return {"services": {"web": {"image": "nginx@sha256:" + "a" * 64, **service}}}


def admit(payload, **overrides):
    base = {
        "tenant": "acme",
        "data_root": Path("/var/lib/spanel/tenants/acme/docker"),
        "compose_sha256": "b" * 64,
        "signature": "sig",
        "image_digests": {"web": "sha256:" + "a" * 64},
    }
    base.update(overrides)
    return admit_compose(payload, **base)


def test_admission_accepts_original_compose_with_bind_and_port(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    data_root.mkdir()
    payload = {
        "services": {
            "web": {
                "image": "nginx@sha256:" + "a" * 64,
                "ports": ["18085:80"],
                "volumes": [f"{data_root}/html:/usr/share/nginx/html:ro"],
                "security_opt": ["no-new-privileges:true"],
            }
        }
    }
    evidence = admit(payload, data_root=data_root)
    assert evidence["profile"] == RUNTIME_TENANT_ROOTLESS
    assert evidence["no_hardener"] is True
    assert "hardened_tree_sha256" not in evidence
    assert evidence["services"] == ["web"]


@pytest.mark.parametrize(
    ("service", "message"),
    [
        ({"privileged": True}, "privileged"),
        ({"devices": ["/dev/fuse"]}, "devices"),
        ({"network_mode": "host"}, "host networking"),
        ({"pid": "host"}, "host pid"),
        ({"volumes": ["/var/run/docker.sock:/var/run/docker.sock"]}, "Docker socket"),
        ({"volumes": ["/etc/shadow:/shadow:ro"]}, "outside the tenant"),
        ({"security_opt": ["seccomp:unconfined", "no-new-privileges:true"]}, "unconfined"),
        ({"security_opt": []}, "no-new-privileges"),
        ({"cap_add": ["SYS_ADMIN"]}, "capabilities"),
        ({"runtime": "runc"}, "runc"),
    ],
)
def test_admission_rejects_unsafe_declarations(service, message) -> None:
    payload = compose(**service)
    payload["services"]["web"].setdefault("security_opt", ["no-new-privileges:true"])
    with pytest.raises(AdmissionRejected, match=message):
        admit(payload)


def test_admission_rejects_unpinned_image_without_digest() -> None:
    payload = {"services": {"web": {"image": "nginx:latest", "security_opt": ["no-new-privileges:true"]}}}
    with pytest.raises(AdmissionRejected, match="digest"):
        admit(payload, image_digests={})


def test_admit_compose_file_preserves_bytes_and_hashes(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    data_root.mkdir()
    path = tmp_path / "compose.yml"
    body = "\n".join([
        "services:",
        "  web:",
        "    image: nginx@sha256:" + "a" * 64,
        "    ports: ['18085:80']",
        "    security_opt: ['no-new-privileges:true']",
    ])
    path.write_text(body, encoding="utf-8")
    before = path.read_bytes()
    evidence = admit_compose_file(
        path, tenant="acme", data_root=data_root, signature="sig",
        image_digests={"web": "sha256:" + "a" * 64},
    )
    assert path.read_bytes() == before
    assert evidence["compose_sha256"] and len(evidence["compose_sha256"]) == 64
    assert yaml.safe_load(body)["services"]["web"]["ports"] == ["18085:80"]


# --- probes and evidence ----------------------------------------------------


def container(**overrides):
    value = {
        "State": {"Status": "running", "RestartCount": 0},
        "HostConfig": {
            "Runtime": "runsc",
            "Privileged": False,
            "Devices": [],
            "PidMode": "",
            "IpcMode": "",
            "NetworkMode": "tenant_default",
            "SecurityOpt": ["no-new-privileges:true"],
            "PortBindings": {"80/tcp": [{"HostIp": "192.168.18.11", "HostPort": "18085"}]},
        },
        "AppArmorProfile": "spanel-tenant-acme (enforce)",
        "Config": {"User": "0:0"},
        "Mounts": [{"Type": "bind", "Source": "/var/lib/spanel/tenants/acme/docker/html"}],
        "NetworkSettings": {"Networks": {"tenant_default": {}}},
    }
    for key, changes in overrides.items():
        if isinstance(value.get(key), dict) and isinstance(changes, dict):
            value[key].update(changes)
        else:
            value[key] = changes
    return value


def test_tenant_isolation_probe_accepts_valid_container() -> None:
    evidence = check_tenant_rootless_isolation(
        InspectRunner(container()), {"web": "cid"}, config()
    )
    assert evidence["web"]["runtime"] == "runsc"
    assert evidence["web"]["apparmor"].startswith("spanel-tenant-acme")


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda: {"AppArmorProfile": "docker-default"}, "profile"),
        (lambda: {"HostConfig": {"Runtime": "runc"}}, "runsc"),
        (lambda: {"State": {"RestartCount": 1}}, "restarted"),
        (lambda: {"HostConfig": {"Privileged": True}}, "privileged"),
        (lambda: {"HostConfig": {"PidMode": "host"}}, "host namespace"),
        (lambda: {"HostConfig": {"PortBindings": {"80/tcp": [{"HostIp": "0.0.0.0"}]}}}, "unrestricted IP"),
    ],
)
def test_tenant_isolation_probe_rejects_violations(mutate, message) -> None:
    with pytest.raises(ProbeFailed, match=message):
        check_tenant_rootless_isolation(
            InspectRunner(container(**mutate())), {"web": "cid"}, config()
        )


def test_tenant_isolation_probe_rejects_host_uid_zero() -> None:
    with pytest.raises(ProbeFailed, match="UID 0"):
        check_tenant_rootless_isolation(
            InspectRunner(container(), top_uid="0"), {"web": "cid"}, config()
        )


def test_tenant_isolation_probe_rejects_docker_sock_bind() -> None:
    payload = container(Mounts=[{"Type": "bind", "Source": "/var/run/docker.sock"}])
    with pytest.raises(ProbeFailed, match="Docker socket"):
        check_tenant_rootless_isolation(InspectRunner(payload), {"web": "cid"}, config())


def test_evidence_contains_every_contract_field() -> None:
    isolation = check_tenant_rootless_isolation(
        InspectRunner(container()), {"web": "cid"}, config()
    )
    daemon = rootless_daemon_evidence(
        FakeRunner(), config(), security_options="[name=rootless]"
    )
    evidence = build_rootless_evidence(
        config=config(),
        runtime=RUNTIME_TENANT_ROOTLESS,
        isolation=isolation,
        daemon=daemon,
        preflight={"fail_closed": True},
        compose_sha256="c" * 64,
        image_digests={"web": "sha256:" + "a" * 64},
        signature="sig",
    )
    for key in ("tenant", "socket", "profile", "runtime", "apparmor_label",
                "uid_mapping", "hashes", "containers", "preflight", "probes"):
        assert key in evidence
    assert evidence["runtime"] == "runsc"
    assert evidence["hashes"]["compose_sha256"] == "c" * 64
