"""Non-destructive deployment-script regressions using a fake Docker CLI."""
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]

FAKE_DOCKER = r"""#!/usr/bin/env bash
set -e
printf '%s\n' "$*" >> "$MOCK_DOCKER_LOG"
if [[ "${1:-}" == "compose" ]]; then
  if [[ "${2:-}" == "config" && "${3:-}" != "--quiet" ]]; then
    printf 'name: testproject\n'
  fi
  exit 0
fi
if [[ "${1:-}" == "ps" && "${2:-}" == "-aq" ]]; then
  case "$MOCK_SCENARIO" in
    upgrade|wrong-volume) printf 'cid-app\n' ;;
    duplicate) printf 'cid-app\ncid-app2\n' ;;
  esac
  exit 0
fi
if [[ "${1:-}" == "ps" && "${2:-}" == "-q" ]]; then
  case "$MOCK_SCENARIO" in
    upgrade|wrong-volume|duplicate) printf 'cid-app\n' ;;
    foreign) printf 'cid-foreign\n' ;;
  esac
  exit 0
fi
if [[ "${1:-}" == "inspect" ]]; then
  if [[ "$*" == *".Mounts"* ]]; then
    if [[ "$MOCK_SCENARIO" == "wrong-volume" ]]; then
      printf 'volume:unexpected_switchyard_data\n'
    else
      printf 'volume:testproject_switchyard_data\n'
    fi
  elif [[ "$*" == *".Name"* ]]; then
    printf '/foreign-switchyard\n'
  else
    printf 'foreignproject\n'
  fi
  exit 0
fi
if [[ "${1:-}" == "port" ]]; then
  printf '9791/tcp -> 0.0.0.0:9791\n'
  exit 0
fi
if [[ "${1:-}" == "exec" ]]; then
  exit 1
fi
exit 0
"""


def run_deploy(tmp_path, scenario):
    scripts = tmp_path / "worktree" / "scripts"
    scripts.mkdir(parents=True)
    shutil.copyfile(ROOT / "scripts" / "deploy.sh", scripts / "deploy.sh")
    mock_bin = tmp_path / "bin"
    mock_bin.mkdir()
    fake_docker = mock_bin / "docker"
    fake_docker.write_text(FAKE_DOCKER)
    fake_docker.chmod(0o755)
    log = tmp_path / "docker.log"
    env = os.environ.copy()
    env.update({
        "PATH": str(mock_bin) + os.pathsep + env["PATH"],
        "MOCK_DOCKER_LOG": str(log),
        "MOCK_SCENARIO": scenario,
        "COMPOSE_PROJECT_NAME": "testproject",
    })
    result = subprocess.run(
        ["bash", str(scripts / "deploy.sh")],
        env=env, text=True, capture_output=True, timeout=15, check=False,
    )
    return result, log.read_text()


def test_relocated_checkout_upgrades_own_container(tmp_path):
    result, commands = run_deploy(tmp_path, "upgrade")
    assert result.returncode == 0, result.stderr
    assert "compose up -d --no-build --wait" in commands
    assert "compose pull" in commands
    assert "down -v" not in commands


def test_other_compose_project_on_port_is_never_replaced(tmp_path):
    result, commands = run_deploy(tmp_path, "foreign")
    assert result.returncode != 0
    assert "already published" in result.stderr
    assert "compose up" not in commands
    assert "compose pull" not in commands


def test_ambiguous_same_project_containers_are_rejected(tmp_path):
    result, commands = run_deploy(tmp_path, "duplicate")
    assert result.returncode != 0
    assert "Multiple Switchyard containers" in result.stderr
    assert "compose up" not in commands


def test_existing_data_volume_mismatch_is_rejected(tmp_path):
    result, commands = run_deploy(tmp_path, "wrong-volume")
    assert result.returncode != 0
    assert "does not match" in result.stderr
    assert "compose up" not in commands


def test_fresh_install_is_allowed_when_port_is_free(tmp_path):
    result, commands = run_deploy(tmp_path, "fresh")
    assert result.returncode == 0, result.stderr
    assert "compose up -d --no-build --wait" in commands
