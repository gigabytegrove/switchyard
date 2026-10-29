"""Release safety checks for the desktop protocol distribution."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def test_private_guacamole_network_and_no_privileged_socket():
    compose = (ROOT / 'compose.yaml').read_text()
    assert re.search(r'^  guacd:\s*$', compose, re.M)
    assert 'guacamole/guacd:1.6.0' in compose
    assert 'remote_access:\n    internal: true' in compose
    assert 'GUACD_HOST:' not in compose
    assert 'environment:' not in compose
    assert '.env' not in compose
    assert 'secrets:' not in compose
    assert '/var/run/docker.sock' not in compose
    assert 'privileged: true' not in compose
    guacd = compose.split('  guacd:', 1)[1].split('  switchyard:', 1)[0]
    assert '\n    ports:' not in guacd, 'guacd must not be published to host'


def test_runtime_assets_and_isolated_spice_shell_are_packaged():
    dockerfile = (ROOT / 'Dockerfile').read_text()
    assert 'verify-runtime-assets /app/static' in dockerfile
    assert 'spice-html5=0.3.0-2' in dockerfile
    assert 'guacamole-common-js/1.6.0/' in dockerfile
    verify = (ROOT / 'scripts/verify-runtime-assets.sh').read_text()
    for required in ('guacamole.js', 'spice-view.js', 'spice/main.js',
                     'spice/spiceconn.js', 'spice/inputs.js', 'spice/display.js'):
        assert required in verify
    shell = (ROOT / 'static/spice-view.html').read_text()
    assert 'spice-screen' in shell
    assert 'spice-view.js' in shell
    assert '<script type="module"' in shell


def test_release_version_consistency():
    version = (ROOT / 'VERSION').read_text().strip()
    assert version == '0.5.0-dev.1'
    assert 'switchyard:0.5.0-dev.1' in (ROOT / 'compose.yaml').read_text()
    assert 'version-0.5.0--dev.1' in (ROOT / 'README.md').read_text()
    assert '## 0.5.0-dev.1' in (ROOT / 'CHANGELOG.md').read_text()
