"""Static DOM wiring contract, independent of any browser runtime."""
from html.parser import HTMLParser
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


class IDs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.duplicates = []

    def handle_starttag(self, tag, attrs):
        key = dict(attrs).get('id')
        if key in self.ids:
            self.duplicates.append(key)
        if key:
            self.ids.add(key)


def test_all_static_js_id_references_resolve_and_unique():
    parser = IDs()
    parser.feed((ROOT / 'static/index.html').read_text())
    js = (ROOT / 'static/app.js').read_text()
    references = set(re.findall(r"\$\('#([a-zA-Z][a-zA-Z0-9_-]*)'\)", js))
    assert not parser.duplicates
    assert references <= parser.ids, f'Missing elements: {references - parser.ids}'
    pages = set(re.findall(r'data-page="([a-z]+)"', (ROOT / 'static/index.html').read_text()))
    assert all(f'page-{page}' in parser.ids for page in pages)
    for required in ('fileEditorDialog', 'healthMetrics', 'runbookHistory', 'runbookForm', 'dockerShowStacks'):
        assert required in parser.ids



def test_smoke_test_is_present_and_strict():
    script = (ROOT/'scripts/smoke-test.sh').read_text()
    assert 'set -Eeuo pipefail' in script
    assert '/static/guacamole.js' in script
    assert '/static/spice/main.js' in script
    assert 'docker compose config --quiet' in script


def test_spice_client_can_activate_display_without_guest_agent():
    from pathlib import Path
    viewer = (Path(__file__).resolve().parents[1] / 'static' / 'spice-view.js').read_text()
    assert 'MutationObserver' in viewer
    assert "screen.querySelector('canvas')" in viewer
    assert "status('Display active')" in viewer
    assert 'displayObserver.disconnect()' in viewer


def test_desktop_history_export_ui_and_gateway_visibility():
    html = (ROOT / 'static/index.html').read_text()
    js = (ROOT / 'static/app.js').read_text()
    assert 'id="desktopHistoryExport"' in html
    assert "'/api/desktops/sessions/export'" in js
    assert 'id="desktopGateway"' in html
    assert "'/desktops/gateway/status'" in js


def test_favorite_desktop_controls_preserve_state_through_editing():
    js = (ROOT / 'static/app.js').read_text()
    assert 'aria-pressed' in js
    assert "favorite:!d.favorite" in js
    assert 'data.favorite = desktopEditing' in js


def test_duplicate_button_opens_new_record_for_review():
    js=(ROOT/'static/app.js').read_text()
    assert "'/duplicate'" in js or "`/desktops/${d.id}/duplicate`" in js
    assert 'openDesktopEditor(copy)' in js


def test_export_inventory_control_is_mounted_and_wired():
    assert 'id="desktopExport"' in (ROOT/'static/index.html').read_text()
    assert "'/api/desktops/export'" in (ROOT/'static/app.js').read_text()


def test_desktop_json_import_has_validation_confirmation_and_success_path():
    html=(ROOT/'static/index.html').read_text()
    js=(ROOT/'static/app.js').read_text()
    assert 'id="desktopImportFile"' in html
    assert "file.size > 1024 * 1024" in js
    assert "'/desktops/import'" in js
    assert 'Existing entries will not be overwritten' in js


def test_desktop_batch_probe_ui_is_rate_bounded():
    html=(ROOT/'static/index.html').read_text()
    js=(ROOT/'static/app.js').read_text()
    assert 'id="desktopBatchProbe"' in html
    assert 'visible.slice(0,20)' in js
    assert "'/desktops/probes'" in js


def test_history_filters_are_accessible_and_request_only_validated_parameters():
    html=(ROOT/'static/index.html').read_text()
    js=(ROOT/'static/app.js').read_text()
    for id in ('desktopHistoryProtocol','desktopHistoryOutcome'):
        assert f'id="{id}"' in html and f"$('#{id}')" in js
    assert "params.set('protocol', protocol)" in js
    assert "params.set('outcome', outcome)" in js


def test_active_sessions_have_confirmed_force_disconnect_ui():
    html=(ROOT/'static/index.html').read_text()
    js=(ROOT/'static/app.js').read_text()
    assert 'id="desktopActiveSessions"' in html
    assert 'id="desktopActiveRefresh"' in html
    assert 'Disconnect session' in js
    assert "'/desktops/sessions/active'" in js
    assert 'Disconnect “${session.label}”' in js


def test_runtime_asset_verification_is_strict_and_invoked_at_image_build():
    script=(ROOT/'scripts/verify-runtime-assets.sh').read_text()
    docker=(ROOT/'Dockerfile').read_text()
    assert 'set -Eeuo pipefail' in script
    assert 'spice/main.js' in script and 'guacamole.js' in script
    assert 'RUN bash /usr/local/bin/verify-runtime-assets /app/static' in docker
