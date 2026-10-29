"""Machine-first navigation and browser contract without a live remote host."""
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / 'static/index.html').read_text()
JS = (ROOT / 'static/app.js').read_text()
CSS = (ROOT / 'static/workspace.css').read_text()


class Dom(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = {}
    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if 'id' in d:
            assert d['id'] not in self.ids, f"Duplicate id: {d['id']}"
            self.ids[d['id']] = (tag,d)


def test_machine_workspace_controls_are_real_and_wired():
    dom = Dom();dom.feed(HTML)
    for element in ('machineSwitcher','machineSwitchSearch','machinePrimaryConnect',
                    'machineTerminalConnect','machineTerminalStatus','machineContent',
                    'machinePanel-files','machinePanel-docker','machinePanel-health'):
        assert element in dom.ids
    for element in ('machineSwitcher','machineSwitchSearch','machinePrimaryConnect','machineTerminalConnect','machineTerminalStatus'):
        assert f"$('#{element}')" in JS
    assert 'function renderMachineSwitcher()' in JS
    assert 'function updateTerminalStatus()' in JS
    assert 'function machineTab(tab)' in JS
    assert 'renderMachineOverview(); renderDesktopList()' in JS


def test_machine_tabs_expose_keyboard_access_and_panel_relationships():
    dom = Dom();dom.feed(HTML)
    for tab in ('overview','terminals','desktops','files','docker','health'):
        assert f'aria-controls="machinePanel-{tab}"' in HTML
        assert f'data-machine-tab="{tab}"' in HTML
    assert 'ArrowLeft' in JS and 'ArrowRight' in JS and "'Home'" in JS and "'End'" in JS
    assert "button.setAttribute('aria-selected',String(tab === id))" in JS


def test_no_duplicate_machine_header_and_responsive_styling():
    assert HTML.count('id="machineTitle"') == 1
    assert '<h2>SSH terminal</h2>' in HTML
    assert 'id="machineTerminalConnect"' in HTML
    assert 'href="/static/workspace.css"' in HTML
    for selector in ('.machine-layout','.machine-context','.profile-intro','.machine-panel .terminal-page'):
        assert selector in CSS
    for breakpoint in ('max-width:920px','max-width:660px','max-width:440px'):
        assert breakpoint in CSS
    assert 'prefers-reduced-motion:reduce' in CSS
    assert ':focus-visible' in CSS


def test_live_session_host_scoping():
    assert "normalizedHost(t.asset.host) !== state.machineHost) continue" in JS
    assert "normalizedHost(state.tabs.get(id).asset.host) === state.machineHost" in JS
    assert 'machineTab(available[next].dataset.machineTab)' in JS

def test_smoke_test_tracks_release_version_file():
    smoke = (ROOT / 'scripts/smoke-test.sh').read_text()
    assert 'expected_version="$(tr -d' in smoke
    assert 'grep -Fq' in smoke
    assert 'running version does not match $expected_version' in smoke
    assert '0\\.5\\.1-dev\\.1' not in smoke
