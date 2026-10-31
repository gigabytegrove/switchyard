"""Assert the restored SwitchYard identity and maximum-view terminal architecture."""
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
HTML=(ROOT/'static/index.html').read_text()
CSS=(ROOT/'static/style.css').read_text()
JS=(ROOT/'static/app.js').read_text()

def test_restored_brand_and_versioned_assets():
    assert 'href="/static/style.css?v=0.5.10-dev.1"' in HTML
    assert 'src="/static/app.js?v=0.5.10-dev.1"' in HTML
    assert '0.5.10-dev.1' in HTML
    assert 'src="/static/switchyard-mark.webp"' in HTML
    assert 'station-monogram' not in HTML
    assert '--sw-logo-red:#bc293a' in CSS
    assert '--sw-neutral-800:#27272b' in CSS
    assert '.station-brand-mark' in CSS
    assert 'color-scheme:light' in CSS
    assert '/static/workspace.css' not in HTML

def test_session_is_default_focus_and_can_undock_components():
    assert 'id="workbenchFocusToggle"' in HTML
    assert 'id="workbenchSessionsToggle"' in HTML
    assert 'id="machineTreeToggle"' in HTML
    assert 'id="page-machines"' not in HTML
    assert '#shell.session-focus .station-header{display:flex!important}' in CSS
    assert 'grid-column:1;grid-row:1;' in CSS
    assert 'id="machineInfoDrawer"' in HTML
    assert "readUiPreference(SESSION_FOCUS_PREF,true)" in JS
    assert "session && state.focusPreferred !== false" in JS
    assert "state.sessionDockOpen = !state.sessionDockOpen" in JS
    assert 'function fitVisibleSession()' in JS
    assert 'ResizeObserver' in JS
    assert 'window.addEventListener' in JS
    assert "event.key !== 'F8'" in JS
    assert '#shell.session-focus .station-header' in CSS
    assert '#shell.session-focus .workbench-terminal .terminal-heading' in CSS
    assert '#shell.session-focus .workbench-terminal .terminal-tabs' in CSS
    assert '#shell.session-focus .terminal-panels .terminal-host' in CSS
    assert '#shell.session-focus .workbench-desktop .desktop-viewports' in CSS
    assert '#shell.session-focus .machine-layout.session-dock-open' in CSS
    assert '--sw-terminal:#1b1a1d' in CSS

def test_no_single_node_for_each_and_reduced_motion():
    assert "$$('[data-page]').forEach" in JS
    assert "$$('.page').forEach" in JS
    assert not re.findall(r'(?<!\$)\$\(([^)]{1,100})\)\.forEach\b',JS)
    assert 'prefers-reduced-motion:reduce' in CSS
    assert ':focus-visible' in CSS

def test_inventory_starts_independently():
    assert 'await Promise.all([refreshFolders(), refreshAssets(), refreshDesktops()])' in JS
    assert "const [assets,info] = await Promise.all([api('/assets')" in JS
    assert 'void refreshDesktopGateway().catch(showError)' in JS


def test_multiconnect_layout_and_direct_host_launch():
    for markup in ('id="terminalLayoutMode"', '<option value="2">Split 2</option>',
                   '<option value="4">Grid 4</option>'):
        assert markup in HTML
    for selector in ('.terminal-panels.multiconnect', '.terminal-host.multi-visible',
                     '.tree-machine-row', '.tree-machine-quick'):
        assert selector in CSS
    assert 'function terminalLayoutSelection()' in JS
    assert 'function applyTerminalLayout()' in JS
    assert 'function renderTabs()' in JS
    assert "if(normalizedHost(t.asset.host)===state.machineHost)" in JS
    assert 'connect(a.id,{newSession:true})' in JS
