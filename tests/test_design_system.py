"""Station 02 operator experience regression tests."""
from pathlib import Path
import re
ROOT=Path(__file__).resolve().parents[1]
HTML=(ROOT/'static/index.html').read_text()
CSS=(ROOT/'static/style.css').read_text()
JS=(ROOT/'static/app.js').read_text()

def test_single_css_owner_busted_cache_and_obvious_version_marker():
    assert 'href="/static/style.css?v=0.5.6-dev.1"' in HTML
    assert 'src="/static/app.js?v=0.5.6-dev.1"' in HTML
    assert 'STATION 02 · 0.5.6-dev.1' in HTML
    assert '/static/workspace.css' not in HTML
    assert not (ROOT/'static/workspace.css').exists()
    assert ':root{' in CSS and '@import' not in CSS
    for token in ('--ink:#203a30','--signal:#dff18a','--off:#f7f7ef','--accent:#9b3c28'):
        assert token in CSS
    assert '.station-header{' in CSS and '.directory-hero{' in CSS
    assert '.machine-entry-actions button{' in CSS
    assert '.machine-context{position:absolute;' in CSS
    assert 'color-scheme:light' in CSS

def test_not_previous_shell_or_previous_workflow():
    assert 'class="sidebar"' not in HTML
    assert 'class="brand"' not in HTML
    assert 'class="station-header"' in HTML
    assert 'id="page-machines" class="page machine-directory-page"' in HTML
    assert 'Where to?' in HTML
    assert 'machine-rail-resize' in HTML and '.machine-rail-resize{display:none!important}' in CSS
    assert 'id="machineBackToDirectory"' in HTML
    assert 'id="treeClose"' in HTML
    assert 'id="machineCommandMenu"' in HTML
    assert "if (page === 'machines') page = 'machine';" not in JS
    assert "navigate('machines')" in JS
    assert "machine.ssh[0].id" in JS
    assert "machine.desktops[0]" in JS

def test_shortcuts_mobile_access_and_no_event_binding_crashes():
    for p in (1280,980,760,540,390):
        assert f'@media(max-width:{p}px)' in CSS
    assert 'prefers-reduced-motion:reduce' in CSS
    assert '.shell.nav-open .station-navigation' in CSS
    assert '.machine-layout.tree-open .machine-context' in CSS
    assert "setMachineTreeOpen(false)" in JS
    assert "$$('[data-page]').forEach" in JS
    assert "$$('.page').forEach" in JS
    assert not re.findall(r'(?<!\$)\$\(([^)]{1,100})\)\.forEach\b',JS)

def test_inventory_starts_independently():
    assert 'await Promise.all([refreshFolders(), refreshAssets(), refreshDesktops()])' in JS
    assert "const [assets,info] = await Promise.all([api('/assets')" in JS
    assert 'void refreshDesktopGateway().catch(showError)' in JS
