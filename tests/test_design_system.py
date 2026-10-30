"""New operator UI: single CSS owner, controls, responsive + accessible contract."""
from html.parser import HTMLParser
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
HTML=(ROOT/'static/index.html').read_text()
CSS=(ROOT/'static/style.css').read_text()
JS=(ROOT/'static/app.js').read_text()


class Elements(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids={}
    def handle_starttag(self, tag, attrs):
        attrs=dict(attrs)
        if 'id' in attrs:
            assert attrs['id'] not in self.ids
            self.ids[attrs['id']]=(tag,attrs)


def test_single_style_owner_and_no_legacy_cascade():
    assert '<link rel="stylesheet" href="/static/style.css">' in HTML
    assert '/static/workspace.css' not in HTML
    assert not (ROOT/'static/workspace.css').exists()
    assert ':root {' in CSS
    for token in ('--paper:#fff','--canvas:#f6f4f0','--graphite:#27272b',
                  '--accent:#bc293a','--wb-rail:276px'):
        assert token in CSS
    assert '@media(prefers-reduced-motion:reduce)' in CSS
    assert 'color-scheme:light' in CSS
    assert '@import' not in CSS


def test_workbench_navigation_and_action_disclosure():
    p=Elements();p.feed(HTML)
    for key in ('shellNavigation','navMobileToggle','navDismiss','globalFind',
                'machineCommandMenu','machinePrimaryConnect','machineInfoToggle',
                'machineTrust','machineProbe','machineEdit','machineAddDesktop',
                'machineSwitcher','machineRailResize','workbenchSessions'):
        assert key in p.ids
    assert p.ids['machineCommandMenu'][0]=='details'
    assert '<summary>Actions</summary>' in HTML
    assert 'function renderWorkbenchSessions()' in JS
    assert "'nav-open'" in JS
    assert "window.matchMedia('(max-width:620px)')" in JS


def test_breakpoints_and_no_mobile_menu_invisibility():
    for size in (1120,840,620,420):
        assert f'@media(max-width:{size}px)' in CSS
    # The nested disclosure menu must stay available on small screens.
    assert '.machine-masthead-actions > .action-quiet {display:none}' in CSS
    assert '.machine-masthead-actions .action-quiet {display:none}' not in CSS
    assert '.machine-layout.tree-open .machine-context' in CSS
    assert '.shell.nav-open .sidebar' in CSS


def test_async_startup_does_not_serialize_independent_inventory_requests():
    assert 'await Promise.all([refreshFolders(), refreshAssets(), refreshDesktops()])' in JS
    assert "const [assets,info] = await Promise.all([api('/assets')" in JS
    assert 'void refreshDesktopGateway().catch(showError)' in JS
    assert 'setTimeout(renderMachineSwitcher, 110)' in JS


def test_navigation_never_calls_for_each_on_a_single_dom_node():
    # A replaced '$$' becomes '$' in JavaScript String.replace when the
    # replacement is not a callback. One such occurrence aborted bind()
    # before any workspace actions had listeners; this is a release blocker.
    bad = re.findall(r'(?<!\$)\$\(([^)]{1,100})\)\.forEach\b', JS)
    assert not bad, f'querySelector returns a single node: {bad}'
    assert "$$('[data-page]').forEach" in JS
    assert "$$('.page').forEach" in JS
