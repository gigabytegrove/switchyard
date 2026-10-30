"""SwitchYard two-pane operator experience contract."""
from html.parser import HTMLParser
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
HTML=(ROOT/'static/index.html').read_text()
JS=(ROOT/'static/app.js').read_text()
CSS=(ROOT/'static/style.css').read_text()

class DOM(HTMLParser):
    def __init__(self): super().__init__();self.ids={}
    def handle_starttag(self,tag,attrs):
        values=dict(attrs);ident=values.get('id')
        if ident:
            assert ident not in self.ids, f'duplicate DOM id: {ident}'
            self.ids[ident]=(tag,values)

def test_left_machines_right_connection_no_landing():
    document=DOM();document.feed(HTML)
    for key in ('shellNavigation','navigation','page-machine','machineLayout',
                'machine-context','machineSwitcher','machineSwitchSearch',
                'machineRailResize','machineContent','workbenchSessions',
                'machinePanel-overview','machinePanel-terminals',
                'machinePanel-desktops','machinePrimaryConnect',
                'terminalLayoutMode','machineTreeToggle','treeClose'):
        if key=='machine-context':
            assert 'class="machine-context"' in HTML
        else:
            assert key in document.ids
    assert 'id="page-machines"' not in HTML
    assert 'class="directory-hero"' not in HTML
    assert 'Where to?' not in HTML
    assert 'id="legacyMachineDirectoryBindings" hidden' in HTML
    assert "if (page === 'machines') page = 'machine';" in JS
    assert "navigate('machine');machineTab('overview');" in JS
    assert "setMachineTreeOpen(!window.matchMedia('(max-width:760px)').matches)" in JS
    assert "if(window.matchMedia('(max-width:760px)').matches)setMachineTreeOpen(false)" in JS
    assert '#shell .machine-layout>.machine-context{' in CSS
    assert '#shell .machine-layout>.machine-work-area{' in CSS
    assert 'grid-column:1;grid-row:1;' in CSS
    assert 'grid-column:3;grid-row:1;' in CSS
    assert '#shell.session-focus .station-header{display:flex!important}' in CSS

def test_workspace_routes_are_preserved():
    for page in ('files','docker','services','health','runbooks','activity','trust','settings'):
        assert f'id="page-{page}"' in HTML
        assert f'data-page="{page}"' in HTML
    assert 'id="sshExport"' in HTML
    assert 'id="sshImport"' in HTML
    assert 'function renderWorkbenchSessions()' in JS
    assert 'closeDesktopTab(id)' in JS
    assert 'closeTab(id)' in JS
    assert 'function applyTerminalLayout()' in JS
    assert "connect(a.id,{newSession:true})" in JS

def test_accessibility_and_responsive_behaviors():
    for size in (860,760,620,390):
        assert f'@media(max-width:{size}px)' in CSS
    assert 'prefers-reduced-motion:reduce' in CSS
    assert ':focus-visible' in CSS
    assert 'role="separator"' in HTML and 'tabindex="0"' in HTML
    assert 'aria-valuenow="236"' in HTML
    assert 'src="/static/switchyard-mark.webp"' in HTML
    assert (ROOT/'static/switchyard-mark.webp').stat().st_size>5000
    assert (ROOT/'static/favicon.png').stat().st_size>5000
    assert '--sw-logo-red:#bc293a' in CSS

def test_data_integrity():
    compose=(ROOT/'compose.yaml').read_text()
    assert 'image: ghcr.io/gigabytegrove/switchyard:0.5.9-dev.1' in compose
    assert 'container_name:' not in compose
    assert '/var/run/docker.sock' not in compose
