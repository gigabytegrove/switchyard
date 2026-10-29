"""Two-pane machine connection workbench contract."""
from html.parser import HTMLParser
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
HTML=(ROOT/'static/index.html').read_text()
JS=(ROOT/'static/app.js').read_text()
CSS=(ROOT/'static/workspace.css').read_text()

class Dom(HTMLParser):
    def __init__(self):
        super().__init__();self.ids={}
    def handle_starttag(self,tag,attrs):
        value=dict(attrs)
        if 'id' in value:
            assert value['id'] not in self.ids, 'duplicate '+value['id']
            self.ids[value['id']]=(tag,value)

def test_permanent_machine_tree_and_connection_canvas():
    dom=Dom();dom.feed(HTML)
    for item in ('machineSwitcher','machineSwitchSearch','treeNewFolder','treeNewMachine',
                 'workbenchSessions','machineContent','machinePanel-overview',
                 'machinePanel-terminals','machinePanel-desktops','machineInfoDrawer',
                 'machineInfoToggle','machinePrimaryConnect'):
        assert item in dom.ids
    assert 'machine-layout' in HTML and 'machine-context' in HTML and 'machine-work-area' in HTML
    assert 'grid-template-columns:var(--wb-rail) minmax(0,1fr)' in CSS
    assert 'function renderMachineSwitcher()' in JS
    assert 'tree-folder-toggle' in JS and 'foldedFolders' in JS
    assert 'tree-machine' in JS and 'dblclick' in JS

def test_tools_are_separate_navigation_pages():
    for page in ('files','docker','health'):
        assert f'<section id="page-{page}"' in HTML
        assert f'data-page="{page}"' in HTML
    assert 'machinePanel-files' not in HTML
    assert 'machinePanel-docker' not in HTML
    assert 'machinePanel-health' not in HTML
    assert 'id="machineTabs"' not in HTML
    assert 'workbench-command-bar' in HTML
    for route in ("page === 'files'","page === 'docker'","page === 'health'"):
        assert route in JS

def test_shared_session_tabs_keep_close_and_keyboard_controls():
    assert 'function renderWorkbenchSessions()' in JS
    assert 'state.tabs' in JS and 'desktopTabs' in JS
    assert "setAttribute('role','tab')" in JS
    assert "'ArrowLeft','ArrowRight','Home','End'" in JS
    assert 'closeDesktopTab(id)' in JS and 'closeTab(id)' in JS
    assert 'function toggleMachineInfo(' in JS

def test_brand_assets_and_mobile_breakpoints():
    for asset in ('switchyard-mark.webp','switchyard-wordmark.webp','favicon.png'):
        assert asset in HTML
        assert (ROOT/'static'/asset).stat().st_size > 5000
    for point in ('max-width:1000px','max-width:760px','max-width:520px'):
        assert point in CSS
    assert 'prefers-reduced-motion:reduce' in CSS
    assert ':focus-visible' in CSS

def test_deployment_preserves_externally_unconfigured_image():
    compose=(ROOT/'compose.yaml').read_text()
    assert 'image: ghcr.io/gigabytegrove/switchyard:0.5.2-dev.1' in compose
    assert 'container_name:' not in compose
    assert 'environment:' not in compose
    assert '.env' not in compose
    assert '/var/run/docker.sock' not in compose
