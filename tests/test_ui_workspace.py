"""Station 02 architecture contract: roster -> connection canvas."""
from html.parser import HTMLParser
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
HTML=(ROOT/'static/index.html').read_text()
JS=(ROOT/'static/app.js').read_text()
CSS=(ROOT/'static/style.css').read_text()

class DOM(HTMLParser):
    def __init__(self):
        super().__init__();self.ids={}
    def handle_starttag(self,tag,attrs):
        props=dict(attrs);key=props.get('id')
        if key:
            assert key not in self.ids, f'duplicate id: {key}'
            self.ids[key]=(tag,props)

def test_machine_directory_is_first_screen_and_not_old_sidebar():
    dom=DOM();dom.feed(HTML)
    for key in ('stationVersion','navigation','page-machines','machineDirectory',
                'machineSearch','machineEnvironment','machineCount',
                'page-machine','machineBackToDirectory','machineSwitcher',
                'workbenchSessions','machineContent','machinePanel-overview',
                'machinePanel-terminals','machinePanel-desktops',
                'machineInfoDrawer','machineInfoToggle','machinePrimaryConnect'):
        assert key in dom.ids
    assert 'class="sidebar"' not in HTML
    assert 'station-header' in HTML and 'directory-hero' in HTML
    assert 'Where to?' in HTML
    assert 'machine-entry-open' in JS and 'machine-connect-ssh' in JS
    assert "navigate('machines')" in JS
    assert 'position:absolute;top:0;bottom:0;left:0;z-index:52' in CSS
    assert '.machine-layout.tree-open .machine-context' in CSS
    assert 'display:none!important' in CSS

def test_all_operational_pages_and_sessions_remain():
    for page in ('files','docker','services','health','runbooks','activity','trust','settings'):
        assert f'id="page-{page}"' in HTML
        assert f'data-page="{page}"' in HTML
    assert 'function renderWorkbenchSessions()' in JS
    assert 'state.tabs' in JS and 'desktopTabs' in JS
    assert 'closeDesktopTab(id)' in JS and 'closeTab(id)' in JS
    assert "setAttribute('role','tab')" in JS

def test_accessibility_and_viewports():
    for p in (1280,980,760,540,390):
        assert f'@media(max-width:{p}px)' in CSS
    assert ':focus-visible' in CSS and 'prefers-reduced-motion:reduce' in CSS
    for asset in ('switchyard-mark.webp','switchyard-wordmark.webp','favicon.png'):
        assert asset in HTML and (ROOT/'static'/asset).stat().st_size>5000

def test_release_integrity():
    assert 'image: ghcr.io/gigabytegrove/switchyard:0.5.6-dev.1' in (ROOT/'compose.yaml').read_text()
    assert 'container_name:' not in (ROOT/'compose.yaml').read_text()
    assert 'environment:' not in (ROOT/'compose.yaml').read_text()
    assert '/var/run/docker.sock' not in (ROOT/'compose.yaml').read_text()
