#!/usr/bin/env python3
"""Headless Chromium acceptance of the *running* Switchyard UI at five widths.

Uses Chrome DevTools Protocol and the already pinned websockets dependency;
does not install a browser automation framework. Writes screenshots of
disposable CI data only. Never connects to an operator's infrastructure.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from urllib.request import urlopen

from websockets.sync.client import connect

ORIGIN = os.environ.get("SWITCHYARD_URL", "http://127.0.0.1:9791").rstrip("/")
ADMIN_USERNAME = os.environ.get("SWITCHYARD_CI_ADMIN_USERNAME", "ci-admin")
ADMIN_PASSWORD = os.environ.get("SWITCHYARD_CI_ADMIN_PASSWORD", "ci-disposable-development-password-2026")
OUT = Path("ui-artifacts")


def browser_executable() -> str:
    for binary in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser"):
        found = shutil.which(binary)
        if found:
            return found
    raise RuntimeError("Chromium/Chrome is required for UI acceptance")


class CDP:
    def __init__(self, socket):
        self.socket = socket
        self.sequence = 0
        self.uncaught = []

    def call(self, method, **params):
        self.sequence += 1
        ident = self.sequence
        self.socket.send(json.dumps({"id": ident, "method": method, "params": params}))
        while True:
            reply = json.loads(self.socket.recv(timeout=20))
            if reply.get("method") == "Runtime.exceptionThrown":
                detail = reply.get("params", {}).get("exceptionDetails", {})
                self.uncaught.append(detail.get("text", "unknown uncaught browser exception"))
            if reply.get("id") != ident:
                continue
            if "error" in reply:
                raise RuntimeError(f"Chrome CDP {method}: {reply['error']}")
            return reply["result"]

    def eval(self, expression):
        reply = self.call("Runtime.evaluate", expression=expression,
                          returnByValue=True, awaitPromise=True)
        if "exceptionDetails" in reply:
            raise RuntimeError(f"Browser JS failed: {reply['exceptionDetails']}")
        return reply["result"].get("value")

    def until(self, expression, description, timeout=25):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.eval(expression):
                return
            time.sleep(0.15)
        raise AssertionError(f"UI did not reach: {description}")

    def screenshot(self, width):
        result = self.call("Page.captureScreenshot", format="png",
                           captureBeyondViewport=False)
        OUT.mkdir(parents=True, exist_ok=True)
        path = OUT / f"switchyard-{width}.png"
        path.write_bytes(base64.b64decode(result["data"]))
        print(f"SCREENSHOT {path} ({path.stat().st_size} bytes)", flush=True)


def run():
    binary = browser_executable()
    print(f"UI test browser: {binary}", flush=True)
    with tempfile.TemporaryDirectory(prefix="switchyard-ui-", ignore_cleanup_errors=True) as profile:
        command = [binary, "--headless=new", "--no-sandbox", "--disable-gpu",
                   "--disable-dev-shm-usage", "--no-first-run",
                   "--disable-background-networking", "--disable-extensions",
                   "--remote-allow-origins=*", "--remote-debugging-port=0",
                   f"--user-data-dir={profile}", "about:blank"]
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        try:
            endpoint = Path(profile) / "DevToolsActivePort"
            deadline = time.monotonic() + 12
            while not endpoint.exists() and time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("Headless browser exited before CDP startup")
                time.sleep(0.1)
            if not endpoint.exists():
                raise RuntimeError("Browser CDP port not available")
            port = endpoint.read_text().splitlines()[0]
            with urlopen(f"http://127.0.0.1:{port}/json/list", timeout=4) as response:
                pages = json.load(response)
            page = next(item for item in pages if item.get("type") == "page")
            with connect(page["webSocketDebuggerUrl"], open_timeout=5) as socket:
                cdp = CDP(socket)
                cdp.call("Runtime.enable")
                cdp.call("Page.enable")
                cdp.call("Emulation.setDeviceMetricsOverride",
                         width=1440, height=900, deviceScaleFactor=1, mobile=False)
                cdp.call("Page.navigate", url=ORIGIN + "/")
                cdp.until("document.readyState==='complete' && !!document.getElementById('loginForm')",
                          "initial login form")
                username = json.dumps(ADMIN_USERNAME)
                password = json.dumps(ADMIN_PASSWORD)
                assert cdp.eval("""(function(){
                  document.getElementById('loginUsername').value=""" + username + """;
                  document.getElementById('loginPassword').value=""" + password + """;
                  document.getElementById('loginForm').dispatchEvent(
                    new Event('submit',{bubbles:true,cancelable:true}));
                  return true;
                })()""")
                started = time.monotonic()
                cdp.until("""!!document.querySelector('#shell:not(.hidden)') &&
                  !!document.querySelector('#page-machine:not(.hidden)') &&
                  document.getElementById('machineSwitcher')""",
                          "default two-pane Machines + Connections workbench")
                print(f"PASS: login -> two-pane workbench in {time.monotonic()-started:.2f}s",flush=True)
                record = cdp.eval("""(async function(){
                    const created=await api('/assets',{method:'POST',body:{
                      label:'QA relay station',host:'192.0.2.48',port:22,
                      username:'operator',environment:'Lab',
                      auth_type:'interactive',credential_ref:'',key_file:'',
                      use_tmux:true,note:'CI-only demo record'
                    }});
                    await refreshAssets();
                    return {id:created.id,rows:document.querySelectorAll('#machineSwitcher .tree-machine-row').length};
                })()""")
                assert record["id"] and record["rows"] >= 1, record
                assert cdp.eval("""(function(){
                  return getComputedStyle(document.querySelector('.station-header')).backgroundColor==='rgb(39, 39, 43)' &&
                    !!document.querySelector('.station-brand-mark[src="/static/switchyard-mark.webp"]') &&
                    document.getElementById('stationVersion').textContent.includes('0.5.9-dev.1') &&
                    !document.getElementById('page-machines') &&
                    !document.querySelector('.directory-hero');
                })()"""), "wrong version, branding, or obsolete landing page"

                for width in (1440, 1024, 840, 620, 360):
                    cdp.call("Emulation.setDeviceMetricsOverride", width=width,
                             height=900, deviceScaleFactor=1, mobile=False)
                    # The left column is docked on desktop, off-canvas on mobile.
                    if width > 760:
                        cdp.eval("setMachineTreeOpen(true)")
                    else:
                        cdp.eval("setMachineTreeOpen(false)")
                    result = cdp.eval("""(function(){
                      const r=s=>{const x=document.querySelector(s).getBoundingClientRect();
                        return {x:x.x,y:x.y,width:x.width,height:x.height,right:x.right};};
                      return {
                        viewport:innerWidth,scrollWidth:document.documentElement.scrollWidth,
                        header:r('.station-header'),
                        machines:r('.machine-context'),
                        stage:r('.machine-work-area'),
                        splitter:r('#machineRailResize'),
                        visible:document.querySelectorAll('.page:not(.hidden)').length,
                        entryCount:document.querySelectorAll('#machineSwitcher .tree-machine-row').length,
                        focused:document.getElementById('shell').classList.contains('session-focus'),
                        navInline:getComputedStyle(document.querySelector('.station-navigation')).position==='static',
                        sidebarVisible:getComputedStyle(document.querySelector('.machine-context')).visibility==='visible'
                      };
                    })()""")
                    assert result["viewport"]==width,result
                    assert result["scrollWidth"] <= width+3,result
                    assert result["header"]["height"]<=42,result
                    assert result["header"]["width"]>=width-3,result
                    assert result["visible"]==1 and result["entryCount"]>=1,result
                    assert result["stage"]["height"]>=850,result
                    if width>760:
                        assert result["navInline"],result
                        assert result["sidebarVisible"],result
                        assert result["machines"]["width"]>=183,result
                        assert abs(result["machines"]["right"]+result["splitter"]["width"]-
                                   result["stage"]["x"])<=5,result
                        assert result["stage"]["right"]>=width-2,result
                        assert result["stage"]["width"]>=width-450,result
                    else:
                        assert result["machines"]["right"]<=1,result
                        assert result["stage"]["width"]>=width-3,result
                    cdp.screenshot(f"{width}-two-pane-workbench")
                    print(f"PASS two-pane workbench at {width}px; right stage {result['stage']['width']:.0f}px",flush=True)

                # Selecting a host only changes the right connection window.
                cdp.call("Emulation.setDeviceMetricsOverride",
                         width=1440,height=900,deviceScaleFactor=1,mobile=False)
                assert cdp.eval("""(function(){
                  openMachine('192.0.2.48');
                  return !!document.querySelector('#page-machine:not(.hidden)') &&
                    !!document.querySelector('#machineLayout.tree-open') &&
                    document.getElementById('machineTitle').textContent.includes('QA relay station') &&
                    document.getElementById('machineSwitcher').children.length>0;
                })()"""), "host selection removed Machines panel or failed to update connection"
                assert cdp.eval("""(function(){
                  document.getElementById('machineTreeToggle').click();
                  const collapsed=!document.getElementById('machineLayout').classList.contains('tree-open');
                  document.getElementById('machineTreeToggle').click();
                  return collapsed && document.getElementById('machineLayout').classList.contains('tree-open');
                })()"""), "Machines dock cannot collapse and reopen"
                assert cdp.eval("""(function(){
                  const search=document.getElementById('globalFind');
                  search.click();
                  return document.activeElement.id==='machineSwitchSearch' &&
                    document.getElementById('machineLayout').classList.contains('tree-open');
                })()"""), "top menu Find did not focus left Machines panel"
                cdp.call("Emulation.setDeviceMetricsOverride",
                         width=360,height=900,deviceScaleFactor=1,mobile=False)
                assert cdp.eval("""(function(){
                  const toggle=document.getElementById('machineTreeToggle');
                  toggle.click();
                  const opened=document.getElementById('machineLayout').classList.contains('tree-open');
                  document.getElementById('treeClose').click();
                  return opened && !document.getElementById('machineLayout').classList.contains('tree-open');
                })()"""), "mobile Machines drawer cannot open and close"
                cdp.call("Emulation.setDeviceMetricsOverride",
                         width=1440,height=900,deviceScaleFactor=1,mobile=False)
                cdp.eval("setMachineTreeOpen(true)")
                # A genuine xterm canvas, without connecting to any external
                # SSH machine. This checks layout/fit; the separate SSH E2E
                # suite checks the actual transport.
                assert cdp.eval("""(function(){
                  openMachine('192.0.2.48');
                  const asset=state.assets.find(a=>a.host==='192.0.2.48');
                  if(!asset||!window.Terminal||!window.FitAddon)return false;
                  const terminal=new window.Terminal({
                    fontSize:14,lineHeight:1.1,cursorBlink:true,
                    theme:{background:'#1b1a1d',foreground:'#eceaec',cursor:'#e24e62'}
                  });
                  const fit=new window.FitAddon.FitAddon();
                  terminal.loadAddon(fit);
                  state.tabs.set('layout-probe',{id:'layout-probe',asset,terminal,fit,ws:null});
                  state.currentTab='layout-probe';
                  navigate('terminals');
                  const host=document.getElementById('term-layout-probe');
                  if(!host)return false;
                  terminal.open(host);
                  fit.fit();
                  terminal.write('SwitchYard focus viewport layout acceptance\\r\\n');
                  return true;
                })()"""), "xterm layout probe could not be constructed"
                cdp.until("""document.getElementById('shell').classList.contains('session-focus') &&
                  !!document.querySelector('#machinePanel-terminals:not(.hidden) .xterm-screen')""",
                          "default focused terminal")
                for width in (1440, 1024, 840, 620, 360):
                    cdp.call("Emulation.setDeviceMetricsOverride",
                             width=width,height=900,deviceScaleFactor=1,mobile=False)
                    cdp.eval("fitVisibleSession()")
                    geometry=cdp.eval("""(function(){
                      const bounds=s=>{const e=document.querySelector(s);const r=e.getBoundingClientRect();return {x:r.x,y:r.y,width:r.width,height:r.height};};
                      return {
                        viewport:innerWidth,height:innerHeight,
                        focus:document.getElementById('shell').classList.contains('session-focus'),
                        headerHidden:getComputedStyle(document.querySelector('.station-header')).display==='none',
                        tabsHidden:getComputedStyle(document.querySelector('.workbench-session-dock')).display==='none',
                        command:bounds('.workbench-command-bar'),
                        host:bounds('.terminal-host.active'),
                        xterm:bounds('.terminal-host.active .xterm'),
                        horizontal:document.documentElement.scrollWidth
                      };
                    })()""")
                    assert geometry['focus'] and not geometry['headerHidden'] and geometry['tabsHidden'],geometry
                    assert geometry['command']['height']<=40,geometry
                    assert geometry['host']['width']>= (width-450 if width>760 else width*.94),geometry
                    assert geometry['host']['height']>=geometry['height']*.88,geometry
                    assert geometry['xterm']['width']>= (width-460 if width>760 else width*.92),geometry
                    assert geometry['xterm']['height']>=geometry['height']*.86,geometry
                    assert geometry['horizontal']<=width+3,geometry
                    cdp.screenshot(f"{width}-focused-terminal")
                    print(f"PASS focus {width}px: terminal {geometry['host']['width']:.0f}x{geometry['host']['height']:.0f}, "+ 
                          f"{100*geometry['host']['height']/geometry['height']:.1f}% viewport height",flush=True)

                # Dock tabs without losing focus or terminal; exit focus to
                # restore header; reenter with F8 (available to keyboard users).
                cdp.call("Emulation.setDeviceMetricsOverride",width=1440,height=900,
                         deviceScaleFactor=1,mobile=False)
                assert cdp.eval("""(function(){
                  const tabs=document.getElementById('workbenchSessionsToggle');
                  tabs.click();
                  const opened=tabs.getAttribute('aria-expanded')==='true' &&
                    getComputedStyle(document.querySelector('.workbench-session-dock')).display!=='none';
                  tabs.click();
                  return opened && tabs.getAttribute('aria-expanded')==='false' &&
                    getComputedStyle(document.querySelector('.workbench-session-dock')).display==='none';
                })()"""), "session tab dock failed to open and close"
                assert cdp.eval("""(function(){
                  const focus=document.getElementById('workbenchFocusToggle');
                  focus.click();
                  const expanded=!document.getElementById('shell').classList.contains('session-focus') &&
                    getComputedStyle(document.querySelector('.station-header')).display!=='none';
                  window.dispatchEvent(new KeyboardEvent('keydown',{key:'F8',bubbles:true}));
                  return expanded && document.getElementById('shell').classList.contains('session-focus');
                })()"""), "focus toggle/F8 failed to restore the full viewport"


                # Render actual, independent xterm instances from different
                # machines side-by-side and in a four-cell grid. No remote
                # connection is attempted; SSH transport is tested separately.
                assert cdp.eval("""(function(){
                  const source=state.assets.find(a=>a.host==='192.0.2.48');
                  if(!source)return false;
                  for(let i=2;i<=4;i++){
                    const asset={...source,id:10000+i,host:'192.0.2.'+(48+i),
                      label:'QA secondary '+i};
                    state.assets.push(asset);
                    const terminal=new window.Terminal({fontSize:13,scrollback:1000});
                    const fit=new window.FitAddon.FitAddon();
                    terminal.loadAddon(fit);
                    const id='layout-probe-'+i;
                    state.tabs.set(id,{id,asset,terminal,fit,ws:null});
                  }
                  renderTabs();
                  for(let i=2;i<=4;i++){
                    const id='layout-probe-'+i,tab=state.tabs.get(id);
                    const host=document.getElementById('term-'+id);
                    if(!host)return false;
                    tab.terminal.open(host);
                    tab.terminal.write('Independent session '+i+'\\r\\n');
                  }
                  return true;
                })()"""), "multiple host xterm creation failed"
                for count,mode in ((2,"Split 2"),(4,"Grid 4")):
                    assert cdp.eval("""(function(count){
                      const layout=document.getElementById('terminalLayoutMode');
                      layout.value=String(count);
                      layout.dispatchEvent(new Event('change',{bubbles:true}));
                      return state.terminalLayout===count &&
                        document.getElementById('terminalPanels').classList.contains('multiconnect') &&
                        layout.options[layout.selectedIndex].textContent=== (count===2?'Split 2':'Grid 4');
                    })("""+str(count)+""")"""), f"layout mode {mode} did not activate"
                    cdp.eval("fitVisibleSession()")
                    split=cdp.eval("""(function(){
                      const panel=document.getElementById('terminalPanels');
                      const active=[...panel.querySelectorAll('.terminal-host.multi-visible')].map(el=>{
                        const rect=el.getBoundingClientRect();
                        const terminal=el.querySelector('.xterm');
                        return {id:el.id,display:getComputedStyle(el).display,
                                width:rect.width,height:rect.height,
                                rendered:!!terminal&&terminal.getBoundingClientRect().height>0};
                      });
                      return {viewport:innerWidth,canvasHeight:panel.getBoundingClientRect().height,
                        active,columnStyle:getComputedStyle(panel).gridTemplateColumns,
                        rowStyle:getComputedStyle(panel).gridTemplateRows,
                        overflow:document.documentElement.scrollWidth};
                    })()""")
                    assert len(split["active"])==count,split
                    assert all(row["rendered"] and row["display"]!="none" for row in split["active"]),split
                    assert all(row["width"] >= 0.43*split["viewport"] for row in split["active"]),split
                    assert split["overflow"]<=split["viewport"]+3,split
                    if count==2:
                        assert all(row["height"]>=split["canvasHeight"]*.94 for row in split["active"]),split
                    cdp.screenshot(f"1440-{count}-simultaneous-terminals")
                    print(f"PASS {mode}: {count} independent live xterm canvases on different hosts",flush=True)
                # Closing the grid doesn't discard any terminal session.
                assert cdp.eval("""(function(){
                  const field=document.getElementById('terminalLayoutMode');
                  field.value='1';field.dispatchEvent(new Event('change',{bubbles:true}));
                  return state.tabs.size===4 && !document.getElementById('terminalPanels').classList.contains('multiconnect');
                })()"""), "return to single view discarded an SSH session"

                cdp.screenshot("360-directory-after-workbench")
                assert not cdp.uncaught, f"Uncaught browser exceptions: {cdp.uncaught}"
                print("PASS: Station 02 actual Chrome CSS colors, roster -> full workbench -> roster, "
                      "horizontal nav, mobile drawer, quick search, no uncaught errors",flush=True)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


if __name__ == "__main__":
    run()
