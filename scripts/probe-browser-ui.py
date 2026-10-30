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
                  !!document.querySelector('#page-machines:not(.hidden)') &&
                  document.getElementById('machineDirectory').textContent.length>0""",
                          "Station 02 directory home")
                print(f"PASS: login -> Station 02 machine directory in {time.monotonic()-started:.2f}s",flush=True)

                # Seed a disposable, reserved-address machine through the real
                # authenticated API. Never attempt a connection to that address.
                record = cdp.eval("""(async function(){
                    const created=await api('/assets',{method:'POST',body:{
                      label:'QA relay station',host:'192.0.2.48',port:22,
                      username:'operator',environment:'Lab',
                      auth_type:'interactive',credential_ref:'',key_file:'',
                      use_tmux:true,note:'CI-only demo record'
                    }});
                    await refreshAssets();
                    return {id:created.id,rows:document.querySelectorAll('.machine-entry').length};
                })()""")
                assert record["id"] and record["rows"] >= 1, record
                assert cdp.eval("""(function(){
                  return getComputedStyle(document.querySelector('.station-header')).backgroundColor==='rgb(32, 58, 48)' &&
                    getComputedStyle(document.querySelector('.directory-hero')).backgroundColor==='rgb(37, 72, 58)' &&
                    document.getElementById('stationVersion').textContent.includes('0.5.6-dev.1') &&
                    !document.querySelector('.sidebar');
                })()"""), "not the unique Station 02 UI (wrong image, CSS or cached shell)"

                for width in (1440, 1024, 840, 620, 360):
                    cdp.call("Emulation.setDeviceMetricsOverride", width=width,
                             height=900, deviceScaleFactor=1, mobile=False)
                    result = cdp.eval("""(function(){
                      const $=s=>document.querySelector(s);
                      const bounds=el=>{const r=el.getBoundingClientRect();
                        return {x:r.x,y:r.y,width:r.width,height:r.height,right:r.right,bottom:r.bottom};};
                      return {
                        viewport:innerWidth,scrollWidth:document.documentElement.scrollWidth,
                        header:bounds($('.station-header')),hero:bounds($('.directory-hero')),
                        roster:bounds($('#machineDirectory')),
                        visible:document.querySelectorAll('.page:not(.hidden)').length,
                        entryCount:document.querySelectorAll('.machine-entry').length,
                        mobileNavigation:getComputedStyle($('#navMobileToggle')).display!=='none'
                      };
                    })()""")
                    assert result["viewport"]==width, result
                    assert result["scrollWidth"] <= width+3, result
                    assert result["header"]["width"] >= width-3, result
                    assert result["hero"]["width"] >= width-3, result
                    assert result["roster"]["width"] >= width-35, result
                    assert result["visible"]==1 and result["entryCount"]>=1, result
                    assert result["mobileNavigation"] == (width<=980), result
                    cdp.screenshot(width)
                    print(f"PASS Station 02 roster at {width}px ({result['entryCount']} machines)",flush=True)

                cdp.call("Emulation.setDeviceMetricsOverride",
                         width=360,height=900,deviceScaleFactor=1,mobile=False)
                drawer = cdp.eval("""(function(){
                  const nav=document.getElementById('navMobileToggle');
                  const shell=document.getElementById('shell');
                  nav.click();
                  const open=shell.classList.contains('nav-open') &&
                    nav.getAttribute('aria-expanded')==='true';
                  document.getElementById('navDismiss').click();
                  return open && !shell.classList.contains('nav-open') &&
                    nav.getAttribute('aria-expanded')==='false';
                })()""")
                assert drawer, "mobile navigation drawer cannot open/close"

                find = cdp.eval("""(function(){
                  document.getElementById('globalFind').click();
                  return document.activeElement.id==='machineSearch' &&
                    !!document.querySelector('#page-machines:not(.hidden)');
                })()""")
                assert find, "global machine search should focus roster input"

                # A machine opens an independent canvas, not a permanent
                # two-column tree layout. All protocols remain available.
                assert cdp.eval("""(function(){
                  document.querySelector('.machine-entry-open').click();
                  return !!document.querySelector('#page-machine:not(.hidden)') &&
                    !!document.querySelector('#page-machines.hidden') &&
                    document.querySelector('.machine-layout').children.length===3 &&
                    !document.querySelector('.sidebar');
                })()"""), "machine roster cannot open independent workbench"
                result = cdp.eval("""(function(){
                  const stage=document.querySelector('.workbench-stage').getBoundingClientRect();
                  const layout=document.querySelector('.machine-layout').getBoundingClientRect();
                  return {stageWidth:stage.width,layoutWidth:layout.width,
                    stageHeight:stage.height};
                })()""")
                assert abs(result["stageWidth"]-result["layoutWidth"])<=4, result
                assert result["stageHeight"]>=340, result
                assert cdp.eval("""(function(){
                  const toggle=document.getElementById('machineTreeToggle');
                  toggle.click();
                  const opened=document.getElementById('machineLayout').classList.contains('tree-open');
                  document.getElementById('treeClose').click();
                  return opened && !document.getElementById('machineLayout').classList.contains('tree-open');
                })()"""), "on-demand machine switcher does not open/close"
                assert cdp.eval("""(function(){
                  document.getElementById('machineBackToDirectory').click();
                  return !!document.querySelector('#page-machines:not(.hidden)');
                })()"""), "back to machine directory did not restore home"
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
