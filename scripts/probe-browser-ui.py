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
    with tempfile.TemporaryDirectory(prefix="switchyard-ui-") as profile:
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
                  document.querySelector('#machineSwitcher').children.length > 0""",
                          "authenticated machine workbench")
                print(f"PASS: login -> usable operations desk in {time.monotonic()-started:.2f}s",flush=True)

                for width in (1440, 1024, 840, 620, 360):
                    cdp.call("Emulation.setDeviceMetricsOverride", width=width,
                             height=900, deviceScaleFactor=1, mobile=False)
                    result = cdp.eval("""(function(){
                      const $=s=>document.querySelector(s);
                      const bounds=el=>{const r=el.getBoundingClientRect();
                        return {x:r.x,y:r.y,width:r.width,height:r.height,right:r.right,bottom:r.bottom};};
                      const stage=bounds($('.workbench-stage'));
                      const area=bounds($('.machine-work-area'));
                      const shell=bounds($('#shell'));
                      const machine=bounds($('#page-machine'));
                      const menu=$('#machineCommandMenu');
                      menu.open=true;
                      const detailVisible=getComputedStyle($('#machineInfoToggle')).display!=='none';
                      menu.open=false;
                      return {
                        viewport:innerWidth,scrollWidth:document.documentElement.scrollWidth,
                        stage,area,shell,machine,detailVisible,
                        mobileNavigation:getComputedStyle($('#navMobileToggle')).display!=='none',
                        activeRoutes:document.querySelectorAll('.page:not(.hidden)').length
                      };
                    })()""")
                    assert result["viewport"] == width, result
                    assert result["scrollWidth"] <= width + 3, result
                    assert result["stage"]["width"] >= min(width-40, 250), result
                    assert result["stage"]["height"] >= 350, result
                    assert result["area"]["x"] >= -1 and result["area"]["right"] <= width+2, result
                    assert result["machine"]["height"] >= 600, result
                    assert result["detailVisible"], result
                    assert result["activeRoutes"] == 1, result
                    assert result["mobileNavigation"] == (width <= 840), result
                    cdp.screenshot(width)
                    print(f"PASS: viewport {width}px, work stage {result['stage']['width']:.0f}x{result['stage']['height']:.0f}",flush=True)

                cdp.call("Emulation.setDeviceMetricsOverride",
                         width=360,height=900,deviceScaleFactor=1,mobile=False)
                assert cdp.eval("""(function(){
                  const nav=document.getElementById('navMobileToggle');
                  nav.click();
                  if(!document.getElementById('shell').classList.contains('nav-open'))return false;
                  if(nav.getAttribute('aria-expanded')!=='true')return false;
                  document.getElementById('navDismiss').click();
                  return !document.getElementById('shell').classList.contains('nav-open') &&
                    nav.getAttribute('aria-expanded')==='false';
                })()"""), "mobile navigation drawer cannot open/close"

                assert cdp.eval("""(function(){
                  document.getElementById('globalFind').click();
                  return document.activeElement.id==='machineSwitchSearch' &&
                    document.getElementById('machineLayout').classList.contains('tree-open');
                })()"""), "global search did not open and focus mobile machine rack"
                assert cdp.eval("""(function(){
                  window.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}));
                  return !document.getElementById('machineLayout').classList.contains('tree-open');
                })()"""), "Escape did not close machine rack"
                assert not cdp.uncaught, f"Uncaught browser exceptions: {cdp.uncaught}"
                print("PASS: live browser at 1440/1024/840/620/360, drawer, search, "
                      "focus and uncaught-exception checks",flush=True)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


if __name__ == "__main__":
    run()
