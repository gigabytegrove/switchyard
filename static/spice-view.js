/* SPICE runs in its own document to isolate screen ids, keyboard events and sessions.
 * Credentials arrive via an origin-checked parent message, never a URL or storage.
 */
import {SpiceMainConn, sendCtrlAltDel, resize_helper, handle_resize} from '/static/spice/main.js';

let spice = null;
let started = false;
let displayActive = false;
const screen = document.getElementById('spice-screen');
// A SPICE guest may have no vdagent. The screen is usable without onagent.
const displayObserver = new MutationObserver(() => {
  if (started && !displayActive && screen.querySelector('canvas')) {
    displayActive = true;
    screen.focus({preventScroll:true});
    status('Display active');
  }
});
displayObserver.observe(screen, {childList:true, subtree:true});
const origin = window.location.origin;
function status(text) {
  window.parent.postMessage({kind: 'switchyard-spice-status', status: text}, origin);
}
function stop() {
  if (spice) {
    try { spice.stop(); } catch (_) { /* already disconnected */ }
    spice = null;
  }
  displayActive = false;
  window.spice_connection = null;
}
window.addEventListener('message', event => {
  if (event.origin !== origin || event.source !== window.parent) return;
  const payload = event.data;
  if (!payload || typeof payload !== 'object') return;
  if (payload.kind === 'switchyard-spice-stop') {
    stop(); status('Disconnected'); return;
  }
  if (payload.kind === 'switchyard-spice-cad') {
    if (spice) sendCtrlAltDel(spice);
    return;
  }
  if (payload.kind !== 'switchyard-spice-start' || started) return;
  if (typeof payload.token !== 'string' || !/^[a-zA-Z0-9_-]{32,100}$/.test(payload.token)) {
    status('Invalid connection authorization'); return;
  }
  started = true;
  const url = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/spice/${payload.token}`;
  try {
    spice = new SpiceMainConn({
      uri: url,
      password: typeof payload.password === 'string' ? payload.password : '',
      screen_id: 'spice-screen', dump_id: 'debug-div', message_id: 'message-div',
      onerror: () => { status('SPICE connection failed'); stop(); },
      onagent: function () {
        window.spice_connection = this;
        resize_helper(this);
        status('Connected');
      },
    });
    status('Connecting…');
  } catch (error) {
    status('SPICE client could not start'); stop();
  }
});
window.addEventListener('resize', () => { if (spice) handle_resize(); });
window.addEventListener('pagehide', () => { stop(); displayObserver.disconnect(); });
window.parent.postMessage({kind:'switchyard-spice-ready'}, origin);
