// Graphical console page: wires the vendored noVNC client (MPL-2.0, unmodified files
// under ./vendor/novnc-1.7.0) to the page. Loaded as a module from 'self' (strict CSP,
// no inline script). The WebSocket carries a one-time ticket; the BMC's VNC credential
// never reaches this page: the server authenticates to the BMC and offers "None" here.
import RFB from './vendor/novnc-1.7.0/core/rfb.js';

const screen = document.getElementById('console-screen');
const statusEl = document.getElementById('console-status');
const reconnect = document.getElementById('console-reconnect');
const buttons = {
  cad: document.getElementById('console-cad'),
  fullscreen: document.getElementById('console-fullscreen'),
  scale: document.getElementById('console-scale'),
  viewOnly: document.getElementById('console-viewonly'),
  disconnect: document.getElementById('console-disconnect'),
};

function setStatus(text, state) {
  statusEl.textContent = text;
  statusEl.dataset.state = state;
}

function enable(on) {
  for (const b of Object.values(buttons)) {
    b.disabled = !on;
  }
}

function toggle(button, value) {
  button.setAttribute('aria-pressed', value ? 'true' : 'false');
}

function wsURL(path, ticket) {
  const url = new URL(path, window.location.href);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  url.searchParams.set('ticket', ticket);
  return url.href;
}

function wire(rfb) {
  rfb.addEventListener('connect', () => {
    setStatus('Connected', 'connected');
    enable(true);
    rfb.focus();
  });
  rfb.addEventListener('disconnect', (e) => {
    enable(false);
    setStatus(e.detail.clean ? 'Disconnected' : 'Connection lost or refused', e.detail.clean ? 'disconnected' : 'error');
    if (document.fullscreenElement) {
      document.exitFullscreen().catch(() => {});
    }
    reconnect.hidden = false;
  });
  rfb.addEventListener('securityfailure', () => setStatus('The console could not be opened', 'error'));
  buttons.cad.addEventListener('click', () => {
    rfb.sendCtrlAltDel();
    rfb.focus();
  });
  buttons.fullscreen.addEventListener('click', () => {
    screen.requestFullscreen().then(() => rfb.focus()).catch(() => setStatus('Full screen is not available', 'connected'));
  });
  buttons.scale.addEventListener('click', () => {
    rfb.scaleViewport = !rfb.scaleViewport;
    toggle(buttons.scale, rfb.scaleViewport);
  });
  buttons.viewOnly.addEventListener('click', () => {
    rfb.viewOnly = !rfb.viewOnly;
    toggle(buttons.viewOnly, rfb.viewOnly);
  });
  buttons.disconnect.addEventListener('click', () => rfb.disconnect());
  // Release chord (WCAG 2.1.2): Ctrl+Alt+Shift hands focus back to the toolbar. The
  // capturing listener runs before noVNC's key handler on the canvas, and noVNC
  // releases every pressed key when the canvas loses focus.
  screen.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.altKey && e.shiftKey) {
      e.preventDefault();
      e.stopPropagation();
      rfb.blur();
      buttons.cad.focus();
    }
  }, true);
  window.addEventListener('pagehide', () => rfb.disconnect());
}

function start() {
  const ticket = screen.dataset.ticket;
  screen.removeAttribute('data-ticket');
  if (!ticket) {
    return;
  }
  const rfb = new RFB(screen, wsURL(screen.dataset.ws, ticket), { shared: false, wsProtocols: ['binary'] });
  rfb.scaleViewport = true;
  rfb.focusOnClick = true;
  rfb.background = '#000000';
  wire(rfb);
}

start();
