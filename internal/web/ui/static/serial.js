// Serial console page: wires the vendored xterm.js 6.0.0 terminal (MIT, unmodified files
// under ./vendor) to the serial WebSocket. Loaded as a module from 'self' (strict CSP, no
// inline script). The socket carries a one-time ticket; the BMC login never reaches this
// page. Binary messages are terminal bytes; text messages are JSON status/control
// (resize, break, quit) — see internal/console/serial_proto.go.
import { Terminal } from './vendor/xterm-6.0.0/xterm.mjs';
import { FitAddon } from './vendor/xterm-addon-fit-0.11.0/addon-fit.mjs';

const host = document.getElementById('serial-term');
const statusEl = document.getElementById('serial-status');
const reconnect = document.getElementById('serial-reconnect');
const silent = document.getElementById('serial-silent');
const transcript = document.getElementById('serial-transcript');
const announce = document.getElementById('serial-announce');
const buttons = {
  brk: document.getElementById('serial-break'),
  quit: document.getElementById('serial-quit'),
  copy: document.getElementById('serial-copy'),
  smaller: document.getElementById('serial-smaller'),
  larger: document.getElementById('serial-larger'),
  disconnect: document.getElementById('serial-disconnect'),
};

const FONT_KEY = 'oob.serial.fontSize';
const FONT_MIN = 10;
const FONT_MAX = 28;
const SILENT_AFTER_MS = 8000;
const TRANSCRIPT_MAX = 200000; // characters kept in the plain-text transcript

const ERRORS = {
  host_key: 'The BMC’s SSH host key does not match the configured key. Nothing was sent to it.',
  bmc_auth: 'The BMC rejected the operator login.',
  algorithms: 'The BMC offers no SSH algorithm in common with oob-manager.',
  bmc_protocol: 'The BMC refused the serial console.',
  timeout: 'The BMC did not answer in time.',
  unreachable: 'The BMC’s SSH service could not be reached.',
  config: 'The serial console is not configured for this server.',
};
const ENDS = {
  quit: 'Console ended',
  idle_timeout: 'Disconnected after the idle limit',
  max_session: 'Disconnected: longest session reached',
  taken_over: 'Disconnected: another admin took over',
  shutdown: 'Disconnected: oob-manager is shutting down',
  session_ended: 'Disconnected: your sign-in ended',
  stepup_expired: 'Disconnected: confirmation expired',
  forbidden: 'Disconnected: your role no longer allows the console',
  bmc_closed: 'The BMC closed the console',
  protocol: 'Disconnected after an unexpected message',
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

function readFont() {
  try {
    const n = parseInt(window.localStorage.getItem(FONT_KEY) || '', 10);
    return Number.isInteger(n) && n >= FONT_MIN && n <= FONT_MAX ? n : 15;
  } catch {
    return 15;
  }
}

function saveFont(n) {
  try {
    window.localStorage.setItem(FONT_KEY, String(n));
  } catch {
    // storage unavailable (private window): the size is kept for this page only
  }
}

function wsURL(path, ticket) {
  const url = new URL(path, window.location.href);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  url.searchParams.set('ticket', ticket);
  return url.href;
}

// plainText strips terminal control sequences for the transcript: CSI and OSC sequences,
// other escapes, carriage returns and control characters except newline and tab.
function plainText(s) {
  return s
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/\x1b\][^\x07\x1b]*(\x07|\x1b\\)/g, '')
    .replace(/\x1b[@-Z\\-_]/g, '')
    .replace(/\r\n?/g, '\n')
    .replace(/[\x00-\x08\x0b-\x1f\x7f]/g, '');
}

function appendTranscript(text) {
  if (!text) {
    return;
  }
  let all = transcript.textContent + text;
  if (all.length > TRANSCRIPT_MAX) {
    all = all.slice(all.length - TRANSCRIPT_MAX);
  }
  transcript.textContent = all;
  transcript.scrollTop = transcript.scrollHeight;
}

function start() {
  const ticket = host.dataset.ticket;
  host.removeAttribute('data-ticket');
  if (!ticket) {
    return;
  }
  let fontSize = readFont();
  host.style.setProperty('--serial-font-size', fontSize + 'px');
  const term = new Terminal({
    screenReaderMode: true, fontSize, scrollback: 5000, cursorBlink: false, convertEol: false,
    fontFamily: 'ui-monospace, "DejaVu Sans Mono", Menlo, Consolas, monospace',
  });
  const fit = new FitAddon();
  term.loadAddon(fit);
  term.open(host);
  fit.fit();

  const ws = new WebSocket(wsURL(host.dataset.ws, ticket), ['oob-serial.v1']);
  ws.binaryType = 'arraybuffer';
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  let received = false;
  let silentTimer = 0;
  let ended = '';

  const send = (obj) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(obj));
    }
  };
  const sendSize = () => send({ type: 'resize', cols: term.cols, rows: term.rows });

  ws.addEventListener('message', (e) => {
    if (typeof e.data !== 'string') {
      const bytes = new Uint8Array(e.data);
      term.write(bytes);
      appendTranscript(plainText(decoder.decode(bytes, { stream: true })));
      if (!received) {
        received = true;
        silent.hidden = true;
        window.clearTimeout(silentTimer);
      }
      return;
    }
    let msg;
    try {
      msg = JSON.parse(e.data);
    } catch {
      return;
    }
    if (msg.type === 'connected') {
      setStatus('Connected', 'connected');
      enable(true);
      sendSize();
      term.focus();
      silentTimer = window.setTimeout(() => {
        if (!received) {
          silent.hidden = false;
        }
      }, SILENT_AFTER_MS);
    } else if (msg.type === 'error') {
      ended = ERRORS[msg.class] || 'The serial console could not be opened.';
      setStatus(ended, 'error');
    } else if (msg.type === 'end') {
      ended = ENDS[msg.reason] || 'Disconnected';
      setStatus(ended, msg.reason === 'quit' ? 'disconnected' : 'error');
    }
  });
  ws.addEventListener('close', () => {
    enable(false);
    window.clearTimeout(silentTimer);
    if (!ended) {
      setStatus('Connection lost or refused', 'error');
    }
    reconnect.hidden = false;
  });

  term.onData((d) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(encoder.encode(d));
    }
  });
  term.onBinary((d) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(Uint8Array.from(d, (c) => c.charCodeAt(0) & 0xff));
    }
  });
  term.onResize(sendSize);
  // Release chord (WCAG 2.1.2): Ctrl+Alt+Shift hands focus back to the toolbar.
  term.attachCustomKeyEventHandler((e) => {
    if (e.type === 'keydown' && e.ctrlKey && e.altKey && e.shiftKey) {
      term.blur();
      buttons.brk.focus();
      return false;
    }
    return true;
  });

  let resizeTimer = 0;
  window.addEventListener('resize', () => {
    window.clearTimeout(resizeTimer);
    resizeTimer = window.setTimeout(() => fit.fit(), 150);
  });
  const setFont = (n) => {
    fontSize = Math.min(FONT_MAX, Math.max(FONT_MIN, n));
    host.style.setProperty('--serial-font-size', fontSize + 'px');
    term.options.fontSize = fontSize;
    saveFont(fontSize);
    fit.fit();
    term.focus();
  };

  buttons.brk.addEventListener('click', () => {
    send({ type: 'break' });
    term.focus();
  });
  buttons.quit.addEventListener('click', () => send({ type: 'quit' }));
  buttons.copy.addEventListener('click', () => {
    const text = term.getSelection() || transcript.textContent;
    navigator.clipboard.writeText(text).then(
      () => setStatus('Copied to the clipboard', 'connected'),
      () => setStatus('Copy is not available in this browser', 'connected'),
    );
  });
  buttons.smaller.addEventListener('click', () => setFont(fontSize - 1));
  buttons.larger.addEventListener('click', () => setFont(fontSize + 1));
  buttons.disconnect.addEventListener('click', () => ws.close(1000));
  announce.addEventListener('change', () => {
    transcript.setAttribute('aria-live', announce.checked ? 'polite' : 'off');
  });
  window.addEventListener('pagehide', () => ws.close(1000));
}

start();
