// Go to palette: optional, loaded from 'self' with defer on signed-in pages (strict CSP: no
// inline script, no eval, no style attribute). Plan 04 §7 and §11 item 7; docs/tech_doc.md §52.
// Every page works without it: the sidebar, the account menu and the /go page are the palette.
//
// What it lists: the destinations the server rendered into <template id="oob-go"> (exactly
// what this user's sidebar and account menu show), the tabs of the server page it is on, and
// the recent pages of this browser tab (sessionStorage: same-origin paths and page titles of
// pages the server marked with <meta name="oob-recent">, never a query string, at most
// RECENT_MAX, bound to the signed-in user and dropped at sign-out). It only ever navigates to
// one of those GET paths: it submits no form and fetches nothing.
//
// Keys: Ctrl+K or Cmd+K opens it; "/" focuses the page's filter field, or opens it when the
// page has none; "g o" Overview, "g s" Servers; "?" the shortcut list (/go#shortcuts). None
// fires while a field, a contenteditable or a console frame has focus, nor anywhere on a page
// with a connected console (VNC or serial), so the remote host gets every key. The
// single-key shortcuts can be switched off per browser (WCAG 2.1.4) on /go#shortcuts.
//
// Removing it: delete its <script> line in layout.html; nothing else changes.
(function () {
  'use strict';

  var RECENT_KEY = 'oob.palette.recent';
  var KEYS_KEY = 'oob.shortcuts';
  var RECENT_MAX = 6;
  var LABEL_MAX = 120;
  var PATH_MAX = 200;
  var SEQUENCE_MS = 1500;
  var SVG = 'http://www.w3.org/2000/svg';
  var UNSAVED_NOTE = 'This page has unsaved input. Submit or clear it before you leave.';
  // Same-origin absolute paths only: "/" or "/a/b", no query, fragment, scheme, "//" or "." / ".."
  // segment (a stored "/servers/x/../../settings" would pass a prefix test, then normalize). Every
  // server ID passes (config idPattern ^[a-z0-9][a-z0-9-]{0,31}$; TestPalettePathPatternAcceptsEveryServerID).
  var PATH_RE = /^\/(?:\.*[A-Za-z0-9_-][A-Za-z0-9._-]*(?:\/\.*[A-Za-z0-9_-][A-Za-z0-9._-]*)*)?$/;

  var source = document.getElementById('oob-go');
  if (!source || !source.content) {
    return;
  }
  var who = document.querySelector('.usermenu .who-n');
  var user = who ? who.textContent.trim() : '';
  var mac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || '');
  var liveConsole = document.querySelector('[data-ticket]') !== null;
  var keysOff = null; // set by the /go toggle when storage is unavailable
  var dialog, input, list, empty, note, status, opener = null, active = -1, shown = [], gAt = 0;

  function cleanPath(p) {
    return typeof p === 'string' && p.length <= PATH_MAX && PATH_RE.test(p) ? p : '';
  }

  function cleanLabel(s) {
    return typeof s === 'string' ? s.replace(/\s+/g, ' ').trim().slice(0, LABEL_MAX) : '';
  }

  // ---- Storage: every access may throw (private mode, blocked site data); the palette then
  // simply has no recent list, and the shortcut switch lasts until the page is left.
  function readRecent() {
    var data = null;
    try {
      data = JSON.parse(window.sessionStorage.getItem(RECENT_KEY) || 'null');
    } catch (e) {
      return [];
    }
    if (!data || data.u !== user || !Array.isArray(data.items)) {
      return [];
    }
    var out = [];
    data.items.forEach(function (it) {
      var p = it ? cleanPath(it.p) : '';
      var l = it ? cleanLabel(it.l) : '';
      if (p && l && out.length < RECENT_MAX) {
        out.push({ p: p, l: l });
      }
    });
    return out;
  }

  function writeRecent(items) {
    try {
      window.sessionStorage.setItem(RECENT_KEY, JSON.stringify({ u: user, items: items }));
    } catch (e) {
      // Storage is off: the recent list is a convenience, nothing depends on it.
    }
  }

  function forgetRecent() {
    try {
      window.sessionStorage.removeItem(RECENT_KEY);
    } catch (e) {
      // Nothing was stored.
    }
  }

  function rememberThisPage() {
    var p = cleanPath(window.location.pathname);
    var l = cleanLabel(document.title.replace(/\s*·\s*oob-manager$/, ''));
    if (!user || !p || !l || !document.querySelector('meta[name="oob-recent"]')) {
      return;
    }
    var items = readRecent().filter(function (it) {
      return it.p !== p;
    });
    writeRecent([{ p: p, l: l }].concat(items).slice(0, RECENT_MAX));
  }

  function singleKeysOn() {
    if (keysOff !== null) {
      return !keysOff;
    }
    try {
      return window.localStorage.getItem(KEYS_KEY) !== 'off';
    } catch (e) {
      return true;
    }
  }

  function setSingleKeys(on) {
    keysOff = !on;
    try {
      if (on) {
        window.localStorage.removeItem(KEYS_KEY);
      } else {
        window.localStorage.setItem(KEYS_KEY, 'off');
      }
    } catch (e) {
      // Kept in memory for this page only.
    }
  }

  // ---- Destinations
  function item(group, label, hint, href) {
    var p = cleanPath(href);
    var l = cleanLabel(label);
    return p && l ? { group: group, label: l, hint: cleanLabel(hint), href: p } : null;
  }

  function templateGroups() {
    var out = [];
    source.content.querySelectorAll('[data-group]').forEach(function (g) {
      var items = [];
      g.querySelectorAll('li').forEach(function (li) {
        var a = li.querySelector('a');
        var hint = li.querySelector('.go-hint');
        var it = a && item(g.getAttribute('data-group'), a.textContent, hint ? hint.textContent : '', a.getAttribute('href'));
        if (it) {
          items.push(it);
        }
      });
      out.push({ label: g.getAttribute('data-group'), items: items });
    });
    return out;
  }

  // The tabs of the server page this is (its Overview, Sensors, History ...).
  function serverTabs() {
    var current = document.querySelector('.slist a[aria-current="page"] .sn');
    var name = current ? current.textContent : '';
    var items = [];
    document.querySelectorAll('nav.tabs[aria-label="Server sections"] a').forEach(function (a) {
      var span = a.querySelector('span');
      var it = item('This server', span ? span.textContent : a.textContent, name, a.getAttribute('href'));
      if (it) {
        items.push(it);
      }
    });
    return { label: 'This server', items: items };
  }

  // reachable reports whether this user can still open path p (a role or the fleet may have
  // changed since it was visited): it is one of today's destinations or this server's tabs,
  // or a page below one of them (a server's tab under /servers/<id>, a user under
  // /settings/users). "/" and "/servers" are never prefixes: a server that left the list
  // must not come back through a recent entry.
  function reachable(p, known) {
    return known.some(function (href) {
      return p === href || (href !== '/' && href !== '/servers' && p.indexOf(href + '/') === 0);
    });
  }

  // The recent pages this user can still reach, minus this one.
  function recentGroup(known) {
    var here = window.location.pathname;
    var items = [];
    readRecent().forEach(function (r) {
      var it = r.p !== here && reachable(r.p, known) && item('Recent', r.l, '', r.p);
      if (it) {
        items.push(it);
      }
    });
    return { label: 'Recent', items: items };
  }

  function allGroups() {
    var fromServer = templateGroups();
    var tabs = serverTabs();
    var known = [];
    [tabs].concat(fromServer).forEach(function (g) {
      g.items.forEach(function (it) {
        known.push(it.href);
      });
    });
    return [recentGroup(known), tabs].concat(fromServer).filter(function (g) {
      return g.items.length > 0;
    });
  }

  // Every word must appear in the label, the hint or the group (the /go filter's rule).
  function matches(it, words) {
    var text = (it.label + ' ' + it.hint + ' ' + it.group).toLowerCase();
    return words.every(function (w) {
      return text.indexOf(w) !== -1;
    });
  }

  // ---- The dialog
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) {
      e.className = cls;
    }
    if (text) {
      e.textContent = text;
    }
    return e;
  }

  function icon(name) {
    var svg = document.createElementNS(SVG, 'svg');
    var use = document.createElementNS(SVG, 'use');
    svg.setAttribute('class', 'ic ic-' + name);
    svg.setAttribute('width', '20');
    svg.setAttribute('height', '20');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');
    use.setAttribute('href', '#i-' + name);
    svg.appendChild(use);
    return svg;
  }

  function attrs(e, map) {
    Object.keys(map).forEach(function (k) {
      e.setAttribute(k, map[k]);
    });
    return e;
  }

  function buildHead() {
    var head = el('div', 'pal-head');
    var label = attrs(el('label', 'sr-only', 'Go to a page, server or setting'), { for: 'pal-q' });
    input = attrs(el('input', 'pal-q'), {
      id: 'pal-q', type: 'text', role: 'combobox', 'aria-autocomplete': 'list', 'aria-expanded': 'true',
      'aria-controls': 'pal-list', autocomplete: 'off', spellcheck: 'false', maxlength: '64', enterkeyhint: 'go',
    });
    var close = attrs(el('button', 'btn btn-quiet pal-x'), { type: 'button' });
    close.appendChild(icon('x'));
    close.appendChild(el('span', 'sr-only', 'Close'));
    close.addEventListener('click', closePalette);
    head.appendChild(icon('search'));
    head.appendChild(label);
    head.appendChild(input);
    head.appendChild(close);
    input.addEventListener('input', render);
    input.addEventListener('keydown', onInputKey);
    return head;
  }

  function buildFoot() {
    var foot = el('p', 'pal-foot');
    [['↑ ↓', 'move'], ['Enter', 'open'], ['Esc', 'close']].forEach(function (k) {
      var span = el('span');
      span.appendChild(el('kbd', '', k[0]));
      span.appendChild(document.createTextNode(' ' + k[1]));
      foot.appendChild(span);
    });
    foot.appendChild(attrs(el('a', '', 'All destinations and shortcuts'), { href: '/go' }));
    return foot;
  }

  function build() {
    dialog = attrs(el('dialog', 'pal'), { 'aria-modal': 'true', 'aria-labelledby': 'pal-h' });
    dialog.appendChild(attrs(el('h2', 'sr-only', 'Go to'), { id: 'pal-h' }));
    dialog.appendChild(buildHead());
    list = attrs(el('div', 'pal-list'), { id: 'pal-list', role: 'listbox', 'aria-label': 'Destinations' });
    empty = el('p', 'pal-empty', 'Nothing matches. The Go to page lists everything.');
    status = attrs(el('p', 'sr-only'), { role: 'status', 'aria-live': 'polite' });
    dialog.appendChild(list);
    dialog.appendChild(empty);
    note = attrs(el('p', 'pal-note'), { role: 'status' });
    note.hidden = true;
    dialog.appendChild(note);
    dialog.appendChild(buildFoot());
    dialog.appendChild(status);
    dialog.addEventListener('keydown', onDialogKey);
    dialog.addEventListener('click', onDialogClick);
    // A close the script did not start (the platform's back gesture, a close request).
    dialog.addEventListener('close', function () {
      if (opener) {
        restoreFocus();
      }
    });
    list.addEventListener('mousemove', function (e) {
      var o = e.target.closest('.pal-o');
      if (o && Number(o.getAttribute('data-i')) !== active) {
        setActive(Number(o.getAttribute('data-i')));
      }
    });
    document.body.appendChild(dialog);
  }

  // option is the row of the i-th shown destination.
  function option(it, i) {
    var o = attrs(el('div', 'pal-o'), { id: 'pal-o-' + i, role: 'option', 'aria-selected': 'false',
      'data-i': String(i) });
    o.appendChild(el('span', 'pal-l', it.label));
    if (it.hint) {
      o.appendChild(el('span', 'pal-hint', it.hint));
    }
    return o;
  }

  // filtered returns the groups with only their matching items (empty groups dropped).
  function filtered(words) {
    return allGroups().map(function (g) {
      return { label: g.label, items: g.items.filter(function (it) { return matches(it, words); }) };
    }).filter(function (g) {
      return g.items.length > 0;
    });
  }

  function render() {
    var groups = filtered(input.value.toLowerCase().split(/\s+/).filter(Boolean));
    var next = [];
    while (list.firstChild) {
      list.removeChild(list.firstChild);
    }
    groups.forEach(function (g) {
      var grp = attrs(el('div', 'pal-g'), { role: 'group', 'aria-label': g.label });
      grp.appendChild(attrs(el('div', 'pal-gh', g.label), { 'aria-hidden': 'true' }));
      g.items.forEach(function (it) {
        grp.appendChild(option(it, next.length));
        next.push(it);
      });
      list.appendChild(grp);
    });
    shown = next;
    list.hidden = shown.length === 0;
    input.setAttribute('aria-expanded', shown.length ? 'true' : 'false');
    empty.hidden = shown.length !== 0;
    note.hidden = true;
    note.textContent = '';
    status.textContent = shown.length === 1 ? '1 destination' : shown.length + ' destinations';
    setActive(shown.length ? 0 : -1);
  }

  function setActive(i) {
    var prev = list.querySelector('[aria-selected="true"]');
    if (prev) {
      prev.setAttribute('aria-selected', 'false');
    }
    active = i;
    if (i < 0) {
      input.removeAttribute('aria-activedescendant');
      return;
    }
    var o = document.getElementById('pal-o-' + i);
    o.setAttribute('aria-selected', 'true');
    input.setAttribute('aria-activedescendant', o.id);
    o.scrollIntoView({ block: 'nearest' });
  }

  // go opens a destination, unless the page holds unsaved input (the leaving shortcuts'
  // rule): then the palette stays open and says why, with no confirm dialog.
  function go(it) {
    if (!it || !cleanPath(it.href)) {
      return;
    }
    if (unsaved()) {
      note.hidden = false;
      note.textContent = UNSAVED_NOTE; // after unhiding, so the live region announces it
      return;
    }
    window.location.assign(it.href);
  }

  // composing: an IME is still building text (Safari reports the final keydown as keyCode 229
  // with isComposing false).
  function composing(e) {
    return e.isComposing || e.keyCode === 229;
  }

  function onInputKey(e) {
    var n = shown.length;
    if ((e.key === 'ArrowDown' || e.key === 'ArrowUp') && n > 0) {
      e.preventDefault();
      setActive(e.key === 'ArrowDown' ? (active + 1) % n : (active - 1 + n) % n);
    } else if (e.key === 'Enter' && !composing(e)) {
      e.preventDefault();
      go(shown[active]);
    }
  }

  // Escape closes; Ctrl/Cmd+K toggles; Tab stays inside the dialog (the field, the close
  // button and the link), wrapping at both ends.
  function onDialogKey(e) {
    if (e.key === 'Escape' && !composing(e)) {
      e.preventDefault();
      e.stopPropagation();
      closePalette();
    } else if ((e.key === 'k' || e.key === 'K') && (e.ctrlKey || e.metaKey) && !e.altKey) {
      e.preventDefault();
      closePalette();
    } else if (e.key === 'Tab') {
      var stops = Array.prototype.filter.call(dialog.querySelectorAll('input, button, a[href]'), function (x) {
        return x.offsetParent !== null;
      });
      var first = stops[0];
      var last = stops[stops.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  }

  function onDialogClick(e) {
    if (e.target === dialog) { // the backdrop
      closePalette();
      return;
    }
    var o = e.target.closest('.pal-o');
    if (o) {
      go(shown[Number(o.getAttribute('data-i'))]);
    }
  }

  // The element to return focus to: a link inside a menu goes back to the menu's summary,
  // since the menu closes when the palette opens.
  function focusTarget(a) {
    var menu = a && a.closest ? a.closest('details.menu') : null;
    return menu ? menu.querySelector('summary') : a;
  }

  function openPalette() {
    if (liveConsole || (dialog && dialog.open)) {
      return;
    }
    if (!dialog) {
      build();
    }
    opener = focusTarget(document.activeElement);
    document.querySelectorAll('details.menu[open]').forEach(function (d) {
      d.open = false;
    });
    input.value = '';
    render();
    dialog.showModal();
    input.focus();
  }

  function closePalette() {
    if (dialog && dialog.open) {
      dialog.close();
      restoreFocus(); // now, not on the "close" event: that one is queued, and a key may come first
    }
  }

  function restoreFocus() {
    var o = opener;
    opener = null;
    if (o && o.isConnected && typeof o.focus === 'function' && o !== document.body) {
      o.focus();
    } else if (dialog.contains(document.activeElement)) {
      // Opened from the page itself: leave no focus on the hidden field (Chromium keeps it
      // there, and every later key would count as typing).
      document.activeElement.blur();
    }
  }

  // ---- Shortcuts
  function typing(t) {
    return !!t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName));
  }

  function inConsole(t) {
    return !!(t && t.closest && t.closest('.con-frame, .console-screen, .serial-term, .xterm'));
  }

  // The page's own filter field (Events, Firmware, the audit log, /go).
  function pageFilter() {
    return document.querySelector('main form.filters input[type="search"]') ||
      document.querySelector('main form.filters input[type="text"]');
  }

  // leave navigates away, unless a form on the page holds input not yet submitted (two stray
  // keys must never discard an edit; app.js pauses its auto-refresh by the same rule).
  function leave(e, path) {
    e.preventDefault();
    if (!unsaved()) {
      window.location.assign(path);
    }
  }

  function unsaved() {
    return Array.prototype.some.call(document.querySelectorAll('main input, main textarea, main select'), function (c) {
      if (/^(hidden|submit|button|reset|image)$/.test(c.type)) {
        return false;
      }
      if (c.type === 'checkbox' || c.type === 'radio') {
        return c.checked !== c.defaultChecked;
      }
      if (c.tagName === 'SELECT') {
        return Array.prototype.some.call(c.options, function (o) { return o.selected !== o.defaultSelected; });
      }
      return c.value !== c.defaultValue;
    });
  }

  function singleKey(e) {
    var now = Date.now();
    var after = gAt !== 0 && now - gAt < SEQUENCE_MS;
    gAt = 0;
    if (after && (e.key === 'o' || e.key === 's')) {
      leave(e, e.key === 'o' ? '/' : '/servers');
    } else if (!after && e.key === 'g') {
      gAt = now;
    } else if (e.key === '/') {
      e.preventDefault();
      var f = pageFilter();
      if (f) {
        f.focus();
        f.select();
      } else {
        openPalette();
      }
    } else if (e.key === '?') {
      leave(e, '/go#shortcuts');
    }
  }

  function onKey(e) {
    if (e.defaultPrevented || composing(e) || liveConsole || (dialog && dialog.open)) {
      return;
    }
    if (typing(e.target) || inConsole(e.target) || document.fullscreenElement) {
      return;
    }
    if ((e.key === 'k' || e.key === 'K') && (e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey) {
      e.preventDefault();
      openPalette();
    } else if (e.ctrlKey || e.metaKey || e.altKey) {
      gAt = 0;
    } else if (singleKeysOn()) {
      singleKey(e);
    }
  }

  // ---- Wiring
  rememberThisPage();
  document.addEventListener('keydown', onKey);
  // "Go to…" links (account menu, Menu sheet) open the palette; a modified click, no script
  // at all, or a page with a connected console follows the link to /go.
  document.addEventListener('click', function (e) {
    var a = e.target.closest ? e.target.closest('a[data-palette]') : null;
    if (a && !liveConsole && e.button === 0 && !e.ctrlKey && !e.metaKey && !e.shiftKey && !e.altKey) {
      e.preventDefault();
      openPalette();
    }
  });
  document.addEventListener('submit', function (e) {
    if (e.target.getAttribute && e.target.getAttribute('action') === '/logout') {
      forgetRecent();
    }
  }, true);
  // Back to a page kept in the back/forward cache: never with the palette still open.
  window.addEventListener('pageshow', function (e) {
    if (e.persisted) {
      closePalette();
    }
  });
  if (!liveConsole) {
    document.querySelectorAll('[data-palette-key]').forEach(function (k) {
      k.textContent = mac ? '⌘ K' : 'Ctrl K';
      k.hidden = false;
    });
  }
  var toggle = document.getElementById('sc-toggle');
  var box = document.getElementById('sc-on');
  if (toggle && box) {
    box.checked = singleKeysOn();
    box.defaultChecked = box.checked;
    toggle.hidden = false;
    box.addEventListener('change', function () {
      setSingleKeys(box.checked);
      box.defaultChecked = box.checked; // saved at once: not unsaved input
    });
  }
})();
