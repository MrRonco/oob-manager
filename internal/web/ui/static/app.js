// Optional enhancement, loaded from 'self' (strict CSP: no inline script). Every page
// works without it; it only adds conveniences:
// - Escape (or a click outside) closes an open menu (<details class="menu">).
// - "Copy" buttons next to shown-once secrets and the build info.
// - The "Change role" button stays disabled until another role is chosen.
// - A signed-out page drops the Go to palette's recent pages (palette.js, tech_doc §52).
// - Auto-refresh (opt-in) reloads the page on the server's interval, but never while a
//   field has focus or holds unsaved input (audit R2-02); without scripts the
//   <noscript> meta refresh applies, on pages that carry no typed input.
(function () {
  'use strict';

  var refreshMeta = document.querySelector('meta[name="oob-refresh"]');
  var refreshEvery = refreshMeta ? parseInt(refreshMeta.getAttribute('content'), 10) * 1000 : 0;
  var refreshRetry = 5000;

  function typedControl(el) {
    return !/^(hidden|submit|button|reset|image)$/.test(el.type);
  }

  function dirty(el) {
    if (el.type === 'checkbox' || el.type === 'radio') {
      return el.checked !== el.defaultChecked;
    }
    if (el.tagName === 'SELECT') {
      for (var i = 0; i < el.options.length; i++) {
        if (el.options[i].selected !== el.options[i].defaultSelected) {
          return true;
        }
      }
      return false;
    }
    return el.value !== el.defaultValue;
  }

  // editing: a form control has focus, or holds something not yet submitted.
  function editing() {
    var active = document.activeElement;
    if (active && /^(INPUT|TEXTAREA|SELECT)$/.test(active.tagName) && typedControl(active)) {
      return true;
    }
    var controls = document.querySelectorAll('input, textarea, select');
    for (var i = 0; i < controls.length; i++) {
      if (typedControl(controls[i]) && dirty(controls[i])) {
        return true;
      }
    }
    return false;
  }

  function refreshTick() {
    if (editing()) {
      document.documentElement.setAttribute('data-refresh-paused', '1');
      window.setTimeout(refreshTick, refreshRetry);
      return;
    }
    window.location.reload();
  }

  if (refreshEvery > 0) {
    window.setTimeout(refreshTick, refreshEvery);
  }

  function closeMenus(except) {
    document.querySelectorAll('details.menu[open]').forEach(function (d) {
      if (d !== except) {
        d.open = false;
      }
    });
  }

  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape') {
      return;
    }
    var open = document.querySelector('details.menu[open]');
    if (open) {
      open.open = false;
      open.querySelector('summary').focus();
    }
  });

  document.addEventListener('click', function (e) {
    closeMenus(e.target.closest('details.menu'));
  });

  document.querySelectorAll('[data-copy]').forEach(function (button) {
    var source = document.getElementById(button.getAttribute('data-copy'));
    var status = document.querySelector('[data-copy-status="' + button.getAttribute('data-copy') + '"]');
    if (!source || !navigator.clipboard) {
      return;
    }
    button.hidden = false;
    button.addEventListener('click', function () {
      var text = source.value !== undefined ? source.value : source.textContent;
      navigator.clipboard.writeText(text.trim()).then(function () {
        if (status) {
          status.textContent = 'Copied.';
        }
      }, function () {
        if (status) {
          status.textContent = 'Copy failed: select the text and copy it by hand.';
        }
      });
    });
  });

  // A page without the Go to list is a signed-out one (sign-in, an expired or revoked
  // session): drop the palette's recent pages of this tab, whoever they belonged to.
  if (!document.getElementById('oob-go')) {
    try {
      window.sessionStorage.removeItem('oob.palette.recent');
    } catch (e) {
      // Storage is off: nothing was stored.
    }
  }

  document.querySelectorAll('form[data-role-form]').forEach(function (form) {
    var button = form.querySelector('button[type="submit"]');
    var current = form.querySelector('input[data-current]');
    if (!button || !current) {
      return;
    }
    function update() {
      button.disabled = current.checked;
    }
    form.addEventListener('change', update);
    update();
  });
})();
