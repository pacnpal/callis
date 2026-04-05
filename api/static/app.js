// Theme toggle — cycles through system → light → dark.
// Stores preference in localStorage; Pico CSS applies the active theme via data-theme.
(function () {
  var MODES = ["system", "light", "dark"];
  var ICONS = {
    system: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>',
    light: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>',
    dark: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>'
  };
  var LABELS = {
    system: "Theme: auto (system). Click for light.",
    light: "Theme: light. Click for dark.",
    dark: "Theme: dark. Click for auto."
  };

  function current() {
    try {
      var v = localStorage.getItem("callis-theme");
      return MODES.indexOf(v) !== -1 ? v : "system";
    } catch (_) {
      return "system";
    }
  }

  function apply(mode) {
    try { localStorage.setItem("callis-theme", mode); } catch (_) {}
    if (mode === "light" || mode === "dark") {
      document.documentElement.setAttribute("data-theme", mode);
    } else {
      document.documentElement.removeAttribute("data-theme");
    }
    updateButtons();
  }

  function updateButtons() {
    var mode = current();
    var btns = document.querySelectorAll("[data-theme-toggle]");
    for (var i = 0; i < btns.length; i++) {
      btns[i].innerHTML = ICONS[mode];
      btns[i].setAttribute("aria-label", LABELS[mode]);
    }
  }

  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-theme-toggle]");
    if (!btn) return;
    var next = MODES[(MODES.indexOf(current()) + 1) % MODES.length];
    apply(next);
  });

  updateButtons();
})();

// Dialog open/close handlers (replaces inline onclick for CSP compliance)
document.addEventListener("click", function (e) {
  var btn = e.target.closest("[data-dialog-open]");
  if (btn) {
    var d = document.getElementById(btn.getAttribute("data-dialog-open"));
    if (d) d.showModal();
  }
  btn = e.target.closest("[data-dialog-close]");
  if (btn) {
    var d = btn.closest("dialog");
    if (d) d.close();
  }
});

// Copy-to-clipboard handler (SSH config and other copyable blocks)
// Uses navigator.clipboard when available (requires HTTPS), falls back to
// execCommand('copy') for HTTP/LAN deployments.
document.addEventListener("click", function (e) {
  var btn = e.target.closest("[data-copy-trigger]");
  if (!btn) return;
  var targetId = btn.getAttribute("data-copy-trigger");
  var target = document.querySelector('[data-copy-target="' + targetId + '"]');
  if (!target) return;
  var text = target.textContent;

  function onSuccess() {
    var orig = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(function () { btn.textContent = orig; }, 2000);
  }

  function fallbackCopy() {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try {
      if (document.execCommand("copy")) onSuccess();
    } catch (_) {}
    document.body.removeChild(ta);
  }

  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(onSuccess).catch(fallbackCopy);
  } else {
    fallbackCopy();
  }
});

// Host user assignment: auto-submit on select change
document.addEventListener("change", function (e) {
  var sel = e.target.closest(".assign-select");
  if (sel && sel.value) {
    var form = sel.closest("form");
    var hostRow = sel.closest("tr");
    var hostId = hostRow ? hostRow.id.replace("host-row-", "") : "";
    if (hostId && window.htmx) {
      form.setAttribute("hx-post", "/hosts/" + hostId + "/assign/" + sel.value);
      window.htmx.process(form);
      window.htmx.trigger(form, "submit");
    }
  }
});
