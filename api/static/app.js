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
