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
