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
