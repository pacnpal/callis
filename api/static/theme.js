// Theme initializer — runs synchronously before body renders to prevent FOUC.
// Reads the user's saved preference from localStorage and applies it immediately.
// Valid values: "light", "dark", or absent/other (system default — Pico CSS auto-detects).
(function () {
  try {
    var t = localStorage.getItem("callis-theme");
    if (t === "light" || t === "dark") {
      document.documentElement.setAttribute("data-theme", t);
    } else {
      document.documentElement.removeAttribute("data-theme");
    }
  } catch (_) {
    // localStorage unavailable (private browsing, storage disabled) — use system theme
  }
})();
