// Theme initializer — runs synchronously before body renders to prevent FOUC.
// Reads the user's saved preference from localStorage and applies it immediately.
// Stored values may be "light", "dark", or "system"; "system" (and absent/other values)
// removes the explicit theme so Pico CSS follows the OS/browser preference.
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
