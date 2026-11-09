/* Shows the page's alerts with SweetAlert2.
   Every element marked data-tl-alert (Django messages, login error) becomes:
   - a pop-up window for errors and warnings (the user confirms it),
   - a toast in the top-right corner for success and info (closes by itself).
   Without SweetAlert2 (offline), the plain Bootstrap alerts stay on the page. */
(function () {
  "use strict";
  if (!window.Swal) {
    return;
  }

  var ICONS = { error: "error", warning: "warning", success: "success", info: "info", debug: "info" };
  var TITLES = { error: "Action failed", warning: "Check this" };

  var themed = Swal.mixin({
    buttonsStyling: false,
    customClass: {
      popup: "tl-swal",
      title: "tl-swal__title",
      htmlContainer: "tl-swal__text",
      confirmButton: "btn btn-primary px-4",
      timerProgressBar: "tl-swal__progress",
    },
  });
  var toast = themed.mixin({
    toast: true,
    position: "top-end",
    showConfirmButton: false,
    timer: 4000,
    timerProgressBar: true,
    showCloseButton: true,
  });

  var alerts = Array.prototype.map.call(document.querySelectorAll("[data-tl-alert]"), function (el) {
    el.classList.add("d-none"); // the pop-up replaces the inline alert
    var text = el.dataset.text || el.textContent.trim();
    return { level: el.dataset.level || "info", title: el.dataset.title, text: text, button: el.dataset.button };
  });

  var popups = alerts.filter(function (a) { return a.level === "error" || a.level === "warning"; });
  var toasts = alerts.filter(function (a) { return a.level !== "error" && a.level !== "warning"; });

  // Pop-ups one after the other, then the toasts one after the other
  var chain = Promise.resolve();
  popups.forEach(function (a) {
    chain = chain.then(function () {
      return themed.fire({
        icon: ICONS[a.level],
        title: a.title || TITLES[a.level],
        text: a.text, // text, not html: messages are never interpreted as markup
        confirmButtonText: a.button || "OK",
      });
    });
  });
  toasts.forEach(function (a) {
    chain = chain.then(function () {
      return toast.fire({ icon: ICONS[a.level], title: a.text });
    });
  });
})();
