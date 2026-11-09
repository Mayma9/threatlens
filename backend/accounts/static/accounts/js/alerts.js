/* Alerts and confirmations with SweetAlert2.
   1. Every element marked data-tl-alert (Django messages, login error) becomes:
      - a pop-up window for errors and warnings (the user confirms it),
      - a toast in the top-right corner for success and info (closes by itself).
   2. Every form marked data-tl-confirm asks for confirmation before it is sent
      (data-confirm-text: explanation, data-confirm-button: label of the confirm button).
   Without SweetAlert2 (offline), the plain Bootstrap alerts stay on the page and
   confirmations use the browser's own dialog. */
(function () {
  "use strict";

  var confirmForms = document.querySelectorAll("form[data-tl-confirm]");

  if (!window.Swal) {
    Array.prototype.forEach.call(confirmForms, function (form) {
      form.addEventListener("submit", function (event) {
        if (!window.confirm(form.dataset.tlConfirm)) {
          event.preventDefault();
        }
      });
    });
    return;
  }

  var ICONS = { error: "error", warning: "warning", success: "success", info: "info", debug: "info" };
  var TITLES = { error: "Action failed", warning: "Check this" };
  var CLASSES = {
    popup: "tl-swal",
    title: "tl-swal__title",
    htmlContainer: "tl-swal__text",
    confirmButton: "btn btn-primary px-4",
    cancelButton: "btn btn-outline-light px-4",
    timerProgressBar: "tl-swal__progress",
  };

  var themed = Swal.mixin({ buttonsStyling: false, customClass: CLASSES });
  var toast = themed.mixin({
    toast: true,
    position: "top-end",
    showConfirmButton: false,
    timer: 4000,
    timerProgressBar: true,
    showCloseButton: true,
  });

  // 1. Messages
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

  // 2. Confirmations
  Array.prototype.forEach.call(confirmForms, function (form) {
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      themed.fire({
        icon: "warning",
        title: form.dataset.tlConfirm,
        text: form.dataset.confirmText || "",
        showCancelButton: true,
        confirmButtonText: form.dataset.confirmButton || "Confirm",
        cancelButtonText: "Cancel",
        reverseButtons: true,
        focusCancel: true,
        customClass: Object.assign({}, CLASSES, { confirmButton: "btn btn-danger px-4" }),
      }).then(function (result) {
        if (result.isConfirmed) {
          form.submit(); // submit() does not fire the submit event again
        }
      });
    });
  });
})();
