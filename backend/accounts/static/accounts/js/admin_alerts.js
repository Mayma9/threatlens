/* Marks the Django admin's own messages so that alerts.js shows them with SweetAlert2:
   - p.errornote: login refused, access refused, "Please correct the errors below." (pop-up)
   - ul.messagelist li: messages after saving or deleting (toast, or pop-up for errors and warnings)
   Must be loaded before alerts.js. */
(function () {
  "use strict";
  var onLoginPage = document.body.classList.contains("login");

  var notes = Array.prototype.slice.call(document.querySelectorAll("p.errornote"));
  if (onLoginPage && notes.length > 1) {
    // Wrong password while logged in with a non-admin account: only the login error matters
    notes = notes.filter(function (el) {
      var keep = !/not authorized/i.test(el.textContent);
      if (!keep) { el.style.display = "none"; }
      return keep;
    });
  }

  notes.forEach(function (el) {
    var text = el.textContent.trim();
    el.setAttribute("data-tl-alert", "");
    el.dataset.level = "error";
    if (/not authorized/i.test(text)) {
      el.dataset.title = "Access denied"; // Django's text names the account and suggests another login
      el.dataset.button = "Log in with another account";
    } else if (onLoginPage) {
      el.dataset.title = "Login failed";
      el.dataset.text = "Invalid username or password for an administrator account. Check both fields and try again.";
      el.dataset.button = "Try again";
    } else {
      el.dataset.title = "Not saved";
      el.dataset.text = text + " The fields to correct are highlighted.";
    }
  });

  Array.prototype.forEach.call(document.querySelectorAll("ul.messagelist > li"), function (li) {
    var level = ["error", "warning", "success", "info", "debug"].filter(function (name) {
      return li.classList.contains(name);
    })[0] || "info";
    li.setAttribute("data-tl-alert", "");
    li.dataset.level = level;
  });
})();
