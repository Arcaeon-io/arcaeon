// SPDX-License-Identifier: MIT
// arcaeon dashboard: small conveniences only. Every page is rendered on the
// server and reads the same with this file blocked. No fetch, no network,
// nothing loaded from anywhere else.
"use strict";

document.documentElement.classList.add("js");

// A check can take a moment: stop a second click from sending it twice.
document.addEventListener("submit", function (event) {
  var form = event.target;
  var buttons = form.querySelectorAll("button[type=submit]");
  for (var i = 0; i < buttons.length; i++) {
    buttons[i].disabled = true;
    buttons[i].textContent = "Checking...";
  }
});
