/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

"use strict";

var Cu = Components.utils;
var Cc = Components.classes;
var Ci = Components.interfaces;


var Enigmail = {
  onLoad: function(event) {},

  onClose: function(event) {},

  onUnloadEnigmail: function() {
    window.removeEventListener("load-enigmail", Enigmail.onLoad, true);
    window.removeEventListener("unload-enigmail", Enigmail.onUnload, true);
    window.removeEventListener("dialogaccept", Enigmail.onClose, false);
    window.removeEventListener("dialogcancel", Enigmail.onClose, false);
  }
};

window.addEventListener("load-enigmail", Enigmail.onLoad.bind(Enigmail), true);
window.addEventListener("unload-enigmail", Enigmail.onUnloadEnigmail.bind(Enigmail), true);
window.addEventListener("dialogaccept", Enigmail.onClose.bind(Enigmail), false);
window.addEventListener("dialogcancel", Enigmail.onClose.bind(Enigmail), false);
