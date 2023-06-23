/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

"use strict";

var Cu = Components.utils;
var Cc = Components.classes;
var Ci = Components.interfaces;

const EnigmailLocalizeHtml = ChromeUtils.import("chrome://enigmail/content/modules/localizeHtml.jsm").EnigmailLocalizeHtml;
const EnigmailWindows = ChromeUtils.import("chrome://enigmail/content/modules/windows.jsm").EnigmailWindows;
const EnigmailGnuPGUpdate = ChromeUtils.import("chrome://enigmail/content/modules/gnupgUpdate.jsm").EnigmailGnuPGUpdate;
const EnigmailCore = ChromeUtils.import("chrome://enigmail/content/modules/core.jsm").EnigmailCore;
const EnigmailTimer = ChromeUtils.import("chrome://enigmail/content/modules/timer.jsm").EnigmailTimer;
const EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;

function onload() {
  EnigmailLog.DEBUG(`aboutEnigmail.js: onLoad():\n`);
  EnigmailTimer.setTimeout(() => {
    EnigmailLocalizeHtml.onPageLoad(document);
    EnigmailLog.DEBUG(`aboutEnigmail.js: onLoad: page loaded\n`);

    let enigmailSvc = EnigmailCore.getService();
    EnigmailLog.DEBUG(`aboutEnigmail.js: onLoad: service: ${enigmailSvc}\n`);

    if (enigmailSvc) {
      if (EnigmailGnuPGUpdate.isGnuPGUpdatable()) {
        document.getElementById("checkGnupgUpdate").classList.remove("hidden");
      }
    }
  }, 50);
}

function checkGnupgUpdate() {
  EnigmailWindows.openGnuPGUpdate();
}
