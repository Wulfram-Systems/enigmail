/**
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */


"use strict";

var EnigmailCore = ChromeUtils.import("chrome://enigmail/content/modules/core.jsm").EnigmailCore;
var EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
var EnigmailLocale = ChromeUtils.import("chrome://enigmail/content/modules/locale.jsm").EnigmailLocale;
var EnigmailDialog = ChromeUtils.import("chrome://enigmail/content/modules/dialog.jsm").EnigmailDialog;
var EnigmailPasswordCheck = ChromeUtils.import("chrome://enigmail/content/modules/passwordCheck.jsm").EnigmailPasswordCheck;
var EnigmailCryptoAPI = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI.jsm").EnigmailCryptoAPI;
var EnigmailKeyRing = ChromeUtils.import("chrome://enigmail/content/modules/keyRing.jsm").EnigmailKeyRing;


var gPasswdDontMatch, gAcceptButton, gNewPasswd, gRepeatPasswd, gQualityMeter;

function onLoad() {
  let keyObj = EnigmailKeyRing.getKeyById(window.arguments[0].keyId);
  let uid = window.window.arguments[0].userId + " - " + keyObj.fprFormatted;
  document.getElementById("keyInfo").value = uid;

  const dlg = document.getElementById("enigmailChangePwdDlg");
  gAcceptButton = dlg.getButton("accept");
  gNewPasswd = document.getElementById("newPasswd");
  gRepeatPasswd = document.getElementById("repeatPasswd");
  gPasswdDontMatch = document.getElementById("passwdDontMatch");
  gQualityMeter = document.getElementById("qualityMeter");

  if (window.window.arguments[0].noCurrentPasswd) {
    document.getElementById("currentPasswdRow").setAttribute("collapsed", "true");
  }

  gNewPasswd.addEventListener("input", comparePasswd);
  gRepeatPasswd.addEventListener("input", comparePasswd);
}

async function onAccept() {
  const enigmailSvc = EnigmailCore.getService();
  if (!enigmailSvc)
    return;

  const keyMgmt = EnigmailCryptoAPI().getKeyManagement();

  let currPasswd = document.getElementById("currPasswd").value;
  if (gNewPasswd.value.length == 0 && gRepeatPasswd.value.length == 0) {
    if (!EnigmailDialog.confirmDlg(window, EnigmailLocale.getString("changePasswdDlg.removePassphrase"), EnigmailLocale.getString("changePasswdDlg.removePassButton"))) {
      return;
    }
  }

  let r = await keyMgmt.performChangePassphrase(window.arguments[0].keyId, currPasswd, gNewPasswd.value);

  if (r.returnCode !== 0) {
    EnigmailDialog.alert(window, EnigmailLocale.getString("changePassFailed") + "\n\n" + r.errorMsg);
  }
  else
    window.close();
}

function comparePasswd() {
  if (gNewPasswd.value !== gRepeatPasswd.value) {
    gAcceptButton.setAttribute("disabled", "true");
    gPasswdDontMatch.removeAttribute("hidden");
  }
  else {
    gAcceptButton.removeAttribute("disabled");
    gPasswdDontMatch.setAttribute("hidden", "true");
  }

  if (gNewPasswd.value.length > 0) {
    gQualityMeter.setAttribute("value", EnigmailPasswordCheck.checkQuality(gNewPasswd.value).complexity);
  }
  else
    gQualityMeter.setAttribute("value", 0);
}

document.addEventListener("dialogaccept", function(event) {
  onAccept();
  event.preventDefault(); // Don't close the dialog - it's done in onAccept().
});
