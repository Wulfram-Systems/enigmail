/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// Uses: chrome://enigmail/content/ui/enigmailCommon.js

/* global EnigmailLog: false, EnigmailLocale: false, EnigmailPrefs: false, EnigmailDialog: false */

// from enigmailCommon.js:
/* global EnigInitCommon: false, EnigGetPref: false, EnigSetPref: false, GetEnigmailSvc: false */
/* global gEnigmailSvc: true, EnigGetString: false, EnigError: false, EnigGetVersion: false */
/* global EnigGetDefaultPref: false, EnigConvertToUnicode: false, EnigCollapseAdvanced: false, EnigGetOS: false */
/* global EnigGetFilePath: false, EnigAlertPref: false, EnigFilePicker: false */
/* global EnigDisplayRadioPref: false, EnigSavePrefs: false, EnigConvertFromUnicode: false */
/* global ENIG_C: false, ENIG_I: false, ENIG_ENIGMAIL_CONTRACTID: false */
/* global gEnigAcceptedKeys: false, gEnigAutoSendEncrypted: true, gEnigConfirmBeforeSending: false */


"use strict";

var Cu = Components.utils;
var Cc = Components.classes;
var Ci = Components.interfaces;

var EnigmailConfigBackup = ChromeUtils.import("chrome://enigmail/content/modules/configBackup.jsm").EnigmailConfigBackup;
var EnigmailWindows = ChromeUtils.import("chrome://enigmail/content/modules/windows.jsm").EnigmailWindows;
var EnigmailLazy = ChromeUtils.import("chrome://enigmail/content/modules/lazy.jsm").EnigmailLazy;
var EnigmailCryptoAPI = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI.jsm").EnigmailCryptoAPI;
var EnigmailTimer = ChromeUtils.import("chrome://enigmail/content/modules/timer.jsm").EnigmailTimer;

const getCore = EnigmailLazy.loader("enigmail/core.jsm", "EnigmailCore");

// Initialize enigmailCommon
EnigInitCommon("pref-enigmail");

var gMimePartsElement, gMimePartsValue, gAdvancedMode, gAcceptedKeyTypes, gAutoSendEncrypted,
  gConfirmBeforeSending, gEncryptionModel;

// saved old manual preferences to switch back
// to them if we temporarily enabled convenient encryption
// (not persistent)
var gSavedManualPrefKeepSettingsForReply = true;
var gSavedManualPrefAcceptedKeys = 1;
var gSavedManualPrefAutoSendEncrypted = 1;
var gSavedManualPrefConfirmBeforeSending = 0;
var gOrigMaxIdle = "-";

function displayPrefs(showDefault, showPrefs, setPrefs) {
  EnigmailLog.DEBUG("pref-enigmail.js displayPrefs\n");

  var s = gEnigmailSvc;

  var obj = {};
  var prefList = EnigmailPrefs.getPrefBranch().getChildList("", obj);

  for (var prefItem in prefList) {
    var prefName = prefList[prefItem];
    var prefElement = document.getElementById("enigmail_" + prefName);

    if (prefElement) {
      var prefType = EnigmailPrefs.getPrefBranch().getPrefType(prefName);
      var prefValue;
      if (showDefault) {
        prefValue = EnigGetDefaultPref(prefName);
      }
      else {
        prefValue = EnigGetPref(prefName);
      }

      EnigmailLog.DEBUG("pref-enigmail.js displayPrefs: " + prefName + "=" + prefValue + "\n");

      switch (prefType) {
        case EnigmailPrefs.getPrefBranch().PREF_BOOL:
          if (showPrefs) {
            if (prefElement.getAttribute("invert") == "true") {
              prefValue = !prefValue;
            }
            if (prefValue) {
              prefElement.setAttribute("checked", "true");
            }
            else {
              prefElement.removeAttribute("checked");
            }
          }
          if (setPrefs) {
            if (prefElement.getAttribute("invert") == "true") {
              if (prefElement.checked) {
                EnigSetPref(prefName, false);
              }
              else {
                EnigSetPref(prefName, true);
              }
            }
            else {
              if (prefElement.checked) {
                EnigSetPref(prefName, true);
              }
              else {
                EnigSetPref(prefName, false);
              }
            }
          }
          break;

        case EnigmailPrefs.getPrefBranch().PREF_INT:
          if (showPrefs) {
            prefElement.value = prefValue;
          }
          if (setPrefs) {
            try {
              EnigSetPref(prefName, 0 + prefElement.value);
            }
            catch (ex) {}
          }
          break;

        case EnigmailPrefs.getPrefBranch().PREF_STRING:
          if (showPrefs) {
            prefElement.value = prefValue;
          }
          if (setPrefs) {
            EnigSetPref(prefName, prefElement.value);
          }
          break;

        default:
          EnigmailLog.DEBUG("pref-enigmail.js displayPrefs: " + prefName + " does not have a type?!\n");
      }
    }
  }
}

async function prefOnLoad() {
  EnigmailLog.DEBUG("pref-enigmail.js: prefOnLoad()\n");
  const cApi = EnigmailCryptoAPI();

  document.getElementById("acSetupMessageDesc").innerHTML = EnigmailLocale.getString("acSetupMessage.desc");

  GetEnigmailSvc();
  displayPrefs(false, true, false);
  displayRequireRestart();

  var maxIdle = -1;
  if (isGnuPGBackend()) {
    if (!gEnigmailSvc) {
      maxIdle = EnigmailPrefs.getPref("maxIdleMinutes");
    }
    else {
      maxIdle = await cApi.getMaxIdlePref(window);
    }
    document.getElementById("maxIdleMinutes").value = maxIdle;

    document.getElementById("idleBox").removeAttribute("collapsed");
  }
  else {
    document.getElementById("acceptedKeysBox").setAttribute("collapsed", "true");
    document.getElementById("weakKeysBox").removeAttribute("collapsed");    
  }

  gOrigMaxIdle = String(maxIdle);
  gAdvancedMode = EnigGetPref("advancedUser");

  if (window.arguments) {
    // if (!window.arguments[0].showBasic) {
    //   // hide basic tab
    //   document.getElementById("basic").setAttribute("collapsed", true);
    //   document.getElementById("basicTab").setAttribute("collapsed", true);
    //   selectPrefTabPanel("sendingTab");
    // }
    // else {
    EnigCollapseAdvanced(document.getElementById("prefTabBox"), "collapsed", null);
    //EnigCollapseAdvanced(document.getElementById("enigPrefTabPanel"), "hidden", null);
    enigShowUserModeButtons(gAdvancedMode);
    // }

    if ((typeof window.arguments[0].selectTab) == "string") {
      selectPrefTabPanel(window.arguments[0].selectTab);
    }

  }
  else {
    enigShowUserModeButtons(gAdvancedMode);
  }

  if ((!window.arguments) || (window.arguments[0].clientType != "seamonkey")) {
    EnigCollapseAdvanced(document.getElementById("prefTabBox"), "collapsed", null);
    //EnigCollapseAdvanced(document.getElementById("enigPrefTabPanel"), "hidden", null);
  }

  document.getElementById("enigmail_protectHeaders").checked = (EnigGetPref("protectedHeaders") === 2);

  // init "saved manual preferences" with current settings:
  gSavedManualPrefKeepSettingsForReply = EnigGetPref("keepSettingsForReply");
  gSavedManualPrefAcceptedKeys = EnigGetPref("acceptedKeys");
  gSavedManualPrefAutoSendEncrypted = EnigGetPref("autoSendEncrypted");
  gSavedManualPrefConfirmBeforeSending = EnigGetPref("confirmBeforeSending");
  gEncryptionModel = EnigGetPref("encryptionModel");
  if (gEncryptionModel === 0) { // convenient encryption
    resetSendingPrefsConvenient();
  }
  else {
    resetSendingPrefsManually();
  }

  gMimePartsElement = document.getElementById("mime_parts_on_demand");

  try {
    gMimePartsValue = EnigmailPrefs.getPrefRoot().getBoolPref("mail.server.default.mime_parts_on_demand");
  }
  catch (ex) {
    gMimePartsValue = true;
  }

  if (gMimePartsValue) {
    gMimePartsElement.setAttribute("checked", "true");
  }
  else {
    gMimePartsElement.removeAttribute("checked");
  }

  var testEmailElement = document.getElementById("enigmail_test_email");
  var userIdValue = EnigGetPref("userIdValue");

  if (isGnuPGBackend()) enigDetermineGpgPath();

  if (testEmailElement && userIdValue) {
    testEmailElement.value = userIdValue;
  }

  EnigmailTimer.setTimeout(resizeDlg, 1);
}

function resizeDlg() {
  window.resizeBy(0,0);
}

function enigDetermineGpgPath() {
  if (!gEnigmailSvc) {
    try {
      gEnigmailSvc = getCore().createInstance();
      if (!gEnigmailSvc.initialized) {
        // attempt to initialize Enigmail
        gEnigmailSvc.initialize(window, EnigGetVersion());
      }
    }
    catch (ex) {}
  }
}

function selectPrefTabPanel(panelName) {
  var prefTabs = document.getElementById("prefTabs");
  var selectTab = document.getElementById(panelName);
  prefTabs.selectedTab = selectTab;
}

function resetPrefs() {
  EnigmailLog.DEBUG("pref-enigmail.js: resetPrefs\n");

  displayPrefs(true, true, false);

  EnigSetPref("configuredVersion", EnigGetVersion());

  // init "saved manual preferences" with current settings:
  gSavedManualPrefKeepSettingsForReply = EnigGetPref("keepSettingsForReply");
  gSavedManualPrefAcceptedKeys = EnigGetPref("acceptedKeys");
  gSavedManualPrefAutoSendEncrypted = EnigGetPref("autoSendEncrypted");
  gSavedManualPrefConfirmBeforeSending = EnigGetPref("confirmBeforeSending");
  // and process encryption model:
  gEncryptionModel = EnigGetPref("encryptionModel");
  if (gEncryptionModel === 0) { // convenient encryption
    resetSendingPrefsConvenient();
  }
  else {
    resetSendingPrefsManually();
  }
}

// Serializes various Enigmail settings into a separate file.
function backupPrefs() {

  window.open("chrome://enigmail/content/ui/exportSettingsWizard.xul",
    "", "chrome,centerscreen,resizable,modal");
}


function restorePrefs() {
  EnigmailWindows.openImportSettings(window);
}

function disableManually(disable) {
  var elems = [
    "enigmail_keepSettingsForReply",
    "acceptedKeysValid",
    "acceptedKeysAll",
    "autoSendEncryptedNever",
    "autoSendEncryptedIfKeys",
    "confirmBeforeSendingNever",
    "confirmBeforeSendingAlways",
    "confirmBeforeSendingIfEncrypted",
    "confirmBeforeSendingIfNotEncrypted",
    "confirmBeforeSendingIfRules"
  ];
  var elem;
  for (var i = 0; i < elems.length; ++i) {
    elem = document.getElementById(elems[i]);
    if (disable) {
      elem.setAttribute("disabled", "true");
    }
    else {
      elem.removeAttribute("disabled");
    }
  }
}

function updateSendingPrefs() {
  EnigDisplayRadioPref("acceptedKeys", EnigGetPref("acceptedKeys"),
    gEnigAcceptedKeys);
  EnigDisplayRadioPref("autoSendEncrypted", EnigGetPref("autoSendEncrypted"),
    gEnigAutoSendEncrypted);
  EnigDisplayRadioPref("confirmBeforeSending", EnigGetPref("confirmBeforeSending"),
    gEnigConfirmBeforeSending);
  gEncryptionModel = EnigGetPref("encryptionModel");
  disableManually(gEncryptionModel === 0);
  displayPrefs(false, true, false);
}

function resetSendingPrefsConvenient() {
  EnigmailLog.DEBUG("pref-enigmail.js: resetSendingPrefsConvenient()\n");

  // save current manual preferences to be able to switch back to them:
  gSavedManualPrefKeepSettingsForReply = document.getElementById("enigmail_keepSettingsForReply").checked;
  gSavedManualPrefAcceptedKeys = document.getElementById("enigmail_acceptedKeys").value;
  gSavedManualPrefAutoSendEncrypted = document.getElementById("enigmail_autoSendEncrypted").value;
  gSavedManualPrefConfirmBeforeSending = document.getElementById("enigmail_confirmBeforeSending").value;

  // switch encryption model:
  gEncryptionModel = 0; // convenient encryption settings
  EnigSetPref("encryptionModel", gEncryptionModel);

  // update GUI elements and corresponding setting variables:
  var keepSettingsForReply = true; // reply encrypted on encrypted emails
  gAcceptedKeyTypes = 1; // all keys accepted
  gAutoSendEncrypted = 1; // auto.send-encrypted if accepted keys exist
  gConfirmBeforeSending = 0; // never confirm before sending
  EnigSetPref("keepSettingsForReply", keepSettingsForReply);
  EnigSetPref("acceptedKeys", gAcceptedKeyTypes);
  EnigSetPref("autoSendEncrypted", gAutoSendEncrypted);
  EnigSetPref("confirmBeforeSending", gConfirmBeforeSending);

  updateSendingPrefs();
}

function resetSendingPrefsManually() {
  EnigmailLog.DEBUG("pref-enigmail.js: resetSendingPrefsManually()\n");

  // switch encryption model:
  gEncryptionModel = 1; // manual encryption settings
  EnigSetPref("encryptionModel", gEncryptionModel);

  // update GUI elements and corresponding setting variables
  // with saved old manual preferences:
  var keepSettingsForReply = gSavedManualPrefKeepSettingsForReply;
  gAcceptedKeyTypes = gSavedManualPrefAcceptedKeys;
  gAutoSendEncrypted = gSavedManualPrefAutoSendEncrypted;
  gConfirmBeforeSending = gSavedManualPrefConfirmBeforeSending;
  EnigSetPref("keepSettingsForReply", keepSettingsForReply);
  EnigSetPref("acceptedKeys", gAcceptedKeyTypes);
  EnigSetPref("autoSendEncrypted", gAutoSendEncrypted);
  EnigSetPref("confirmBeforeSending", gConfirmBeforeSending);

  updateSendingPrefs();
}

function resetRememberedValues() {
  EnigmailLog.DEBUG("pref-enigmail.js: resetRememberedValues\n");
  var prefs = ["confirmBeforeSend",
    "displaySignWarn",
    "encryptAttachmentsSkipDlg",
    "initAlert",
    "mimePreferPgp",
    "quotedPrintableWarn",
    "warnOnRulesConflict",
    "warnGpgAgentAndIdleTime",
    "warnClearPassphrase",
    "warnOnSendingNewsgroups",
    "warnDownloadContactKeys",
    "warnRefreshAll",
    "warnDeprecatedGnuPG",
    "warnOnMissingOwnerTrust"
  ];

  for (var j = 0; j < prefs.length; j++) {
    EnigSetPref(prefs[j], EnigGetDefaultPref(prefs[j]));
  }
  EnigmailDialog.info(window, EnigGetString("warningsAreReset"));
}

async function prefOnAccept() {

  EnigmailLog.DEBUG("pref-enigmail.js: prefOnAccept\n");
  const cApi = EnigmailCryptoAPI();

  let defaultKeySrv = document.getElementById("enigmail_defaultKeyserver").value;

  if (defaultKeySrv.search(/.[ ,;\t]+./) >= 0) {
    EnigmailDialog.info(window, EnigGetString("prefEnigmail.oneKeyserverOnly2"));
    return false;
  }

  displayPrefs(false, false, true);

  if (gMimePartsElement &&
    (gMimePartsElement.checked != gMimePartsValue)) {

    EnigmailPrefs.getPrefRoot().setBoolPref("mail.server.default.mime_parts_on_demand", (gMimePartsElement.checked ? true : false));
  }

  EnigSetPref("configuredVersion", EnigGetVersion());
  EnigSetPref("advancedUser", gAdvancedMode);
  let maxIdle = document.getElementById("maxIdleMinutes").value;

  if (gOrigMaxIdle != maxIdle) {
    // only change setting in gpg-agent if value has actually changed
    // because gpg-agent deletes cache upon changing timeout settings
    if (isGnuPGBackend()) await cApi.setMaxIdlePref(maxIdle);
  }

  let protectionUndecided = (EnigGetPref("protectedHeaders") === 1);
  let chk = document.getElementById("enigmail_protectHeaders").checked;

  if (protectionUndecided && chk) {
    EnigSetPref("protectedHeaders", 2);
  }
  else if (!protectionUndecided) {
    EnigSetPref("protectedHeaders", chk ? 2 : 0);
  }

  EnigSavePrefs();

  if (isRestartRequired()) {
    if (EnigmailDialog.confirmDlg(window, EnigmailLocale.getString("pref.dialogRestartApp.desc"),
        EnigmailLocale.getString("dlg.button.restartNow"), EnigmailLocale.getString("dlg.button.restartLater"))) {
      restartApplication();
    }
  }

  if (!isGnuPGBackend()) {
    const pgpjs_crypto = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-crypto-main.jsm").pgpjs_crypto;
    await pgpjs_crypto.loadConfig();
  }

  return true;
}

function enigActivateDependent(obj, dependentIds) {
  var idList = dependentIds.split(/ /);
  var depId;

  for (depId in idList) {
    if (obj.checked) {
      document.getElementById(idList[depId]).removeAttribute("disabled");
    }
    else {
      document.getElementById(idList[depId]).setAttribute("disabled", "true");
    }
  }
  return true;
}

function enigShowUserModeButtons(expertUser) {
  var advUserButton = document.getElementById("enigmail_advancedUser");
  var basicUserButton = document.getElementById("enigmail_basicUser");
  if (!expertUser) {
    basicUserButton.setAttribute("hidden", true);
    advUserButton.removeAttribute("hidden");
  }
  else {
    advUserButton.setAttribute("hidden", true);
    basicUserButton.removeAttribute("hidden");
  }
}

function enigSwitchAdvancedMode(expertUser) {

  var origPref = EnigGetPref("advancedUser");
  enigShowUserModeButtons(expertUser);
  gAdvancedMode = expertUser;

  if (expertUser) {
    EnigSetPref("advancedUser", true);
  }
  else {
    EnigSetPref("advancedUser", false);
  }

  var prefTabBox = document.getElementById("prefTabBox");
  EnigCollapseAdvanced(prefTabBox, "collapsed", null);
  EnigSetPref("advancedUser", origPref);
}

function isRestartRequired() {
  let currValue = isGnuPGBackend() ? "1" : "2";

  return (document.getElementById("enigmail_cryptoAPI").value !== currValue);
}

function displayRequireRestart() {
  if (isRestartRequired()) {
    document.getElementById("requireRestart").removeAttribute("hidden");
  }
  else {
    document.getElementById("requireRestart").setAttribute("hidden", "true");
  }
}

function onCryptoEngineChanged(newCryptoEngine) {
  displayRequireRestart();

  switch (newCryptoEngine) {
    case "gnupg":
      document.getElementById("idleBox").removeAttribute("collapsed");
      document.getElementById("weakKeysBox").setAttribute("collapsed", "true");
      break;
    case "openpgpjs":
      document.getElementById("idleBox").setAttribute("collapsed", "true");
      document.getElementById("weakKeysBox").removeAttribute("collapsed");
      break;
  }
}

function enigAlertAskNever() {
  EnigmailDialog.info(window, EnigGetString("prefs.warnAskNever"));
}

function activateRulesButton(radioListObj, buttonId) {
  switch (radioListObj.value) {
    case "3":
    case "4":
      document.getElementById(buttonId).setAttribute("disabled", "true");
      break;
    default:
      document.getElementById(buttonId).removeAttribute("disabled");
  }
}

function handleClick(event) {
  if (event.target.hasAttribute("href")) {
    EnigmailWindows.openMailTab(event.target.getAttribute("href"));
  }
}

function isGnuPGBackend() {
  const cApi = EnigmailCryptoAPI();

  return (cApi.apiName === "GpgME");
}


function restartApplication() {
  let oAppStartup = Cc["@mozilla.org/toolkit/app-startup;1"].getService(Ci.nsIAppStartup);
  if (!oAppStartup.eRestart) throw ("Restart is not supported");
  oAppStartup.quit(oAppStartup.eAttemptQuit | oAppStartup.eRestart);
}


function initiateAcKeyTransfer() {
  EnigmailWindows.inititateAcSetupMessage();
}


document.addEventListener("dialogaccept", function(event) {
  if (!prefOnAccept())
    event.preventDefault();
});
