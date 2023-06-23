/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

"use strict";

var Cu = Components.utils;
var Cc = Components.classes;
var Ci = Components.interfaces;

var EnigmailAutoSetup = ChromeUtils.import("chrome://enigmail/content/modules/autoSetup.jsm").EnigmailAutoSetup;
var EnigmailConstants = ChromeUtils.import("chrome://enigmail/content/modules/constants.jsm").EnigmailConstants;
var EnigmailApp = ChromeUtils.import("chrome://enigmail/content/modules/app.jsm").EnigmailApp;
var EnigmailPrefs = ChromeUtils.import("chrome://enigmail/content/modules/prefs.jsm").EnigmailPrefs;
var EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
var EnigmailLocale = ChromeUtils.import("chrome://enigmail/content/modules/locale.jsm").EnigmailLocale;
var EnigmailTimer = ChromeUtils.import("chrome://enigmail/content/modules/timer.jsm").EnigmailTimer;
var EnigmailLazy = ChromeUtils.import("chrome://enigmail/content/modules/lazy.jsm").EnigmailLazy;
var EnigmailOS = ChromeUtils.import("chrome://enigmail/content/modules/os.jsm").EnigmailOS;
var EnigmailDialog = ChromeUtils.import("chrome://enigmail/content/modules/dialog.jsm").EnigmailDialog;
var EnigmailFiles = ChromeUtils.import("chrome://enigmail/content/modules/files.jsm").EnigmailFiles;
var InstallGnuPG = ChromeUtils.import("chrome://enigmail/content/modules/installGnuPG.jsm").InstallGnuPG;
var EnigmailConfigBackup = ChromeUtils.import("chrome://enigmail/content/modules/configBackup.jsm").EnigmailConfigBackup;
var EnigmailKeyRing = ChromeUtils.import("chrome://enigmail/content/modules/keyRing.jsm").EnigmailKeyRing;
var EnigmailWindows = ChromeUtils.import("chrome://enigmail/content/modules/windows.jsm").EnigmailWindows;

const getCore = EnigmailLazy.loader("enigmail/core.jsm", "EnigmailCore");

/* Imported from commonWorkflows.js: */
/* global EnigmailCommon_importKeysFromFile: false */

const FINAL_ACTION_DONOTHING = 0;
const FINAL_ACTION_CREATEKEYS = 2;

var gEnigmailSvc = null;
var gResolveInstall = null;
var gDownoadObj = null;
var gFoundSetupType = {
  value: -1
};
var gSecretKeys = [];
var gFinalAction = FINAL_ACTION_DONOTHING;

function onLoad() {
  EnigmailLog.DEBUG(`setupWizard2.js: onLoad()\n`);
  let dlg = document.getElementById("setupWizardDlg");
  dlg.getButton("accept").setAttribute("disabled", "true");

  document.getElementById("foundAcSetupMessage").innerHTML = EnigmailLocale.getString("setupWizard.foundAcSetupMessage");
  document.getElementById("foundAcNoSetupMsg").innerHTML = EnigmailLocale.getString("setupWizard.foundAcNoSetupMsg");
  document.getElementById("setupComplete").innerHTML = EnigmailLocale.getString("setupWizard.setupComplete");

  // let the dialog be loaded asynchronously such that we can disply the dialog
  // before we start working on it.
  EnigmailTimer.setTimeout(onLoadAsync, 1);

}

async function onLoadAsync() {
  document.getElementById("searchingGnuPG").style.visibility = "visible";
  checkGnupgInstallation();
  document.getElementById("determineInstall").style.visibility = "visible";
  gSecretKeys = EnigmailKeyRing.getAllSecretKeys(true);

  try {
    gFoundSetupType = await EnigmailAutoSetup.getDeterminedSetupType();
    EnigmailLog.DEBUG(`setupWizard2.js: onLoadAsync: got setupType ${gFoundSetupType.value}\n`);
  }
  catch (x) {}

  displayExistingEmails();
}

/**
 * Main function to display the found case matching the user's setup
 */
function displayExistingEmails() {
  EnigmailLog.DEBUG(`setupWizard2.js: displayExistingEmails(): found setup type ${gFoundSetupType.value}\n`);
  let prevInstallElem = "previousInstall_none";
  let unhideButtons = [];

  if (gSecretKeys.length > 0) {
    // secret keys are already available
    EnigmailLog.DEBUG(`setupWizard2.js: displayExistingEmails: found existing keys\n`);
    prevInstallElem = "previousInstall_keysAvailable";
  }
  else {
    switch (gFoundSetupType.value) {
      case EnigmailConstants.AUTOSETUP_AC_SETUP_MSG:
        // found Autocrypt Setup Message
        prevInstallElem = "previousInstall_acSetup";
        break;
      case EnigmailConstants.AUTOSETUP_AC_HEADER:
        // found Autocrypt messages
        prevInstallElem = "previousInstall_ac";
        unhideButtons = ["btnRescanInbox", "btnImportSettings"];
        break;
      case EnigmailConstants.AUTOSETUP_ENCRYPTED_MSG:
        // encrypted messages without Autocrypt found
        prevInstallElem = "previousInstall_encrypted";
        unhideButtons = ["btnImportKeys"];
        enableDoneButton();
        break;
      default:
        // no encrypted messages found
        enableDoneButton();
        gFinalAction = FINAL_ACTION_CREATEKEYS;
    }
  }
  document.getElementById("determineInstall").style.visibility = "collapse";
  document.getElementById(prevInstallElem).style.visibility = "visible";

  for (let e of unhideButtons) {
    document.getElementById(e).style.visibility = "visible";
  }
}

/**
 * Check if GnuPG is available and set dialog parts accordingly
 */
function checkGnupgInstallation() {
  let cryptoEngine = EnigmailPrefs.getPref("cryptoAPI");
  let uiItem = cryptoEngine === 1 ? "usingGnuPG" : "usingOpenpgpJS";
  document.getElementById(uiItem).style.display = "initial";
}


/**
 * Import Autocrypt Setup Messages
 */
function importAcSetup() {
  let btnInitiateAcSetup = document.getElementById("btnInitiateAcSetup");
  btnInitiateAcSetup.setAttribute("disabled", true);
  EnigmailAutoSetup.performAutocryptSetup(gFoundSetupType).then(r => {
    if (r > 0) {
      document.getElementById("previousInstall_none").style.visibility = "visible";
      enableDoneButton();
    }
  });
}

/**
 * Actively re-scan the inbox to find (for example) a new Autocrypt Setup Message
 */
function rescanInbox() {
  EnigmailAutoSetup.determinePreviousInstallType().then(r => {
    EnigmailLog.DEBUG(`setupWizard2.js: onLoad: got rescanInbox ${r.value}\n`);
    gFoundSetupType = r;

    for (let i of ["previousInstall_ac", "btnRescanInbox", "btnImportSettings"]) {
      document.getElementById(i).style.visibility = "collapse";
    }

    displayExistingEmails();
  }).catch(x => {
    for (let i of ["previousInstall_ac", "btnRescanInbox", "btnImportSettings"]) {
      document.getElementById(i).style.visibility = "collapse";
    }
    displayExistingEmails();
  });
}

/**
 * open the "Restore Settings and Keys" wizard
 */
function importSettings() {
  EnigmailWindows.openImportSettings(window);
}


function enableDoneButton() {
  let dlg = document.getElementById("setupWizardDlg");
  dlg.getButton("cancel").setAttribute("collapsed", "true");
  dlg.getButton("accept").removeAttribute("disabled");
}


function onCancel() {
  if (gDownoadObj) {
    gDownoadObj.abort();
    gDownoadObj = null;
  }

  return true;
}


function onAccept() {
  if (gFinalAction === FINAL_ACTION_CREATEKEYS) {
    EnigmailAutoSetup.createKeyForAllAccounts();
  }
  return true;
}

function importKeysFromFile() {
  EnigmailCommon_importKeysFromFile();
  applyExistingKeys();
}

function applyExistingKeys() {
  EnigmailAutoSetup.applyExistingKeys();

  document.getElementById("btnApplyExistingKeys").setAttribute("disabled", "true");
  document.getElementById("applyExistingKeysOK").style.visibility = "visible";
  document.getElementById("previousInstall_none").style.visibility = "visible";
  enableDoneButton();
}

function handleClick(event) {
  if (event.target.hasAttribute("href")) {
    let target = event.target;
    event.stopPropagation();
    EnigmailWindows.openMailTab(target.getAttribute("href"));
  }
}


document.addEventListener("dialogaccept", function(event) {
  if (!onAccept())
    event.preventDefault(); // Prevent the dialog closing.
});

document.addEventListener("dialogcancel", function(event) {
  if (!onCancel())
    event.preventDefault(); // Prevent the dialog closing.
});
