/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

"use strict";

var EXPORTED_SYMBOLS = ["EnigmailConfigure"];

const EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
const EnigmailPrefs = ChromeUtils.import("chrome://enigmail/content/modules/prefs.jsm").EnigmailPrefs;
const EnigmailTimer = ChromeUtils.import("chrome://enigmail/content/modules/timer.jsm").EnigmailTimer;
const EnigmailApp = ChromeUtils.import("chrome://enigmail/content/modules/app.jsm").EnigmailApp;
const EnigmailLocale = ChromeUtils.import("chrome://enigmail/content/modules/locale.jsm").EnigmailLocale;
const EnigmailDialog = ChromeUtils.import("chrome://enigmail/content/modules/dialog.jsm").EnigmailDialog;
const EnigmailWindows = ChromeUtils.import("chrome://enigmail/content/modules/windows.jsm").EnigmailWindows;
const EnigmailConstants = ChromeUtils.import("chrome://enigmail/content/modules/constants.jsm").EnigmailConstants;
const EnigmailCore = ChromeUtils.import("chrome://enigmail/content/modules/core.jsm").EnigmailCore;
const EnigmailStdlib = ChromeUtils.import("chrome://enigmail/content/modules/stdlib.jsm").EnigmailStdlib;
const EnigmailLazy = ChromeUtils.import("chrome://enigmail/content/modules/lazy.jsm").EnigmailLazy;
const EnigmailAutoSetup = ChromeUtils.import("chrome://enigmail/content/modules/autoSetup.jsm").EnigmailAutoSetup;
const EnigmailSqliteDb = ChromeUtils.import("chrome://enigmail/content/modules/sqliteDb.jsm").EnigmailSqliteDb;
const getEnigmailCryptoAPI = EnigmailLazy.loader("enigmail/cryptoAPI.jsm", "EnigmailCryptoAPI");

// Interfaces
const nsIFolderLookupService = Ci.nsIFolderLookupService;
const nsIMsgAccountManager = Ci.nsIMsgAccountManager;

/**
 * Upgrade sending prefs
 * (v1.6.x -> v1.7 )
 */
function upgradePrefsSending() {
  EnigmailLog.DEBUG("enigmailCommon.jsm: upgradePrefsSending()\n");

  var cbs = EnigmailPrefs.getPref("confirmBeforeSend");
  var ats = EnigmailPrefs.getPref("alwaysTrustSend");
  var ksfr = EnigmailPrefs.getPref("keepSettingsForReply");
  EnigmailLog.DEBUG("enigmailCommon.jsm: upgradePrefsSending cbs=" + cbs + " ats=" + ats + " ksfr=" + ksfr + "\n");

  // Upgrade confirmBeforeSend (bool) to confirmBeforeSending (int)
  switch (cbs) {
    case false:
      EnigmailPrefs.setPref("confirmBeforeSending", 0); // never
      break;
    case true:
      EnigmailPrefs.setPref("confirmBeforeSending", 1); // always
      break;
  }

  // Upgrade alwaysTrustSend (bool)   to acceptedKeys (int)
  switch (ats) {
    case false:
      EnigmailPrefs.setPref("acceptedKeys", 0); // valid
      break;
    case true:
      EnigmailPrefs.setPref("acceptedKeys", 1); // all
      break;
  }

  // if all settings are default settings, use convenient encryption
  if (cbs === false && ats === true && ksfr === true) {
    EnigmailPrefs.setPref("encryptionModel", 0); // convenient
    EnigmailLog.DEBUG("enigmailCommon.jsm: upgradePrefsSending() encryptionModel=0 (convenient)\n");
  }
  else {
    EnigmailPrefs.setPref("encryptionModel", 1); // manually
    EnigmailLog.DEBUG("enigmailCommon.jsm: upgradePrefsSending() encryptionModel=1 (manually)\n");
  }

  // clear old prefs
  EnigmailPrefs.getPrefBranch().clearUserPref("confirmBeforeSend");
  EnigmailPrefs.getPrefBranch().clearUserPref("alwaysTrustSend");
}

/**
 * Replace short key IDs with FPR in identity settings
 * (v1.9 -> v2.0)
 */
function replaceKeyIdWithFpr() {
  try {
    const GetKeyRing = EnigmailLazy.loader("enigmail/keyRing.jsm", "EnigmailKeyRing");

    var accountManager = Cc["@mozilla.org/messenger/account-manager;1"].getService(Ci.nsIMsgAccountManager);
    for (var i = 0; i < accountManager.allIdentities.length; i++) {
      var id = accountManager.allIdentities.queryElementAt(i, Ci.nsIMsgIdentity);
      if (id.getBoolAttribute("enablePgp")) {
        let keyId = id.getCharAttribute("pgpkeyId");

        if (keyId.search(/^(0x)?[a-fA-F0-9]{8}$/) === 0) {

          EnigmailCore.getService();

          let k = GetKeyRing().getKeyById(keyId);
          if (k) {
            id.setCharAttribute("pgpkeyId", "0x" + k.fpr);
          }
          else {
            id.setCharAttribute("pgpkeyId", "");
          }
        }
      }
    }
  }
  catch (ex) {
    EnigmailDialog.alert("config upgrade: error" + ex.toString());
  }
}


/**
 * set the Autocrypt prefer-encrypt option to "mutual" for all existing
 * accounts
 */
function setAutocryptForOldAccounts() {
  try {
    let accountManager = Cc["@mozilla.org/messenger/account-manager;1"].getService(Ci.nsIMsgAccountManager);

    for (let acct = 0; acct < accountManager.accounts.length; acct++) {
      let ac = accountManager.accounts.queryElementAt(acct, Ci.nsIMsgAccount);
      if (ac.incomingServer.type.search(/(pop3|imap|movemail)/) >= 0) {
        ac.incomingServer.setIntValue("acPreferEncrypt", 1);
      }
    }
  }
  catch (ex) {}
}

function setDefaultKeyServer() {
  EnigmailLog.DEBUG("configure.jsm: setDefaultKeyServer()\n");

  let ks = EnigmailPrefs.getPref("keyserver");

  if (ks.search(/^ldaps?:\/\//) < 0) {
    ks = "vks://keys.openpgp.org, " + ks;
  }

  ks = ks.replace(/hkps:\/\/keys.openpgp.org/g, "vks://keys.openpgp.org");
  EnigmailPrefs.setPref("keyserver", ks);
}

function setGnuPGDefault() {
  EnigmailLog.DEBUG("configure.jsm: setGnuPGDefault()\n");
  // set the cryptoAPI for all existing users to "GnuPG"

  EnigmailPrefs.setPref("cryptoAPI", 1);
}


function displayUpgradeInfo() {
  EnigmailLog.DEBUG("configure.jsm: displayUpgradeInfo()\n");

  const EnigmailCryptoAPI = getEnigmailCryptoAPI();
  const cApi = EnigmailCryptoAPI();

  if (cApi.api_name === "GpgME") {
    EnigmailTimer.setTimeout(() => {
      EnigmailWindows.openMailTab("chrome://enigmail/content/ui/upgradeInfo.html");
    }, 10000);
  }
}


var EnigmailConfigure = {
  /**
   * configureEnigmail: main function for configuring Enigmail after startup
   *
   * @param {Object} esvc: Enigmail service object
   *
   */
  configureEnigmail: function(esvc) {
    EnigmailLog.DEBUG("configure.jsm: configureEnigmail()\n");

    let oldVer = EnigmailPrefs.getPref("configuredVersion");

    let vc = Cc["@mozilla.org/xpcom/version-comparator;1"].getService(Ci.nsIVersionComparator);

    if (oldVer === "") {
      return;
    }
    else {
      if (vc.compare(oldVer, "1.7a1pre") < 0) {
        // 1: rules only
        //     => assignKeysByRules true; rest false
        // 2: rules & email addresses (normal)
        //     => assignKeysByRules/assignKeysByEmailAddr/assignKeysManuallyIfMissing true
        // 3: email address only (no rules)
        //     => assignKeysByEmailAddr/assignKeysManuallyIfMissing true
        // 4: manually (always prompt, no rules)
        //     => assignKeysManuallyAlways true
        // 5: no rules, no key selection
        //     => assignKeysByRules/assignKeysByEmailAddr true

        upgradePrefsSending();
      }

      if (vc.compare(oldVer, "2.0a1pre") < 0) {
        this.upgradeTo20(esvc);
      }
      if (vc.compare(oldVer, "2.0.1a2pre") < 0) {
        this.upgradeTo201();
      }
      if (vc.compare(oldVer, "2.1b2") < 0) {
        this.upgradeTo21();
      }
      if (vc.compare(oldVer, "3.0a1") < 0) {
        this.upgradeTo30();
      }
      if (vc.compare(oldVer, "3.1") < 0) {
        this.upgradeTo31(esvc);
      }
    }

    EnigmailPrefs.setPref("configuredVersion", EnigmailApp.getVersion());
    EnigmailPrefs.savePrefs();
  },

  /**
   * Set up Enigmail after it was installed for the 1st time
   *
   * @param {nsIWindow} win: The parent window. Null if no parent window available
   * @param {Object}    esvc: Enigmail service object
   *
   * @return {Promise<null>}
   */
  setupEnigmail: async function(win, esvc) {
    EnigmailLog.DEBUG("configure.jsm: setupEnigmail()\n");

    if (!EnigmailStdlib.hasConfiguredAccounts()) {
      EnigmailLog.DEBUG("configure.jsm: setupEnigmail: no account configured. Waiting 60 seconds.\n");

      // try again in 60 seconds
      EnigmailTimer.setTimeout(
        function _f() {
          EnigmailConfigure.setupEnigmail(win, esvc);
        }, 60000);
      return;
    }


    try {
      await this.detectGnuPG(esvc);
      await determineInstallType();

      switch (EnigmailAutoSetup.value) {
        case EnigmailConstants.AUTOSETUP_NOT_INITIALIZED:
        case EnigmailConstants.AUTOSETUP_NO_ACCOUNT:
          break;
        default:
          EnigmailPrefs.setPref("configuredVersion", EnigmailApp.getVersion());
          EnigmailWindows.openSetupWizard(win);
      }
    }
    catch (x) {
      // ignore exceptions and proceed without setup wizard
    }
  },

  upgradeTo20: function(esvc) {
    esvc.addPostInitTask(replaceKeyIdWithFpr);
  },

  upgradeTo201: function() {
    setAutocryptForOldAccounts();
  },

  upgradeTo21: function() {
    setDefaultKeyServer();
  },

  upgradeTo30: function() {
    upgradeKeyserverPrefs();
    setGnuPGDefault();
  },

  upgradeTo31: function(esvc) {
    EnigmailLog.DEBUG(`configure.jsm: upgradeTo31()\n`);
    esvc.addPostInitTask(displayUpgradeInfo);
  },

  /**
   * Determine if GnuPG is available, and at least one key is present and set the cryptoAPI
   * correspondingly
   */
  detectGnuPG: async function(esvc) {
    EnigmailLog.DEBUG(`configure.jsm: detectGnuPG()\n`);
    const gpgAPI = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/gnupg.js").getGnuPGAPI();

    try {
      gpgAPI.initialize(null, esvc, null);

      let ot = await gpgAPI.getOwnerTrust(null);

      if (ot.ownerTrustData.search(/^[A-F0-9]/m) >= 0) {
        EnigmailLog.DEBUG(`configure.jsm: detectGnuPG: found usable GnuPG installation\n`);
        EnigmailPrefs.setPref("cryptoAPI", 1);
      }
      else {
        throw new Error("GnuPG found, but no key available");
      }
    }
    catch (ex) {
      EnigmailLog.DEBUG(`configure.jsm: detectGnuPG: ${ex.toString()}\n`);
      EnigmailPrefs.setPref("cryptoAPI", 2);

      const EnigmailCryptoAPI = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI.jsm").EnigmailCryptoAPI;
      EnigmailCryptoAPI(true);
      esvc.reinitialize();
    }
  }
};


function determineInstallType() {
  return new Promise((resolve, reject) => {
    EnigmailTimer.setTimeout(() => {
      EnigmailAutoSetup.determinePreviousInstallType().then(() => {
        resolve(true);
      });
    }, 10000);
  });
}


function upgradeKeyserverPrefs() {
  let keyservers = EnigmailPrefs.getPref("keyserver");
  let autoKeyRetrieve = EnigmailPrefs.getPref("autoKeyRetrieve");

  if (autoKeyRetrieve) {
    EnigmailPrefs.setPref("autoKeyRetrieveFromServer", true);
    EnigmailPrefs.setPref("defaultKeyserver", autoKeyRetrieve);
  }
  else {
    let defaultServer = keyservers.split(/[ ,;\t]/)[0];
    if (defaultServer) {
      EnigmailPrefs.setPref("defaultKeyserver", defaultServer);
    }
  }

  // unset old pref
  EnigmailPrefs.getPref("autoKeyRetrieve", "");
}
