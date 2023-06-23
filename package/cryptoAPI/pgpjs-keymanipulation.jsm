/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */


"use strict";

var EXPORTED_SYMBOLS = ["pgpjs_keymanipulation"];


var Services = ChromeUtils.import("resource://gre/modules/Services.jsm").Services;
const EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
const EnigmailLazy = ChromeUtils.import("chrome://enigmail/content/modules/lazy.jsm").EnigmailLazy;
const getOpenPGPLibrary = ChromeUtils.import("chrome://enigmail/content/modules/stdlib/openpgp-loader.jsm").getOpenPGPLibrary;
const EnigmailTime = ChromeUtils.import("chrome://enigmail/content/modules/time.jsm").EnigmailTime;
const EnigmailTimer = ChromeUtils.import("chrome://enigmail/content/modules/timer.jsm").EnigmailTimer;
const EnigmailData = ChromeUtils.import("chrome://enigmail/content/modules/data.jsm").EnigmailData;
const EnigmailFuncs = ChromeUtils.import("chrome://enigmail/content/modules/funcs.jsm").EnigmailFuncs;
const EnigmailFiles = ChromeUtils.import("chrome://enigmail/content/modules/files.jsm").EnigmailFiles;
const EnigmailLocale = ChromeUtils.import("chrome://enigmail/content/modules/locale.jsm").EnigmailLocale;
const getOpenPGP = EnigmailLazy.loader("enigmail/openpgp.jsm", "EnigmailOpenPGP");
const EnigmailConstants = ChromeUtils.import("chrome://enigmail/content/modules/constants.jsm").EnigmailConstants;
const pgpjs_keyStore = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-keystore.jsm").pgpjs_keyStore;
const pgpjs_keys = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-keys.jsm").pgpjs_keys;

const NS_WRONLY = 0x02;
const NS_CREATE_FILE = 0x08;
const NS_TRUNCATE = 0x20;
const STANDARD_FILE_PERMS = 0o600;
const NS_LOCALFILEOUTPUTSTREAM_CONTRACTID = "@mozilla.org/network/file-output-stream;1";


/**
 * OpenPGP.js implementation of CryptoAPI
 */

var pgpjs_keymanipulation = {
  genRevokeCert: async function(parentWindow, keyId, outFile, reasonCode, reasonText) {
    EnigmailLog.DEBUG(`pgpjs-keymanipulation.jsm: genRevokeCert: keyId=${keyId}\n`);

    const PgpJS = getOpenPGPLibrary();

    let keyList = await pgpjs_keyStore.getKeysForKeyIds(true, [keyId]);

    if (!keyList || keyList.length === 0) {
      return createError(EnigmailLocale.getString("keyNotFound", keyId));
    }

    let revokeReason = 0;
    switch (reasonCode) {
      case "1":
        revokeReason = PgpJS.enums.reasonForRevocation.key_compromised;
        break;
      case "2":
        revokeReason = PgpJS.enums.reasonForRevocation.key_superseded;
        break;
      case "3":
        revokeReason = PgpJS.enums.reasonForRevocation.key_retired;
    }

    const res = await pgpjs_keys.decryptSecretKey(keyList[0], EnigmailConstants.KEY_DECRYPT_REASON_MANIPULATE_KEY);
    if (!res) {
      return createError(EnigmailLocale.getString("noPassphrase"));
    }
    keyList[0] = res;

    const revokedKey = await keyList[0].revoke({
      flag: revokeReason,
      string: reasonText
    });

    const revCert = await revokedKey.getRevocationCertificate();

    EnigmailFiles.writeFileContents(outFile, revCert, STANDARD_FILE_PERMS);

    return createSuccess();
  },


  /**
   * set the expiration date of the chosen key and subkeys
   *
   * @param  {nsIWindow} parent
   * @param  {String}    keyId         e.g. 8D18EB22FDF633A2
   * @param  {Array}     subKeys       List of Integer values, e.g. [0,1,3]
   *                                   "0" reflects the primary key and should always be set.
   * @param  {Integer}   expiryValue   A number between 1 and 100
   * @param  {Integer}   timeScale     1 or 30 or 365 meaning days, months, years
   * @param  {Boolean}   noExpiry      True: Expire never. False: Use expiryLength.
   * @return  {Promise<Object>}
   */
  setKeyExpiration: async function(parent, keyId, subKeys, expiryValue, timeScale, noExpiry) {
    EnigmailLog.DEBUG(`pgpjs-keymanipulation.jsm: setKeyExpiration: keyId=${keyId}\n`);
    let keyList = await pgpjs_keyStore.getKeysForKeyIds(true, [keyId]);

    if (!keyList || keyList.length === 0) {
      return createError(EnigmailLocale.getString("keyNotFound", keyId));
    }

    if (noExpiry) {
      expiryValue = 0;
    }

    let newKey = await pgpjs_keys.changeKeyExpiry(keyList[0], subKeys, parseInt(timeScale, 10) * expiryValue * 86400);
    if (newKey) {
      try {
        await pgpjs_keyStore.replaceKey(newKey);
      }
      catch (ex) {
        return createError(ex.message);
      }
    }

    return createSuccess();
  },

  enableDisableKey: async function(parent, keyId, disableKey) {
    EnigmailLog.DEBUG(`pgpjs-keymanipulation.jsm: enableDisableKey: keyId=${keyId}\n`);

    let fpr = keyId.replace(/^0x/, "");
    let keyList = await pgpjs_keyStore.getKeysForKeyIds(false, [keyId.replace(/^0x/, "")], true);

    if (!keyList || keyList.length === 0) {
      return createError(EnigmailLocale.getString("keyNotFound", keyId));
    }

    try {
      await pgpjs_keyStore.setKeyStatus(fpr, !disableKey);
    }
    catch (ex) {
      return createError(ex.message);
    }

    return createSuccess();
  },

  initiateChangePassphrase: async function(parent, keyId) {
    EnigmailLog.DEBUG(`pgpjs-keymanipulation.jsm: initiateChangePassphrase: keyId=${keyId}\n`);
    const EnigmailWindows = ChromeUtils.import("chrome://enigmail/content/modules/windows.jsm").EnigmailWindows;

    if (!parent) {
      parent = EnigmailWindows.getBestParentWin();
    }

    let keyList = await pgpjs_keyStore.getKeysForKeyIds(true, [keyId]);

    if (!keyList || keyList.length === 0) {
      return createError(EnigmailLocale.getString("keyNotFound", keyId));
    }

    parent.openDialog("chrome://enigmail/content/ui/changePassword.xul", "", "dialog,modal,centerscreen", {
      keyId: keyList[0].getFingerprint().toUpperCase(),
      userId: keyList[0].users[0].userID.userID,
      noCurrentPasswd: keyList[0].isDecrypted()
    });

    return createSuccess();
  },


  performChangePassphrase: async function(keyId, oldPassword, newPassword) {
    EnigmailLog.DEBUG(`pgpjs-keymanipulation.jsm: performChangePassphrase: keyId=${keyId}\n`);

    const PgpJS = getOpenPGPLibrary();
    let keyList = await pgpjs_keyStore.getKeysForKeyIds(true, [keyId]);

    if (!keyList || keyList.length === 0) {
      return createError(EnigmailLocale.getString("keyNotFound", keyId));
    }

    let key = keyList[0];
    if (!key.isDecrypted()) {
      try {
        key = await PgpJS.decryptKey({
          privateKey: key,
          passphrase: oldPassword
        });
      }
      catch (ex) {
        if (pgpjs_keys.isWrongPassword(ex)) {
          return createError(EnigmailLocale.getString("changePasswdDlg.wrongOldPasswd"));
        }
        else if (!pgpjs_keys.isKeyFullyDecrypted(ex, key)) {
          return createError(ex.toString());
        }
      }
    }

    if (newPassword.length > 0) {
      key = await PgpJS.encryptKey({
        privateKey: key,
        passphrase: newPassword
      });
    }

    try {
      await pgpjs_keyStore.replaceKey(key);
    }
    catch (ex) {
      return createError(ex.message);
    }

    return createSuccess();
  },

  signKey: async function(parent, signingKeyId, keyIdToSign, signUids, signLocally, trustLevel) {
    EnigmailLog.DEBUG(`pgpjs-keymanipulation.jsm: signKey (trustLevel=${trustLevel}, userId= ${signingKeyId}, keyId=${keyIdToSign})\n`);

    let keyList = await pgpjs_keyStore.getKeysForKeyIds(true, [signingKeyId]);
    if (!keyList || keyList.length === 0) {
      return createError(EnigmailLocale.getString("keyNotFound", signingKeyId));
    }
    const signingKey = keyList[0];

    keyList = await pgpjs_keyStore.getKeysForKeyIds(false, [keyIdToSign]);
    if (!keyList || keyList.length === 0) {
      return createError(EnigmailLocale.getString("keyNotFound", keyIdToSign));
    }
    const keyToSign = keyList[0];
    try {
      let result = await pgpjs_keys.signKey(signingKey, keyToSign, signUids);
      if (result.signedKey !== null) {
        let r = await pgpjs_keyStore.writeKey(await result.signedKey.armor());
        if (r.length > 0) {
          return createSuccess();
        }
        else {
          return createError(EnigmailLocale.getString("saveKeysFailed"));
        }
      }
      else {
        return createError(result.errorMsg);
      }
    }
    catch (ex) {
      return createError(ex.message);
    }
  }
};


function createError(errorMsg) {
  return {
    returnCode: 1,
    errorMsg: errorMsg
  };
}

function createSuccess() {
  return {
    returnCode: 0,
    errorMsg: ""
  };
}
