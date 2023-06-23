/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */


"use strict";

var EXPORTED_SYMBOLS = ["pgpjs_encrypt"];


var Services = ChromeUtils.import("resource://gre/modules/Services.jsm").Services;
const EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
const getOpenPGPLibrary = ChromeUtils.import("chrome://enigmail/content/modules/stdlib/openpgp-loader.jsm").getOpenPGPLibrary;
const EnigmailConstants = ChromeUtils.import("chrome://enigmail/content/modules/constants.jsm").EnigmailConstants;
const pgpjs_keys = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-keys.jsm").pgpjs_keys;
const pgpjs_keyStore = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-keystore.jsm").pgpjs_keyStore;
const pgpjs_crypto = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-crypto-main.jsm").pgpjs_crypto;
const EnigmailLocale = ChromeUtils.import("chrome://enigmail/content/modules/locale.jsm").EnigmailLocale;

var gLastKeyDecrypted = null;

/**
 * OpenPGP.js implementation of CryptoAPI
 *
 * Encryption-related functions
 */

var pgpjs_encrypt = {
  /**
   * Encrypt messages
   *
   * @param {String} from: keyID of sender/signer
   * @param {String} recipients: keyIDs of recipients, separated by spaces
   * @param {String} hiddenRecipients: keyIDs or email addresses of hidden recipients (bcc), separated by spaces
   * @param {Number} encryptionFlags: Flags for Signed/encrypted/PGP-MIME etc.
   * @param {String} plainText: data to encrypt
   * @param {String} hashAlgorithm: [OPTIONAL] hash algorithm (ignored for this API)
   * @param {nsIWindow} parentWindow: [OPTIONAL] window on top of which to display modal dialogs
   *
   * @return {Promise<Object>}:
   *     - {Number} exitCode:    0 = success / other values: error
   *     - {String} data:        encrypted data
   *     - {String} errorMsg:    error message in case exitCode !== 0
   *     - {Number} statusFlags: Status flags for result
   */

  encryptMessage: async function(from, recipients, hiddenRecipients, encryptionFlags, plainText, hashAlgorithm = null, parentWindow = null) {
    EnigmailLog.DEBUG(`pgpjs-encrypt.jsm: encryptMessage(${from}, ${recipients}, ${encryptionFlags}, ${plainText.length})\n`);

    let retObj = {
      exitCode: 1,
      data: "",
      errorMsg: "",
      statusFlags: 0
    };

    try {
      if (from.substr(0, 2) !== "0x") {
        throw Error("From address is not a key ID");
      }

      let ownKeyId = from;

      if (encryptionFlags & EnigmailConstants.SEND_ENCRYPTED) {
        if (!(encryptionFlags & EnigmailConstants.SEND_SIGNED)) {
          from = null;
        }

        let recipientArr = [];

        if (recipients && recipients.length > 0) {
          recipientArr = recipients.split(/ +/);
          for (let i of recipientArr) {
            if (i.substr(0, 2) !== "0x") {
              throw Error(`Recipient ${i} is not a key ID`);
            }
          }
        }

        let hiddenRcpt = [];
        if (hiddenRecipients && hiddenRecipients.length > 0) {
          hiddenRcpt = hiddenRecipients.split(/ +/);
          for (let i of recipientArr) {
            if (i.substr(0, 2) !== "0x") {
              throw Error(`Hidden recipient ${i} is not a key ID`);
            }
          }
        }

        recipientArr = recipientArr.concat(hiddenRcpt);

        if (encryptionFlags & EnigmailConstants.SEND_ENCRYPT_TO_SELF) recipientArr.push(ownKeyId);
        let result = await encryptData(recipientArr, from, plainText);

        if (typeof(result) === "string") {
          retObj.data = result;
          retObj.exitCode = 0;
        }
      }
      else {
        const detachedSig = ((encryptionFlags & EnigmailConstants.SEND_PGP_MIME) ||
          (encryptionFlags & EnigmailConstants.SEND_ATTACHMENT));

        let result = await signData(from, plainText, detachedSig ? true : false, encryptionFlags);
        if (typeof(result) === "string") {
          retObj.data = result;
          retObj.exitCode = 0;
        }
      }
    }
    catch (ex) {
      EnigmailLog.DEBUG(`pgpjs-encrypt.jsm: encryptMessage: ERROR: ${ex.toString()}\n`);
      EnigmailLog.DEBUG(`${ex.stack}\n`);
      retObj.errorMsg = ex.toString();
    }
    return retObj;
  }

};

/**
 * Encrypt (and possibly sign) some text data
 *
 * @param {Array<String>} recipientKeyIds: Array of key IDs to which to encrypt the message
 * @param {String} signingKeyId:           If provided, the message will be signed using that key.
 *                                         If '' or null, message will not be signed.
 * @param {String} text:                   The message to encrypt.
 * @param {Number} encryptionFlags:        Flags for Signed/encrypted/PGP-MIME etc.
 */
async function encryptData(recipientKeyIds, signingKeyId, text, encryptionFlags) {
  EnigmailLog.DEBUG(`pgpjs-encrypt.jsm: encryptData(${recipientKeyIds.length}, ${signingKeyId})\n`);
  const PgpJS = getOpenPGPLibrary();

  let privateKeys = null;
  let pk = {
    key: null
  };

  if (signingKeyId) {
    privateKeys = await pgpjs_keyStore.getKeysForKeyIds(true, [signingKeyId]);
    pk.key = privateKeys[0];
    if (!await decryptPrivateKey(pk, EnigmailConstants.KEY_DECRYPT_REASON_SIGNCRYPT_MSG, encryptionFlags)) {
      throw Error("No password provided");
    }
  }

  let uniqueKeyIds = [...new Set(recipientKeyIds)]; // make key IDs unique
  let publicKeys = await pgpjs_keyStore.getKeysForKeyIds(false, uniqueKeyIds);

  return pgpjs_crypto.encryptData(text, publicKeys, pk.key);
}

/**
 * Sign some text data
 *
 * @param {String} signingKeyId:       Key ID used for signing the message
 * @param {String} text:               Text data to sign
 * @param {Boolean} detachedSignature: If true, create a detached signature.
 *                                     If false, create a clearsigned message.
 * @param {Number} encryptionFlags:    Flags for Signed/encrypted/PGP-MIME etc.
 */
async function signData(signingKeyId, text, detachedSignature, encryptionFlags) {
  EnigmailLog.DEBUG(`pgpjs-encrypt.jsm: signData(${signingKeyId})\n`);
  const PgpJS = getOpenPGPLibrary();

  let privateKeys = null;

  if (!signingKeyId) {
    throw Error("No private key provided");
  }

  privateKeys = await pgpjs_keyStore.getKeysForKeyIds(true, [signingKeyId]);
  let pk = {
    key: privateKeys[0]
  };
  if (!await decryptPrivateKey(pk, EnigmailConstants.KEY_DECRYPT_REASON_SIGN_MSG, encryptionFlags)) {
    throw Error("No password provided");
  }

  return pgpjs_crypto.signData(text, pk.key, detachedSignature);
}

/**
 * Decrypt a private key and, if the flag SEND_TEST is provided, keep the decrypted version for another use
 * This is done to allow for testing encryption/signing and then sending the message without needing to enter
 * the password twice.
 *
 * @param {Object} keyData:         <key> contains the private key
 * @param {Text} decryptionMsg:     reason message to display for password dialog
 * @param {Number} encryptionFlags: Flags for Signed/encrypted/PGP-MIME etc.
 *
 * @returns {Boolean} true if key was decrypted, false if not
 */
async function decryptPrivateKey(keyData, decryptionMsg, encryptionFlags) {
  if (encryptionFlags & EnigmailConstants.SEND_TEST) {
    gLastKeyDecrypted = null;
    let decryptedKey = await pgpjs_keys.decryptSecretKey(keyData.key, decryptionMsg);
    if (decryptedKey) {
      keyData.key = decryptedKey;
      gLastKeyDecrypted = keyData.key;
    }

    return decryptedKey !== null;
  }

  // regular message -> use the key once
  if (gLastKeyDecrypted && (gLastKeyDecrypted.getFingerprint() === keyData.key.getFingerprint())) {
    keyData.key = gLastKeyDecrypted;
    gLastKeyDecrypted = null;
    return true;
  }
  else {
    let decryptedKey = await pgpjs_keys.decryptSecretKey(keyData.key, decryptionMsg);
    keyData.key = decryptedKey;
    return  decryptedKey !== null;
  }
}
