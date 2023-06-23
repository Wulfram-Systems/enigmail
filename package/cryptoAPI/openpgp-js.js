/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */


"use strict";

var EXPORTED_SYMBOLS = ["getOpenPGPjsAPI"];


var Services = ChromeUtils.import("resource://gre/modules/Services.jsm").Services;
const pgpjs_keys = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-keys.jsm").pgpjs_keys;
const pgpjs_keyStore = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-keystore.jsm").pgpjs_keyStore;
const pgpjs_encrypt = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-encrypt.jsm").pgpjs_encrypt;
const pgpjs_crypto = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-crypto-main.jsm").pgpjs_crypto;
const pgpjs_keymanipulation = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-keymanipulation.jsm").pgpjs_keymanipulation;
const EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
const EnigmailConstants = ChromeUtils.import("chrome://enigmail/content/modules/constants.jsm").EnigmailConstants;
const XPCOMUtils = ChromeUtils.import("resource://gre/modules/XPCOMUtils.jsm").XPCOMUtils;

/* eslint no-invalid-this: 0 */
XPCOMUtils.defineLazyModuleGetter(this, "EnigmailKeyRing", "chrome://enigmail/content/modules/keyRing.jsm", "EnigmailKeyRing"); /* global EnigmailKeyRing: false */

// Load generic API
if (typeof CryptoAPI === "undefined") {
  Services.scriptloader.loadSubScript("chrome://enigmail/content/modules/cryptoAPI/interface.js",
    null, "UTF-8"); /* global CryptoAPI */
}

/**
 * OpenPGP.js implementation of CryptoAPI
 */

class OpenPGPjsCryptoAPI extends CryptoAPI {
  constructor() {
    super();
    this.api_name = "OpenPGP.js";
  }

  /**
   * Initialize the tools/functions required to run the API
   *
   * @param {nsIWindow} parentWindow: parent window, may be NULL
   * @param {Object} enigSvc: Enigmail service object
   * @param {String } preferredPath: try to use specific path to locate tool (gpg)
   */
  initialize(parentWindow, enigSvc, preferredPath) {
    let success = this.sync(pgpjs_keyStore.init());

    pgpjs_crypto.loadConfig();

    if (!success) throw "Init Error";
  }


  /**
   * Get a human readable version string
   *
   * @returns {String}
   */
  getVersionString() {
    return pgpjs_keys.getVersionString();
  }

  async getKeys(onlyKeys = null) {
    return pgpjs_keyStore.readKeyMetadata(onlyKeys);
  }

  async getStrippedKey(armoredKey, emailAddr) {
    return pgpjs_keys.getStrippedKey(armoredKey, emailAddr);
  }

  async getKeyListFromKeyBlock(keyBlockStr) {
    return pgpjs_keys.getKeyListFromKeyBlock(keyBlockStr);
  }

  /**
   * Import key(s) from a string provided
   *
   * @param {String} keyData:  the key data to be imported (ASCII armored)
   * @param {Boolean} minimizeKey: import the minimum key without any 3rd-party signatures
   * @param {Array of String} limitedUid: only import the UID specified
   *
   * @return {Object} or null in case no data / error:
   *   - {Number}          exitCode:        result code (0: OK)
   *   - {Array of String) importedKeys:    imported fingerprints
   *   - {Number}          importSum:       total number of processed keys
   *   - {Number}          importUnchanged: number of unchanged keys
   */

  async importKeyData(keyData, minimizeKey, limitedUid) {
    return pgpjs_keyStore.importKeyData(keyData, minimizeKey, limitedUid);
  }

  /**
   * Import key(s) from a file
   *
   * @param {nsIFile} inputFile:  the file holding the keys
   *
   * @return {Object} or null in case no data / error:
   *   - {Number}          exitCode:        result code (0: OK)
   *   - {Array of String) importedKeys:    imported fingerprints
   *   - {String}          errorMsg:        human readable error message
   *   - {Number}          importSum:       total number of processed keys
   *   - {Number}          importUnchanged: number of unchanged keys
   */
  async importKeyFromFile(inputFile) {
    const EnigmailFiles = ChromeUtils.import("chrome://enigmail/content/modules/files.jsm").EnigmailFiles;

    let fileData = EnigmailFiles.readBinaryFile(inputFile);
    return this.importKeyData(fileData, false, null);
  }

  /**
   * Delete keys from keyring
   *
   * @param {Array<String>} fpr: fingerprint(s) to delete
   * @param {Boolean} deleteSecretKey: if true, also delete secret keys [non-op]
   * @param {nsIWindow} parentWindow: parent window for displaying modal dialogs [non-op]
   *
   * @return {Promise<Object>}:
   *      - {Number} exitCode: 0 if successful, other values indicate error
   *      - {String} errorMsg: error message if deletion not successful
   */
  async deleteKeys(fpr, deleteSecretKey, parentWindow) {
    let exitCode = 1;
    try {
      await pgpjs_keyStore.deleteKeys(fpr);
      EnigmailKeyRing.updateKeys(fpr);

      exitCode = 0;
    }
    catch (ex) {}

    return {
      exitCode: exitCode,
      errorMsg: ""
    };
  }


  /**
   * Export public key(s) as ASCII armored data
   *
   * @param {String}  fpr         Fingerprint(s), separate mutliple keys with spaces
   *
   * @return {Object}:
   *   - {Number} exitCode:  result code (0: OK)
   *   - {String} keyData:   ASCII armored key data material
   *   - {String} errorMsg:  error message in case exitCode !== 0
   */

  async extractPublicKey(fpr) {
    let exitCode = 1,
      keyData = "";
    try {
      let fprArr = fpr.split(/[ ,\t]+/);
      keyData = await pgpjs_keyStore.readPublicKeys(fprArr);

      exitCode = 0;
    }
    catch (ex) {}

    return {
      exitCode: exitCode,
      keyData: keyData,
      errorMsg: ""
    };
  }


  /**
   * Export secret key(s) as ASCII armored data
   *
   * @param {String}  fpr       Specification by fingerprint(s) separate mutliple keys with spaces
   * @param {Boolean} minimalKey  if true, reduce key to minimum required
   *
   * @return {Object}:
   *   - {Number} exitCode:  result code (0: OK)
   *   - {String} keyData:   ASCII armored key data material
   *   - {String} errorMsg:  error message in case exitCode !== 0
   */

  async extractSecretKey(fpr, minimalKey) {
    let exitCode = 1,
      keyData = "";
    try {
      let fprArr = fpr.split(/[ ,\t]+/);
      keyData = await pgpjs_keyStore.readSecretKeys(fprArr, minimalKey);

      exitCode = 0;
    }
    catch (ex) {}

    return {
      exitCode: exitCode,
      keyData: keyData,
      errorMsg: ""
    };
  }

  /**
   * Export the minimum key for the public key object:
   * public key, user ID, newest encryption subkey
   *
   * @param {String} fpr  : a single FPR
   * @param {String} email: [optional] the email address of the desired user ID.
   *                        If the desired user ID cannot be found or is not valid, use the primary UID instead
   * @param {Array<Number>} subkeyDates: [optional] remove subkeys that don't match sepcific creation Dates
   *
   * @return {Promise<Object>}:
   *    - exitCode (0 = success)
   *    - errorMsg (if exitCode != 0)
   *    - keyData: BASE64-encded string of key data
   */
  async getMinimalPubKey(fpr, email, subkeyDates) {
    // subkeyDates are not needed/supported for OpenPGP.js
    return pgpjs_keyStore.readMinimalPubKey(fpr, email);
  }

  /**
   * Obtain signatures for a given set of key IDs.
   *
   * @param {String}  fpr:            fingerprint of key
   * @param {Boolean} ignoreUnknownUid: if true, filter out unknown signer's UIDs
   *
   * @return {Promise<Array of Object>}:
   *     - {String} userId
   *     - {String} rawUserId
   *     - {String} keyId
   *     - {String} fpr
   *     - {String} created
   *     - {Array} sigList:
   *            - {String} userId
   *            - {String} created
   *            - {String} signerKeyId
   *            - {String} sigType
   *            - {Boolean} sigKnown
   */
  async getKeySignatures(fpr, ignoreUnknownUid = false) {
    EnigmailLog.DEBUG(`openpgp-js.js: getKeySignatures ${fpr}\n`);

    let keys = await pgpjs_keyStore.readKeys([fpr]);
    let allKeys = await pgpjs_keyStore.readKeyMetadata();

    let keyList = [];
    for (let k of allKeys) {
      keyList[k.fpr] = k;
      keyList[k.keyId] = k;
    }

    let sigs = [];

    for (let k of keys) {
      let uids = pgpjs_keys.getSignaturesFromKey(k.key);

      for (let uid of uids) {
        let foundSigs = [];

        for (let sig of uid.sigList) {
          if (sig.signerKeyId in keyList) {
            sig.sigKnown = true;
            sig.userId = keyList[sig.signerKeyId].userId;
            sig.fpr = keyList[sig.signerKeyId].fpr;
            foundSigs.push(sig);
          }
          else if (ignoreUnknownUid) {
            foundSigs.push(sig);
          }
        }

        uid.sigList = foundSigs;
        sigs.push(uid);
      }
    }

    return sigs;
  }

  /**
   * Extract a photo ID from a key, store it as file and return the file object.
   *
   * @param {String} keyId:       Key ID / fingerprint
   * @param {Number} photoNumber: number of the photo on the key, starting with 0
   *
   * @return {nsIFile} object or null in case no data / error.
   */
  async getPhotoFile(keyId, photoNumber) {
    let keys = await pgpjs_keyStore.getKeysForKeyIds(false, [keyId]);
    if (keys.length > 0) {
      return pgpjs_keys.getPhotoForKey(keys[0], photoNumber);
    }

    return null;
  }


  /**
   * Generate a new key pair
   *
   * @param {String} name:       name part of UID
   * @param {String} comment:    comment part of UID (brackets are added)
   * @param {String} email:      email part of UID (<> will be added)
   * @param {Number} expiryDate: Key expiry: number of days after now; 0 if no expiry
   * @param {Number} keyLength:  size of key in bytes (e.g 4096)
   * @param {String} keyType:    'RSA' or 'ECC'
   * @param {String} passphrase: password; use null if no password
   *
   * @return {Object}: Handle to key creation
   *    - {function} cancel(): abort key creation
   *    - {Promise<exitCode, generatedKeyId>} promise: resolved when key creation is complete
   *                 - {Number} exitCode:       result code (0: OK)
   *                 - {String} generatedKeyId: generated key ID
   */

  generateKey(name, comment, email, expiryDate, keyLength, keyType, passphrase) {
    let canceled = false;

    let promise = new Promise((resolve, reject) => {
      pgpjs_keys.generateKey(name, comment, email, expiryDate, keyLength, keyType, passphrase).then(async (keyData) => {
        if (canceled) return;

        await pgpjs_keyStore.writeKey(keyData.privateKey);
        pgpjs_keyStore.storeRevocationCert(keyData.key, keyData.revocationCertificate);

        resolve({
          exitCode: 0,
          generatedKeyId: "0x" + keyData.key.getFingerprint().toUpperCase()
        });
      }).catch(err => {
        reject(err);
      });
    });

    return {
      cancel: function() {
        canceled = true;
      },
      promise: promise
    };
  }


  /**
   * Determine the file name from OpenPGP data.
   *
   * @param {byte} byteData    The encrypted data
   *
   * @return {String} - the name of the attached file
   */

  async getFileName(byteData) {
    let fn = null;
    try {
      let msg = await pgpjs_crypto.processPgpMessage(byteData, {});
      fn = msg.encryptedFileName;
    }
    catch (x) {}

    return fn;
  }

  /**
   * Verify the detached signature of an attachment (or in other words,
   * check the signature of a file, given the file and the signature).
   *
   * @param {String} filePath    Path specification for the signed file
   * @param {String} sigPath     Path specification for the signature file
   *
   * @return {Promise<String>} - A message from the verification.
   *
   * Use Promise.catch to handle failed verifications.
   * The message will be an error message in this case.
   */

  async verifyAttachment(filePath, sigPath) {
    return pgpjs_crypto.verifyFile(filePath, sigPath);
  }

  /**
   * Decrypt an attachment.
   *
   * @param {Bytes}  encrypted     The encrypted data
   *
   * @return {Promise<Object>} - Return object with decrypted data in {stdoutData} and
   * status information
   *
   * Use Promise.catch to handle failed decryption.
   * retObj.errorMsg will be an error message in this case.
   */

  async decryptAttachment(encrypted) {
    let ret = await pgpjs_crypto.processPgpMessage(encrypted, {});

    if ("decryptedData" in ret) {
      ret.stdoutData = ret.decryptedData;
    }

    return ret;
  }

  /**
   * Generic function to decrypt and/or verify an OpenPGP message.
   *
   * @param {String} pgpMessage:   The signed or encrypted OpenPGP message  data
   * @param {Object} options       Decryption/verification options
   *
   * @return {Promise<Object>} - Return object with decryptedData and
   * status information
   *
   * Use Promise.catch to handle failed decryption.
   * retObj.errorMsg will be an error message in this case.
   */

  async decrypt(pgpMessage, options) {
    EnigmailLog.DEBUG(`openpgpg-js.js: decrypt()\n`);

    if (options.verifyOnly) {
      return pgpjs_crypto.verify(pgpMessage, options);
    }
    else {
      return pgpjs_crypto.processPgpMessage(pgpMessage, options);
    }
  }

  /**
   * Decrypt a PGP/MIME-encrypted message
   *
   * @param {String} encrypted     The encrypted data
   * @param {Object} options       Decryption options
   *
   * @return {Promise<Object>} - Return object with decryptedData and
   * status information
   *
   * Use Promise.catch to handle failed decryption.
   * retObj.errorMsg will be an error message in this case.
   */

  async decryptMime(encrypted, options) {
    options.noOutput = false;
    options.verifyOnly = false;
    options.uiFlags = EnigmailConstants.UI_PGP_MIME;

    return pgpjs_crypto.processPgpMessage(encrypted, options);
  }

  /**
   * Verify a PGP/MIME-signed message
   *
   * @param {String} signedData    The signed data
   * @param {String} signature     The signature data
   * @param {Object} options       Decryption options
   *
   * @return {Promise<Object>} - Return object with decryptedData and
   * status information
   *
   * Use Promise.catch to handle failed decryption.
   * retObj.errorMsg will be an error message in this case.
   */

  async verifyMime(signedData, signature, options) {
    return pgpjs_crypto.verifyDetached(signedData, signature);
  }


  /**
   * Encrypt messages
   *
   * @param {String} from: keyID or email address of sender/signer
   * @param {String} recipients: keyIDs or email addresses of recipients, separated by spaces
   * @param {String} hiddenRecipients: keyIDs or email addresses of hidden recipients (bcc), separated by spaces
   * @param {Number} encryptionFlags: Flags for Signed/encrypted/PGP-MIME etc.
   * @param {String} plainText: data to encrypt
   * @param {String} hashAlgorithm: [OPTIONAL] hash algorithm
   * @param {nsIWindow} parentWindow: [OPTIONAL] window on top of which to display modal dialogs
   *
   * @return {Promise<Object>}:
   *     - {Number} exitCode:    0 = success / other values: error
   *     - {String} data:        encrypted data
   *     - {String} errorMsg:    error message in case exitCode !== 0
   *     - {Number} statusFlags: Status flags for result
   */

  encryptMessage(from, recipients, hiddenRecipients, encryptionFlags, plainText, hashAlgorithm = null, parentWindow = null) {
    return pgpjs_encrypt.encryptMessage(from, recipients, hiddenRecipients, encryptionFlags, plainText, hashAlgorithm, parentWindow);
  }

  /**
   * Clear any cached passwords
   *
   * @return {Boolean} true if successful, false otherwise
   */
  async clearPassphrase() {
    // this has no meaning
    return true;
  }

  /***
   * Determine if a specific feature is available by the used toolset
   *
   * @param {String} featureName:  String; one of the following values:
   *    version-supported    - is the gpg version supported at all (true for gpg >= 2.0.10)
   *    supports-gpg-agent   - is gpg-agent is auto-started (true for gpg >= 2.0.16)
   *    keygen-passphrase    - can the passphrase be specified when generating keys (false for gpg 2.1 and 2.1.1)
   *    windows-photoid-bug  - is there a bug in gpg with the output of photoid on Windows (true for gpg < 2.0.16)
   *    genkey-no-protection - is "%no-protection" supported for generting keys (true for gpg >= 2.1)
   *    search-keys-cmd      - what command to use to terminate the --search-key operation. ("save" for gpg > 2.1; "quit" otherwise)
   *    socks-on-windows     - is SOCKS proxy supported on Windows (true for gpg >= 2.0.20)
   *    supports-dirmngr     - is dirmngr supported (true for gpg >= 2.1)
   *    supports-ecc-keys    - are ECC (elliptic curve) keys supported (true for gpg >= 2.1)
   *    supports-sender      - does gnupg understand the --sender argument (true for gpg >= 2.1.15)
   *    supports-wkd         - does gpg support wkd (web key directory) (true for gpg >= 2.1.19)
   *    export-result        - does gpg print EXPORTED when exporting keys (true for gpg >= 2.1.10)
   *    decryption-info      - does gpg print DECRYPTION_INFO (true for gpg >= 2.0.19)
   *    export-specific-uid  - does gpg support exporting a key with a specific UID (true for gpg >= 2.2.8)
   *    supports-show-only   - does gpg support --import-options show-only (true for gpg >= 2.1.14)
   *    handles-huge-keys    - can gpg deal with huge keys without aborting (true for gpg >= 2.2.17)
   *    smartcard            - does the library support smartcards
   *    uid-management       - implementation supports adding, removing etc. of UIDs (true for GnuPG)

   * @return: depending on featureName - Boolean unless specified differently:
   *    (true if feature is available / false otherwise)
   *   If the feature cannot be found, undefined is returned
   */
  supportsFeature(featureName) {
    switch (featureName) {
      case "supports-ecc-keys":
      case "export-specific-uid":
      case "keygen-passphrase":
        return true;
    }
    return false;
  }

  /**
   * Return the key management functions (sub-API)
   */
  getKeyManagement() {
    return pgpjs_keymanipulation;
  }

  getTrustLabel(trustCode) {
    return pgpjs_keys.getTrustLabel(trustCode);
  }
}

function getOpenPGPjsAPI() {
  return new OpenPGPjsCryptoAPI();
}
