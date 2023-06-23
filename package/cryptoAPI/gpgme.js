/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */


"use strict";

var EXPORTED_SYMBOLS = ["getGpgMEApi"];

var Services = Components.utils.import("resource://gre/modules/Services.jsm").Services;
const XPCOMUtils = ChromeUtils.import("resource://gre/modules/XPCOMUtils.jsm").XPCOMUtils;

if (typeof CryptoAPI === "undefined") {
  Services.scriptloader.loadSubScript("chrome://enigmail/content/modules/cryptoAPI/interface.js",
    null, "UTF-8"); /* global CryptoAPI */
}

/* eslint no-invalid-this: 0 */
XPCOMUtils.defineLazyModuleGetter(this, "EnigmailKeyRing", "chrome://enigmail/content/modules/keyRing.jsm", "EnigmailKeyRing"); /* global EnigmailKeyRing: false */
XPCOMUtils.defineLazyModuleGetter(this, "EnigmailDialog", "chrome://enigmail/content/modules/dialog.jsm", "EnigmailDialog"); /* global EnigmailDialog: false */
XPCOMUtils.defineLazyModuleGetter(this, "EnigmailData", "chrome://enigmail/content/modules/data.jsm", "EnigmailData"); /* global EnigmailData: false */
XPCOMUtils.defineLazyModuleGetter(this, "EnigmailKeyEditor", "chrome://enigmail/content/modules/cryptoAPI/gnupg-keyEditor.jsm", "EnigmailKeyEditor"); /* global EnigmailKeyEditor: false */

const EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
const EnigmailExecution = ChromeUtils.import("chrome://enigmail/content/modules/execution.jsm").EnigmailExecution;
const EnigmailFiles = ChromeUtils.import("chrome://enigmail/content/modules/files.jsm").EnigmailFiles;
const EnigmailConstants = ChromeUtils.import("chrome://enigmail/content/modules/constants.jsm").EnigmailConstants;
const EnigmailTime = ChromeUtils.import("chrome://enigmail/content/modules/time.jsm").EnigmailTime;
const EnigmailData = ChromeUtils.import("chrome://enigmail/content/modules/data.jsm").EnigmailData;
const EnigmailLocale = ChromeUtils.import("chrome://enigmail/content/modules/locale.jsm").EnigmailLocale;
const EnigmailOS = ChromeUtils.import("chrome://enigmail/content/modules/os.jsm").EnigmailOS;
const EnigmailVersioning = ChromeUtils.import("chrome://enigmail/content/modules/versioning.jsm").EnigmailVersioning;
const EnigmailPrefs = ChromeUtils.import("chrome://enigmail/content/modules/prefs.jsm").EnigmailPrefs;

const nsIWindowsRegKey = Ci.nsIWindowsRegKey;
const MINIMUM_GPG_VERSION = "2.2.10";

const VALIDITY_SYMBOL = {
  ultimate: "u",
  unknown: "-",
  full: "f",
  marginal: "m",
  never: "n"
};

var inspector;

/**
 * GpgME-JSON implementation of CryptoAPI
 */

class GpgMECryptoAPI extends CryptoAPI {
  constructor() {
    super();
    this.api_name = "GpgME";
    this._gpgmePath = "";
    this._gpgPath = "";
    this._gpgAgentPath = "";
    this._gpgVersion = "";
    this._gpgConfPath = "";

    if (!inspector) {
      inspector = Cc["@mozilla.org/jsinspector;1"].createInstance(Ci.nsIJSInspector);
    }
  }

  /**
   * Initialize the tools/functions required to run the API
   *
   * @param {nsIWindow} parentWindow: parent window, may be NULL
   * @param {Object} esvc: Enigmail service object
   * @param {String } preferredPath: try to use specific path to locate tool (not used for gpgme)
   */
  initialize(parentWindow, esvc, preferredPath) {
    EnigmailLog.DEBUG(`gpgme.js: initialize()\n`);
    if (!esvc) {
      esvc = {
        environment: Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment)
      };
    }

    this._gpgmePath = resolvePath(esvc.environment);
    if (!this._gpgmePath) {
      throw new Error(`gpgme.js: initialize: gpgme-json executable not found`);
    }

    this._gpgPath = null;
    try {
      let opts = this.sync(this.execJsonCmd({
        op: "config"
      }));

      for (let o of opts.components) {
        switch (o.name) {
          case "gpg":
            this._gpgPath = gpgUnescape(o.program_name);
            break;
          case "gpg-agent":
            this._gpgAgentPath = gpgUnescape(o.program_name);
            break;
        }
      }

      if (!this._gpgPath) throw "GnuPG not available";

      let r = this.sync(determineGpgVersion(this._gpgPath));

      if (EnigmailVersioning.lessThan(r.gpgVersion, MINIMUM_GPG_VERSION)) {
        EnigmailLog.ERROR(`gpgme.js: found GnuPG version ${r.gpgVersion} older than minimum version ${MINIMUM_GPG_VERSION}\n`);

        EnigmailDialog.alert(parentWindow, EnigmailLocale.getString("oldGpgVersion20", [r.gpgVersion, MINIMUM_GPG_VERSION]));
        throw Components.results.NS_ERROR_FAILURE;
      }

      this._gpgPath = r.gpgPath;
      this._gpgVersion = r.gpgVersion;
      this._gpgConfPath = resolveToolPath(this._gpgAgentPath, "gpgconf");
      EnigmailLog.DEBUG(`gpgme.js: initialization complete\n`);
    }
    catch (ex) {
      EnigmailLog.DEBUG(`gpgme.js: initialize: error: ${ex.toString()}\n`);
      this._gpgmePath = null;
      throw ex;
    }
  }

  /**
   * Close/shutdown anything related to the functionality
   */
  finalize() {
    return null;
  }


  /**
   * Obtain signatures for a given set of key IDs.
   *
   * @param {String}  fpr:            key fingerprint. Separate multiple keys by spaces.
   * @param {Boolean} ignoreUnknownUid: if true, filter out unknown signer's UIDs
   *
   * @return {Promise<Array of Object>}
   *     - {String} userId
   *     - {String} rawUserId
   *     - {String} keyId
   *     - {String} fpr
   *     - {String} created
   *     - {Array} sigList:
   *            - {String} userId
   *            - {String} created
   *            - {Number} createdTime
   *            - {String} signerKeyId
   *            - {String} sigType
   *            - {Boolean} sigKnown
   */
  async getKeySignatures(fpr, ignoreUnknownUid = false) {
    EnigmailLog.DEBUG(`gpgme.js: getKeySignatures(${fpr}, ${ignoreUnknownUid})\n`);
    let cmdObj = {
      "op": "keylist",
      "sigs": true,
      "keys": fpr.split(/[ ,]+/)
    };

    let keysObj = await this.execJsonCmd(cmdObj);
    let signatureList = [];

    if ("keys" in keysObj && keysObj.keys.length > 0) {
      for (let key of keysObj.keys) {
        for (let uid of key.userids) {
          const sig = {
            userId: EnigmailData.convertGpgToUnicode(uid.uid),
            rawUserId: EnigmailData.convertGpgToUnicode(uid.uid),
            keyId: key.subkeys[0].keyid,
            fpr: key.fingerprint,
            created: EnigmailTime.getDateTime(key.subkeys[0].timestamp, true, false),
            sigList: []
          };

          for (let s of uid.signatures) {
            let uid = s.name ? s.name : "";
            let sigKnown = s.status === "Success";
            if (sigKnown) {
              if (s.email) {
                if (uid.length > 0) {
                  uid += " <" + s.email + ">";
                }
                else {
                  uid = s.email;
                }
              }

              if (s.comment.length > 0) {
                if (uid.length > 0) {
                  uid += "(" + s.comment + ")";
                }
                else {
                  uid = s.comment;
                }
              }
            }

            if (sigKnown || ignoreUnknownUid) {
              sig.sigList.push({
                userId: EnigmailData.convertGpgToUnicode(uid),
                created: EnigmailTime.getDateTime(s.timestamp, true, false),
                createdTime: s.timestamp,
                signerKeyId: s.keyid,
                sigType: s.exportable ? "x" : "l",
                sigKnown: sigKnown
              });
            }
          }
          signatureList.push(sig);
        }
      }
    }

    return signatureList;
  }

  /**
   * Get the list of all konwn keys (including their secret keys)
   * @param {Array of String} onlyKeys: [optional] only load data for specified key IDs
   *
   * @return {Promise<Array of Object>}
   */
  async getKeys(onlyKeys = null) {
    EnigmailLog.DEBUG(`gpgme.js: getKeys(${onlyKeys})\n`);
    let cmdObj = {
      "op": "keylist",
      "with-secret": true
    };

    if (onlyKeys && typeof(onlyKeys) === "string") {
      onlyKeys = onlyKeys.split(/[, ]+/);
    }
    if (onlyKeys) {
      cmdObj.keys = onlyKeys;
    }

    let keysObj = await this.execJsonCmd(cmdObj);

    let keyArr = [];
    if ("keys" in keysObj) {
      for (let key of keysObj.keys) {
        keyArr.push(createKeyObj(key));
      }
    }

    return keyArr;
  }

  /**
   * Return an array containing the aliases and the email addresses
   *
   * @return {Array<{alias,keylist}>} <{String,String}>
   */
  getGroups() {
    EnigmailLog.DEBUG(`gpgme.js: getGroups()\n`);
    let cfg = this.sync(this.execJsonCmd({
      op: "config_opt",
      component: "gpg",
      option: "group"
    }));
    let groups = null;
    if ("option" in cfg) {
      groups = cfg.option.value;
    }

    if (!groups) return [];

    let groupList = [];
    for (let g of groups) {
      let parts = g.string.match(/^([^=]+)=(.+)$/);
      if (parts && parts.length > 2) {
        parts[1] = parts[1].toLowerCase();
        if (parts[1] in groupList) {
          groupList[parts[1]] += ` ${parts[2]}`;
        }
        else
          groupList[parts[1]] = parts[2];
      }
    }

    let ret = [];
    for (let g in groupList) {
      ret.push({
        alias: g,
        keylist: groupList[g]
      });
    }

    return ret;
  }

  /**
   * Get groups defined in gpg.conf in the same structure as KeyObject
   * [synchronous]
   *
   * @return {Array of KeyObject} with type = "grp"
   */
  getGroupList() {
    EnigmailLog.DEBUG(`gpgme.js: getGroupList()\n`);

    let groupList = this.getGroups();
    let retList = [];
    for (let grp of groupList) {

      let grpObj = {
        type: "grp",
        keyUseFor: "G",
        userIds: [],
        subKeys: [],
        keyTrust: "g",
        userId: grp.alias,
        keyId: grp.alias
      };

      let rcpt = grp.keylist.split(/[,; ]+/);
      for (let r of rcpt) {
        grpObj.userIds.push({
          userId: EnigmailData.convertGpgToUnicode(r),
          keyTrust: "q"
        });
      }

      retList.push(grpObj);
    }

    return retList;
  }

  /**
   * Extract a photo ID from a key, store it as file and return the file object.
   *
   * @param {String} keyId:       Key Fingerprint
   * @param {Number} photoNumber: number of the photo on the key, starting with 0
   *
   * @return {nsIFile} object or null in case no data / error.
   */

  async getPhotoFile(keyId, photoNumber) {
    // not available via this API
    return null;
  }


  /**
   * Import key(s) from a file
   *
   * @param {nsIFile} inputFile:  the file holding the keys
   *
   * @return {Object} or null in case no data / error:
   *   - {Number}          exitCode:        result code (0: OK)
   *   - {Array of String) importedKeys:    imported fingerprints
   *   - {Number}          importSum:       total number of processed keys
   *   - {Number}          importUnchanged: number of unchanged keys
   */

  async importKeyFromFile(inputFile) {
    EnigmailLog.DEBUG(`gpgme.js: importKeyFromFile(${inputFile.path})\n`);

    let fileData = EnigmailFiles.readBinaryFile(inputFile);
    return this.importKeyData(fileData, false);
  }

  /**
   * Import key(s) from a string
   *
   * @param {String} keyData:  the key data to be imported (ASCII armored)
   * @param {Boolean} minimizeKey: import the minimum key without any 3rd-party signatures
   * @param {Array of String} limitedUids: skip UIDs that were not specified
   *
   * @return {Object} or null in case no data / error:
   *   - {Number}          exitCode:        result code (0: OK)
   *   - {Array of String) importedKeys:    imported fingerprints
   *   - {Number}          importSum:       total number of processed keys
   *   - {Number}          importUnchanged: number of unchanged keys
   */

  async importKeyData(keyData, minimizeKey = false, limitedUids = []) {
    EnigmailLog.DEBUG(`gpgme.js: importKeyData(${keyData.length}, ${minimizeKey})\n`);

    let args = ["--no-verbose", "--status-fd", "2"];
    if (minimizeKey) {
      args = args.concat(["--import-options", "import-minimal"]);
    }

    if (limitedUids && limitedUids.length > 0 && this.supportsFeature("export-specific-uid")) {
      let filter = limitedUids.map(i => {
        return `mbox =~ ${i}`;
      }).join(" || ");

      args.push("--import-filter");
      args.push(`keep-uid=${filter}`);
    }
    args = args.concat(["--no-auto-check-trustdb", "--import"]);

    const res = await EnigmailExecution.execAsync(this._gpgPath, args, keyData);

    let importedKeys = [];
    let importSum = 0;
    let importUnchanged = 0;
    let secCount = 0;
    let secImported = 0;
    let secDups = 0;

    if (res.statusMsg) {
      let r = parseImportResult(res.statusMsg);
      if (r.exitCode !== -1) {
        res.exitCode = r.exitCode;
      }
      if (r.errorMsg !== "") {
        res.errorMsg = r.errorMsg;
      }

      importedKeys = r.importedKeys;
      importSum = r.importSum;
      importUnchanged = r.importUnchanged;
      secCount = r.secCount;
      secImported = r.secImported;
      secDups = r.secDups;
    }

    return {
      exitCode: res.exitCode,
      errorMsg: res.errorMsg,
      importedKeys: importedKeys,
      importSum: importSum,
      importUnchanged: importUnchanged,
      secCount: secCount,
      secImported: secImported,
      secDups: secDups
    };
  }

  /**
   * Delete keys from keyring
   *
   * @param {Array<String>} fpr: fingerprint(s) to delete
   * @param {Boolean} deleteSecretKey: if true, also delete secret keys
   * @param {nsIWindow} parentWindow: parent window for displaying modal dialogs
   *
   * @return {Promise<Object>}:
   *      - {Number} exitCode: 0 if successful, other values indicate error
   *      - {String} errorMsg: error message if deletion not successful
   */
  async deleteKeys(fpr, deleteSecretKey, parentWindow) {
    EnigmailLog.DEBUG(`gpgme.js: deleteKeys(${fpr.join("+")}, ${deleteSecretKey})\n`);
    let args = ["--no-verbose", "--status-fd", "2", "--batch", "--yes"];

    if (deleteSecretKey) {
      args.push("--delete-secret-and-public-key");
    }
    else {
      args.push("--delete-keys");
    }

    args = args.concat(fpr);
    const res = await EnigmailExecution.execAsync(this._gpgPath, args, "");
    const deletedKeys = [];

    let lines = res.statusMsg.split(/[\r\n]+/);
    for (let l of lines) {
      if (l.search(/^KEY_CONSIDERED /) === 0) {
        deletedKeys.push(l.split(/ /)[1]);
      }
    }

    let exitCode = (deletedKeys.length >= fpr.length) ? 0 : 1;

    return {
      exitCode: exitCode,
      errorMsg: exitCode !== 0 ? res.errorMsg : ""
    };
  }

  /**
   * Export the minimum key for the public key object:
   * public key, user ID, newest encryption subkey
   *
   * @param {String} fpr  : a single FPR
   * @param {String} email: [optional] the email address of the desired user ID.
   *                        If the desired user ID cannot be found or is not valid, use the primary UID instead
   * @param {Array<Number>} subkeyDates: [optional] remove subkeys with sepcific creation Dates
   *
   * @return {Promise<Object>}:
   *    - exitCode (0 = success)
   *    - errorMsg (if exitCode != 0)
   *    - keyData: BASE64-encded string of key data
   */
  async getMinimalPubKey(fpr, email, subkeyDates) {
    return exportKeyFromGnuPG(this._gpgPath, fpr, false, false, true, email, subkeyDates);
  }

  /**
   * Export secret key(s) as ASCII armored data
   *
   * @param {String}  keyId       Specification by fingerprint or keyID, separate mutliple keys with spaces
   * @param {Boolean} minimalKey  if true, reduce key to minimum required
   *
   * @return {Object}:
   *   - {Number} exitCode:  result code (0: OK)
   *   - {String} keyData:   ASCII armored key data material
   *   - {String} errorMsg:  error message in case exitCode !== 0
   */

  async extractSecretKey(keyId, minimalKey = false) {
    return exportKeyFromGnuPG(this._gpgPath, keyId, true, true, minimalKey);
  }

  /**
   * Export public key(s) as ASCII armored data
   *
   * @param {String}  keyId       Specification by fingerprint or keyID, separate mutliple keys with spaces
   *
   * @return {Object}:
   *   - {Number} exitCode:  result code (0: OK)
   *   - {String} keyData:   ASCII armored key data material
   *   - {String} errorMsg:  error message in case exitCode !== 0
   */

  async extractPublicKey(keyId) {
    return exportKeyFromGnuPG(this._gpgPath, keyId, false, true, false);
  }

  /**
   * Generate a new key pair
   *
   * @param {String} name:       name part of UID
   * @param {String} comment:    comment part of UID (brackets are added)
   * @param {String} email:      email part of UID (<> will be added)
   * @param {Number} expiryDate: number of days after now; 0 if no expiry
   * @param {Number} keyLength:  size of key in bytes (not supported in this API)
   * @param {String} keyType:    'RSA' or 'ECC'
   * @param {String} passphrase: password; use null if no password (not supported in this API)
   *
   * @return {Object}: Handle to key creation
   *    - {function} cancel(): abort key creation
   *    - {Promise<exitCode, generatedKeyId>} promise: resolved when key creation is complete
   *                 - {Number} exitCode:       result code (0: OK)
   *                 - {String} generatedKeyId: generated key ID
   */

  generateKey(name, comment, email, expiryDate = 0, keyLength, keyType, passphrase) {
    EnigmailLog.DEBUG(`gpgme.js: generateKey(${name}, ${email}, ${expiryDate}, ${keyType})\n`);
    let canceled = false;

    let promise = new Promise((resolve, reject) => {
      let uid = (name + (comment ? ` (${comment})` : "") + (email ? ` <${email}>` : "")).trim();
      this.execJsonCmd({
        op: "createkey",
        userid: uid,
        algo: (keyType === "RSA" ? "default" : "future-default"),
        expires: expiryDate * 86400
      }).then(async (result) => {
        if ("fingerprint" in result) {
          resolve({
            exitCode: 0,
            generatedKeyId: "0x" + result.fingerprint
          });
        }
        else {
          let r = getErrorMessage(result.code);
          reject(r.errorMessage);
        }

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
    let r = await this.decrypt(byteData, {
      noOutput: true
    });

    if (r.exitCode === 0) {
      return r.encryptedFileName;
    }
    return null;
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
    let dataFile = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
    let sigFile = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
    EnigmailFiles.initPath(dataFile, filePath);
    EnigmailFiles.initPath(sigFile, sigPath);

    if (!dataFile.exists()) {
      throw new Error(`Data file ${filePath} does not exist`);
    }
    if (!sigFile.exists()) {
      throw new Error(`Signature file ${sigPath} does not exist`);
    }

    let data = EnigmailFiles.readBinaryFile(dataFile);
    let sig = EnigmailFiles.readBinaryFile(sigFile);

    let r = await this.verifyMime(data, sig, null);
    if (r.statusFlags & (EnigmailConstants.BAD_SIGNATURE | EnigmailConstants.UNVERIFIED_SIGNATURE)) {
      throw r.errorMsg ? r.errorMsg : EnigmailLocale.getString("unverifiedSig") + " - " + EnigmailLocale.getString("msgSignedUnkownKey");
    }

    const detailArr = r.sigDetails.split(/ /);
    const dateTime = EnigmailTime.getDateTime(detailArr[2], true, true);
    return r.errorMsg + "\n" + EnigmailLocale.getString("keyAndSigDate", [r.keyId, dateTime]);
  }

  /**
   * Decrypt an attachment.
   *
   * @param {Bytes}  encrypted     The encrypted data
   *
   * @return {Promise<Object>} - Return object with decryptedData and
   * status information
   *
   * Use Promise.catch to handle failed decryption.
   * retObj.errorMsg will be an error message in this case.
   */

  async decryptAttachment(encrypted) {
    let r = await this.decrypt(encrypted, {});
    r.stdoutData = r.decryptedData;
    delete r.decryptedData;
    return r;
  }

  /**
   * Generic function to decrypt and/or verify an OpenPGP message.
   *
   * @param {String} encrypted     The encrypted data
   * @param {String} encrypted     The encrypted data
   * @param {Object} options       Decryption options
   *      - logFile (the actual file)
   *      - keyserver
   *      - keyserverProxy
   *      - fromAddr
   *      - noOutput
   *      - verifyOnly
   *      - uiFlags
   *      - mimeSignatureFile
   *      - maxOutputLength
   *
   * @return {Promise<Object>} - Return object with decryptedData and status information:
   *     - {String} decryptedData
   *     - {Number} exitCode
   *     - {Number} statusFlags
   *     - {String} errorMsg
   *     - {String} blockSeparation
   *     - {String} userId: signature user Id
   *     - {String} keyId: signature key ID
   *     - {String} sigDetails: as printed by GnuPG for VALIDSIG pattern
   *     - {String} encToDetails: \n  keyId1 (userId1),\n  keyId1 (userId2),\n  ...
   *     - {String} encryptedFileName
   *
   * Use Promise.catch to handle failed decryption.
   * retObj.errorMsg will be an error message in this case.
   */

  async decrypt(encrypted, options) {
    EnigmailLog.DEBUG(`gpgme.js: decrypt()\n`);

    let result = await this.execJsonCmd({
      op: options.verifyOnly ? "verify" : "decrypt",
      data: btoa(encrypted),
      base64: true
    });

    EnigmailLog.DEBUG(`gpgme.js: decrypt: result.type: ${result.type}\n`);
    let ret = {
      decryptedData: "",
      exitCode: 1,
      statusFlags: 0,
      errorMsg: "err",
      blockSeparation: "",
      userId: "",
      keyId: "",
      sigDetails: "",
      encToDetails: ""
    };

    if (result.type === "plaintext") {
      ret.errorMsg = "";
      ret.decryptedData = result.base64 ? atob(result.data) : result.data;
      if (options.uiFlags & EnigmailConstants.UI_PGP_MIME) {
        ret.statusFlags |= EnigmailConstants.PGP_MIME_ENCRYPTED;
      }

      if ("dec_info" in result) {
        if (!result.dec_info.wrong_key_usage && result.dec_info.symkey_algo.length > 0) {
          ret.statusFlags += EnigmailConstants.DECRYPTION_OKAY;
          if (result.dec_info.legacy_cipher_nomdc) ret.statusFlags += EnigmailConstants.MISSING_MDC;
        }

        if (result.dec_info.file_name) ret.encryptedFileName = result.dec_info.file_name;

        if ("recipients" in result.dec_info) {
          let encToArr = [];
          for (let r of result.dec_info.recipients) {
            // except for ID 00000000, which signals hidden keys
            if (r.keyid.search(/^0+$/) < 0) {
              let localKey = EnigmailKeyRing.getKeyById(`0x${r.keyid}`);
              encToArr.push(r.keyid + (localKey ? ` (${localKey.userId})` : ""));
            }
            else {
              encToArr.push(EnigmailLocale.getString("hiddenKey"));
            }
          }
          ret.encToDetails = "\n  " + encToArr.join(",\n  ") + "\n";
        }
      }

      if ("info" in result) {
        await this._interpetSignatureData(result, ret);
      }
      ret.exitCode = 0;
    }
    else {
      EnigmailLog.DEBUG(`gpgme.js: decrypt: result= ${JSON.stringify(result)}\n`);

      let r = getErrorMessage(result.code);
      ret.errorMsg = r.errorMessage;
      ret.exitCode = 1;
      ret.statusFlags = r.statusFlags | EnigmailConstants.DECRYPTION_FAILED;
    }

    return ret;
  }

  /**
   * Decrypt a PGP/MIME-encrypted message
   *
   * @param {String} encrypted     The encrypted data
   * @param {Object} options       Decryption options (see decrypt() for details)
   *
   * @return {Promise<Object>} - Return object with decryptedData and status information
   *                             (see decrypt() for details)
   *
   * Use Promise.catch to handle failed decryption.
   * retObj.errorMsg will be an error message in this case.
   */

  async decryptMime(encrypted, options) {
    options.noOutput = false;
    options.verifyOnly = false;
    options.uiFlags = EnigmailConstants.UI_PGP_MIME;

    return this.decrypt(encrypted, options);
  }

  /**
   * Verify a PGP/MIME-signed message
   *
   * @param {String} signedData    The signed data
   * @param {String} signature     The signature data
   * @param {Object} options       Decryption options
   *
   * @return {Promise<Object>} - Return object with decryptedData and
   *                             status information
   *
   * Use Promise.catch to handle failed decryption.
   * retObj.errorMsg will be an error message in this case.
   */

  async verifyMime(signedData, signature, options) {
    EnigmailLog.DEBUG(`gpgme.js: verifyMime()\n`);
    let result = await this.execJsonCmd({
      op: "verify",
      data: btoa(signedData),
      signature: btoa(signature),
      base64: true
    });

    let ret = {};

    if ("info" in result) {
      await this._interpetSignatureData(result, ret);
    }
    else {
      EnigmailLog.DEBUG(`gpgme.js: verifyMime: result.type: ${result.type}\n`);
      ret.errorMsg = result.msg;
      ret.statusFlags = EnigmailConstants.DECRYPTION_FAILED;
    }

    return ret;
  }

  /**
   * private function to resd/intperet the signature data returned by gpgme
   */
  async _interpetSignatureData(resultData, retObj) {
    if (!retObj) return;
    if (!("info" in resultData)) return;
    if (resultData.info.signatures.length < 1) return;

    const
      undetermined = 0,
      none = 1,
      keyMissing = 2,
      red = 3,
      green = 4,
      valid = 99;

    let overallSigStatus = undetermined,
      iSig = null;

    // determine "best" signature
    for (let sig of resultData.info.signatures) {
      let s = sig.summary;
      let sigStatus = s.valid ? valid : s.green ? green : s.red ? red : s["key-misssing"] ? keyMissing : none;
      if (sigStatus > overallSigStatus) {
        overallSigStatus = sigStatus;
        iSig = sig;
      }
    }

    // interpret the "best" signature
    if (iSig) {
      if (iSig.summary.red) {
        retObj.statusFlags |= EnigmailConstants.BAD_SIGNATURE;
      }
      else if (iSig.summary["key-missing"]) {
        retObj.statusFlags |= (EnigmailConstants.UNVERIFIED_SIGNATURE | EnigmailConstants.NO_PUBKEY);
      }
      else {
        retObj.statusFlags |= EnigmailConstants.GOOD_SIGNATURE;
        if (iSig.summary.valid) retObj.statusFlags |= EnigmailConstants.TRUSTED_IDENTITY;
        if (iSig.summary.revoked) retObj.statusFlags |= EnigmailConstants.REVOKED_KEY;
        if (iSig.summary["key-expired"]) retObj.statusFlags |= (EnigmailConstants.EXPIRED_KEY | EnigmailConstants.EXPIRED_KEY_SIGNATURE);
        if (iSig.summary["sig-expired"]) retObj.statusFlags |= EnigmailConstants.EXPIRED_SIGNATURE;
      }

      if (iSig.fingerprint) {
        retObj.keyId = iSig.fingerprint;
        // use gpgme to find key, as fpr may not be available via API
        let keys = await this.getKeys(`0x${iSig.fingerprint}`);
        if (keys && keys.length > 0) {
          if (retObj.statusFlags & EnigmailConstants.GOOD_SIGNATURE) {
            retObj.errorMsg = EnigmailLocale.getString("prefGood", [keys[0].userId]);
          }
          else if (retObj.statusFlags & EnigmailConstants.BAD_SIGNATURE) {
            retObj.errorMsg = EnigmailLocale.getString("prefBad", [keys[0].userId]);
          }
          retObj.userId = keys[0].userId;
        }
        else {
          keys = null;
        }

        let sigDate = new Date(iSig.timestamp * 1000).toISOString().substr(0, 10);
        /*  VALIDSIG args are (separated by space):
            - <fingerprint_in_hex> 4F9F89F5505AC1D1A260631CDB1187B9DD5F693B
            - <sig_creation_date> 2020-03-21
            - <sig-timestamp> 1584805187
            - <expire-timestamp> 0
            - <sig-version> 4
            - <reserved> 0
            - <pubkey-algo> 1
            - <hash-algo> 8
            - <sig-class> 00
            - [ <primary-key-fpr> ] 4F9F89F5505AC1D1A260631CDB1187B9DD5F693B
        */
        retObj.sigDetails = `${iSig.fingerprint} ${sigDate} ${iSig.timestamp} ${iSig.exp_timestamp} 4 0 ${iSig.pubkey_algo_name} ${iSig.hash_algo_name} 00 ${keys ? keys[0].fpr : ""}`;
      }
    }
  }

  /**
   * Get details (key ID, UID) of the data contained in a OpenPGP key block
   *
   * @param {String} keyBlockStr  String: the contents of one or more public keys
   *
   * @return {Promise<Array>}: array of objects with the following structure:
   *          - id (key ID)
   *          - fpr
   *          - name (the UID of the key)
   */

  async getKeyListFromKeyBlock(keyBlockStr) {
    EnigmailLog.DEBUG(`gpgme.js: getKeyListFromKeyBlock()\n`);

    const args = ["--no-tty", "--batch", "--no-verbose", "--with-fingerprint", "--with-colons", "--import-options", "import-show", "--dry-run", "--import"];
    const ENTRY_ID = 0;
    const KEY_ID = 4;
    const CREATED_ID = 5;
    const USERID_ID = 9;


    let res = await EnigmailExecution.execAsync(this._gpgPath, args, keyBlockStr);
    let lines = res.stdoutData.split(/\n/);

    let key = {};
    let keyId = "";
    let keyList = [];

    for (let i = 0; i < lines.length; i++) {
      const lineTokens = lines[i].split(/:/);

      switch (lineTokens[ENTRY_ID]) {
        case "pub":
        case "sec":
          key = {
            id: lineTokens[KEY_ID],
            fpr: null,
            name: null,
            isSecret: false,
            created: EnigmailTime.getDateTime(lineTokens[CREATED_ID], true, false),
            uids: []
          };

          if (!(key.id in keyList)) {
            keyList[key.id] = key;
          }

          if (lineTokens[ENTRY_ID] === "sec") {
            keyList[key.id].isSecret = true;
          }
          break;
        case "fpr":
          if (!key.fpr) {
            key.fpr = lineTokens[USERID_ID];
          }
          break;
        case "uid":
          if (!key.name) {
            key.name = lineTokens[USERID_ID];
          }
          else {
            key.uids.push(lineTokens[USERID_ID]);
          }
          break;
        case "rvs":
        case "rvk":
          keyId = lineTokens[KEY_ID];
          if (keyId in keyList) {
            keyList[keyId].revoke = true;
          }
          else {
            keyList[keyId] = {
              revoke: true,
              id: keyId
            };
          }
          break;
      }
    }

    return keyList;
  }


  /**
   * Export the ownertrust database
   * @param {String or nsIFile} outputFile: Output file name or Object - or NULL if trust data
   *                                        should be returned as string
   *
   * @return {Object}:
   *          - ownerTrustData {String}: if outputFile is NULL, the key block data; "" if a file is written
   *          - exitCode {Number}: exit code
   *          - errorMsg {String}: error message
   */
  async getOwnerTrust(outputFile) {
    const DEFAULT_FILE_PERMS = 0o600;
    const GPG_ARGS = ["--no-tty", "--batch", "--no-verbose", "--export-ownertrust"];

    let res = await EnigmailExecution.execAsync(this._gpgPath, GPG_ARGS, "");
    let exitCode = res.exitCode;
    let errorMsg = res.errorMsg;

    if (outputFile) {
      if (!EnigmailFiles.writeFileContents(outputFile, res.stdoutData, DEFAULT_FILE_PERMS)) {
        exitCode = -1;
        errorMsg = EnigmailLocale.getString("fileWriteFailed", [outputFile]);
      }

      return {
        ownerTrustData: "",
        exitCode: exitCode,
        errorMsg: errorMsg
      };
    }

    return {
      ownerTrustData: res.stdoutData,
      exitCode: exitCode,
      errorMsg: errorMsg
    };

  }


  /**
   * Import the ownertrust database
   *
   * @param {String or nsIFile} inputFile: input file name or Object
   *
   * @return {Object}:
   *         - exitCode {Number}: exit code
   *         - errorMsg {String}: error message
   */
  async importOwnerTrust(inputFile) {
    const GPG_ARGS = ["--no-tty", "--batch", "--no-verbose", "--import-ownertrust"];
    let res = {
      exitCode: -1,
      errorMsg: ""
    };

    try {
      let trustData = EnigmailFiles.readFile(inputFile);
      res = await EnigmailExecution.execAsync(this._gpgPath, GPG_ARGS, trustData);
    }
    catch (ex) {}

    return res;
  }


  /**
   * Encrypt messages
   *
   * @param {String} from: keyID of sender/signer
   * @param {String} recipients: keyIDs or email addresses of recipients, separated by spaces
   * @param {String} hiddenRecipients: keyIDs or email addresses of hidden recipients (bcc), separated by spaces
   * @param {Number} encryptionFlags: Flags for Signed/encrypted/PGP-MIME etc.
   * @param {String} plainText: data to encrypt
   * @param {String} hashAlgorithm: [OPTIONAL] hash algorithm (ignored for this API)
   * @param {nsIWindow} parentWindow: [OPTIONAL] window on top of which to display modal dialogs
   *
   * @return {Object}:
   *     - {Number} exitCode:    0 = success / other values: error
   *     - {String} data:        encrypted data
   *     - {String} errorMsg:    error message in case exitCode !== 0
   *     - {Number} statusFlags: Status flags for result
   */

  async encryptMessage(from, recipients, hiddenRecipients, encryptionFlags, plainText, hashAlgorithm = null, parentWindow = null) {
    EnigmailLog.DEBUG(`gpgme.js: encryptMessage(${from}, ${recipients}, ${encryptionFlags}, ${plainText.length})\n`);
    let reqOp;

    if (encryptionFlags & EnigmailConstants.SEND_ENCRYPTED) {
      if (hiddenRecipients.length > 0) {
        recipients += " " + hiddenRecipients;
      }

      reqOp = {
        op: "encrypt",
        keys: (from + " " + recipients).split(/[ ,]+/),
        data: btoa(plainText),
        sender: from,
        base64: true,
        armor: true,
        'always-trust': encryptionFlags & EnigmailConstants.SEND_ALWAYS_TRUST ? true : false,
        mime: encryptionFlags & EnigmailConstants.SEND_PGP_MIME ? true : false
      };

      if (encryptionFlags & EnigmailConstants.SEND_SIGNED) {
        reqOp.signing_keys = from;
      }
    }
    else {
      reqOp = {
        op: "sign",
        keys: from,
        data: btoa(plainText),
        sender: from,
        base64: true,
        armor: true,
        mode: encryptionFlags & EnigmailConstants.SEND_PGP_MIME ? "detached" : "clearsign"
      };
    }
    let result = await this.execJsonCmd(reqOp);
    EnigmailLog.DEBUG(`gpgme.js: encryptMessage: result.type: ${result.type}\n`);

    if (result.type === "ciphertext" || result.type === "signature") {
      result.exitCode = 0;
      result.statusFlags = 0;
      if (result.base64) {
        result.data = atob(result.data);
      }
    }
    else {
      EnigmailLog.DEBUG(`gpgme.js: encryptMessage: result=${JSON.stringify(result)}\n`);

      let r = getErrorMessage(result.code);
      result.errorMsg = r.errorMessage;
      result.exitCode = 1;
      result.statusFlags = r.statusFlags;
      result.data = "";
    }

    return result;
  }

  /**
   * Clear any cached passwords
   *
   * @return {Boolean} true if successful, false otherwise
   */
  async clearPassphrase() {
    const input = "RELOADAGENT\n/bye\n";
    let gpgConnPath = resolveToolPath(this._gpgAgentPath, "gpg-connect-agent");

    let res = await EnigmailExecution.execAsync(gpgConnPath, [], input);
    return (res.stdoutData.search(/^ERR/m) < 0);
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
   *
   * @return: depending on featureName - Boolean unless specified differently:
   *    (true if feature is available / false otherwise)
   *   If the feature cannot be found, undefined is returned
   */
  supportsFeature(featureName) {
    let gpgVersion = this._gpgVersion;

    if (!gpgVersion || typeof(gpgVersion) !== "string" || gpgVersion.length === 0) {
      return undefined;
    }

    gpgVersion = gpgVersion.replace(/-.*$/, "");
    if (gpgVersion.search(/^\d+\.\d+/) < 0) {
      // not a valid version number
      return undefined;
    }

    switch (featureName) {
      case "search-keys-cmd":
        // returns a string
        return "save";
      case "handles-huge-keys":
        return EnigmailVersioning.greaterThanOrEqual(gpgVersion, "2.2.17");
      case "supports-sender":
      case "export-result":
      case "decryption-info":
      case "supports-wkd":
      case "export-specific-uid":
      case "supports-show-only":
      case "smartcard":
      case "uid-management":
      case "ownertrust":
      case "supports-dirmngr":
      case "supports-ecc-keys":
      case "socks-on-windows":
      case "supports-gpg-agent":
      case "genkey-no-protection":
        return true;
      case "keygen-passphrase":
      case "windows-photoid-bug":
        return false;
    }

    return undefined;
  }

  /**
   * Get a human readable version string
   *
   * @returns {String}
   */
  getVersionString() {
    return EnigmailLocale.getString("usingAgent", ["Gnupg / GpgME", this._gpgVersion]);
  }


  /**
   *
   * @param {String} trustCode
   * @return {String}   Localized label
   */
  getTrustLabel(trustCode) {
    let keyTrust = trustCode;
    switch (trustCode) {
      case '-':
        keyTrust = EnigmailLocale.getString("keyValid.unknown");
        break;
      case 'i':
        keyTrust = EnigmailLocale.getString("keyValid.invalid");
        break;
      case 'd':
      case 'D':
        keyTrust = EnigmailLocale.getString("keyValid.disabled");
        break;
      case 'r':
        keyTrust = EnigmailLocale.getString("keyValid.revoked");
        break;
      case 'e':
        keyTrust = EnigmailLocale.getString("keyValid.expired");
        break;
      case 'n':
        keyTrust = EnigmailLocale.getString("keyTrust.untrusted");
        break;
      case 'm':
        keyTrust = EnigmailLocale.getString("keyTrust.marginal");
        break;
      case 'f':
        keyTrust = EnigmailLocale.getString("keyTrust.full");
        break;
      case 'u':
        keyTrust = EnigmailLocale.getString("keyTrust.ultimate");
        break;
      default:
        keyTrust = "";
    }

    return keyTrust;
  }

  /**
   * Return the key management functions (sub-API)
   */
  getKeyManagement() {
    EnigmailKeyEditor.gpgPath = this._gpgPath;
    return EnigmailKeyEditor;
  }

  /**
   * Return the OpenPGP configuration directory (if any)
   *
   * @return {String}: config directory or null if none
   */
  getConfigDir() {
    if (!this._gpgConfPath) return null;

    const args = ["--list-dirs"];

    let result = this.sync(EnigmailExecution.execAsync(this._gpgConfPath, args, ""));

    let m = result.stdoutData.match(/^(homedir:)(.*)$/mi);
    if (m && m.length > 2) {
      return EnigmailData.convertGpgToUnicode(unescape(m[2]));
    }

    return null;
  }

  async execJsonCmd(paramsObj) {
    let jsonStr = JSON.stringify(paramsObj);
    EnigmailLog.DEBUG(`gpgme.js: execJsonCmd(${jsonStr.substr(0, 40)})\n`);
    let n = jsonStr.length;
    let result = await EnigmailExecution.execAsync(this._gpgmePath, [], convertNativeNumber(n) + jsonStr);

    try {
      if (!result.stdoutData) throw "no data";
      let retObj = JSON.parse(result.stdoutData.substr(4));
      return retObj;
    }
    catch (ex) {
      return {
        "error": result.stderrData
      };
    }
  }

  async getAgentMaxIdle() {
    EnigmailLog.DEBUG("gpgme.js: getAgentMaxIdle()\n");
    let maxIdle = -1;

    if (!this._gpgConfPath) return maxIdle;

    const DEFAULT = 7;
    const CFGVALUE = 9;

    let result = await EnigmailExecution.execAsync(this._gpgConfPath, ["--list-options", "gpg-agent"], "");
    const lines = result.stdoutData.split(/[\r\n]/);

    for (let i = 0; i < lines.length; i++) {
      EnigmailLog.DEBUG("gpgme.js: getAgentMaxIdle: line: " + lines[i] + "\n");

      if (lines[i].search(/^default-cache-ttl:/) === 0) {
        const m = lines[i].split(/:/);
        if (m[CFGVALUE].length === 0) {
          maxIdle = Math.round(m[DEFAULT] / 60);
        }
        else {
          maxIdle = Math.round(m[CFGVALUE] / 60);
        }

        break;
      }
    }
    return maxIdle;
  }

  async setAgentMaxIdle(idleMinutes) {
    EnigmailLog.DEBUG("gpgme.js: setAgentMaxIdle()\n");
    if (!this._gpgConfPath) return;

    const RUNTIME = 8;

    const stdinData = "default-cache-ttl:" + RUNTIME + ":" + (idleMinutes * 60) + "\n" +
      "max-cache-ttl:" + RUNTIME + ":" + (idleMinutes * 600) + "\n";

    let result = await EnigmailExecution.execAsync(this._gpgConfPath, ["--runtime", "--change-options", "gpg-agent"], stdinData);
    EnigmailLog.DEBUG("gpgme.js: setAgentMaxIdle.stdout: " + result.stdoutData + "\n");
  }

  async getMaxIdlePref() {
    let maxIdle = EnigmailPrefs.getPref("maxIdleMinutes");

    try {
      if (this._gpgConfPath) {
        const m = await this.getAgentMaxIdle();
        if (m > -1) maxIdle = m;
      }
    }
    catch (ex) {}

    return maxIdle;
  }

  async setMaxIdlePref(minutes) {
    EnigmailPrefs.setPref("maxIdleMinutes", minutes);
    try {
      await this.setAgentMaxIdle(minutes);
    }
    catch (ex) {}
  }
}


function getGpgMEApi() {
  return new GpgMECryptoAPI();
}


/**
 * Determine the location of the GnuPG executable
 *
 * @param env: Object: nsIEnvironment to use
 *
 * @return Object: nsIFile pointing to gpg, or NULL
 */
function resolvePath(env) {
  EnigmailLog.DEBUG("gpgme.js: resolvePath()\n");

  let toolName = EnigmailOS.isDosLike ? "gpgme-json.exe" : "gpgme-json";

  // Resolve relative path using PATH environment variable
  const envPath = env.get("PATH");
  let toolPath = EnigmailFiles.resolvePath(toolName, envPath, EnigmailOS.isDosLike);

  if (!toolPath && EnigmailOS.isDosLike) {
    // DOS-like systems: search for GPG in c:\gnupg, c:\gnupg\bin, d:\gnupg, d:\gnupg\bin
    let gpgPath = "c:\\gnupg;c:\\gnupg\\bin;d:\\gnupg;d:\\gnupg\\bin";
    toolPath = EnigmailFiles.resolvePath(toolName, gpgPath, EnigmailOS.isDosLike);
  }

  if ((!toolPath) && EnigmailOS.isWin32) {
    // Look up in Windows Registry
    const installDir = ["Software\\Gpg4win", "Software\\Wow6432Node\\Gpg4win"];
    const registryStores = [nsIWindowsRegKey.ROOT_KEY_LOCAL_MACHINE, nsIWindowsRegKey.ROOT_KEY_CURRENT_USER];

    try {
      for (let regStore of registryStores) {
        for (let i = 0; i < installDir.length && !toolPath; i++) {
          let gpgPath = EnigmailOS.getWinRegistryString(installDir[i], "Install Directory", regStore);

          toolPath = EnigmailFiles.resolvePath(toolName, gpgPath, EnigmailOS.isDosLike);
          if (!toolPath) {
            gpgPath += "\\bin";
            toolPath = EnigmailFiles.resolvePath(toolName, gpgPath, EnigmailOS.isDosLike);
          }
        }
      }
    }
    catch (ex) {}

    if (!toolPath) {
      // try to determine the default PATH from the registry after the installation
      // if we could not get any information from the registry
      try {
        let winPath = EnigmailOS.getWinRegistryString("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", "Path", nsIWindowsRegKey.ROOT_KEY_LOCAL_MACHINE);
        toolPath = EnigmailFiles.resolvePath(toolName, winPath, EnigmailOS.isDosLike);
      }
      catch (ex) {}
    }

    if (!toolPath) {
      // Default paths for gpg4win 3.x and 4.x
      let gpgPath = "C:\\Program Files\\GnuPG\\bin;C:\\Program Files (x86)\\GnuPG\\bin;C:\\Program Files\\Gpg4win\\bin;C:\\Program Files (x86)\\Gpg4win\\bin";
      toolPath = EnigmailFiles.resolvePath(toolName, gpgPath, EnigmailOS.isDosLike);
    }
  }

  if (!toolPath && !EnigmailOS.isDosLike) {
    // Unix-like systems: check /usr/bin and /usr/local/bin
    let gpgPath = "/usr/bin:/usr/local/bin";
    toolPath = EnigmailFiles.resolvePath(toolName, gpgPath, EnigmailOS.isDosLike);
  }

  if (!toolPath) {
    return null;
  }

  return toolPath.QueryInterface(Ci.nsIFile);
}

function resolveToolPath(parentPath, fileName) {
  let filePath = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);

  EnigmailFiles.initPath(filePath, parentPath);

  if (filePath) {
    // try to get the install directory of gpg/gpg2 executable
    filePath.normalize();
    filePath = filePath.parent;
  }

  if (filePath) {
    filePath.append(EnigmailFiles.potentialWindowsExecutable(fileName));
    if (filePath.exists()) {
      filePath.normalize();
      return filePath;
    }
  }

  return EnigmailFiles.resolvePathWithEnv(fileName);
}


function createKeyObj(keyData) {
  if (!("validity" in keyData)) {
    keyData.validity = "u";
  }

  let keyObj = {
    keyId: keyData.keyid ? keyData.keyid : keyData.fingerprint.substr(-16),
    expiryTime: 0,
    created: "",
    keyCreated: 0,
    keyUseFor: (keyData.can_sign ? "s" : "") + (keyData.can_encrypt ? "e" : "") + (keyData.can_certify ? "c" : "") + (keyData.can_authenticate ? "a" : "") +
      (keyData.secret ? (keyData.can_sign ? "S" : "") + (keyData.can_encrypt ? "E" : "") + (keyData.can_certify ? "C" : "") + (keyData.can_authenticate ? "A" : "") : ""),
    ownerTrust: VALIDITY_SYMBOL[keyData.owner_trust],
    keySize: 0,
    secretAvailable: keyData.secret,
    userIds: [],
    subKeys: [],
    fpr: keyData.fingerprint,
    photoAvailable: false,
    type: "pub",
    keyTrust: keyData.disabled ? "d" : keyData.revoked ? "r" : keyData.expired ? "e" : keyData.invalid ? "i" : VALIDITY_SYMBOL[keyData.owner_trust]
  };

  if (keyData.subkeys.length > 0) {
    keyObj.created = EnigmailTime.getDateTime(keyData.subkeys[0].timestamp, true, false);
    keyObj.keyCreated = keyData.subkeys[0].timestamp;
    keyObj.expiryTime = keyData.subkeys[0].expires;
    keyObj.algoSym = keyData.subkeys[0].pubkey_algo_name;
    keyObj.keySize = keyData.subkeys[0].length;

    for (let i = 1; i < keyData.subkeys.length; i++) {
      let s = keyData.subkeys[i];
      keyObj.subKeys.push({
        keyId: s.keyid,
        expiry: EnigmailTime.getDateTime(s.expires, true, false),
        expiryTime: s.expires,
        keyTrust: s.revoked ? "r" : s.expired ? "e" : s.disabled ? "d" : s.invalid ? "i" : "f",
        keyUseFor: (s.can_sign ? "s" : "") + (s.can_encrypt ? "e" : "") + (s.can_certify ? "c" : "") + (s.can_authenticate ? "a" : "") +
          (keyData.secret ? (s.can_sign ? "S" : "") + (s.can_encrypt ? "E" : "") + (s.can_certify ? "C" : "") + (s.can_authenticate ? "A" : "") : ""),
        keySize: s.length,
        algoSym: s.pubkey_algo_name,
        created: EnigmailTime.getDateTime(s.timestamp, true, false),
        keyCreated: s.timestamp,
        type: "sub"
      });
    }
  }

  if (keyData.userids.length > 0) {
    keyObj.userId = EnigmailData.convertGpgToUnicode(keyData.userids[0].uid);

    for (let u of keyData.userids) {
      keyObj.userIds.push({
        userId: EnigmailData.convertGpgToUnicode(u.uid),
        keyTrust: VALIDITY_SYMBOL[u.validity],
        uidFpr: "0",
        type: "uid"
      });
    }
  }

  return keyObj;
}


function convertNativeNumber(num) {
  let s = String.fromCharCode(num & 0xFF) + String.fromCharCode((num >> 8) & 0xFF) + String.fromCharCode((num >> 16) & 0xFF) + String.fromCharCode((num >> 24) & 0xFF);
  return s;
}

/**
 * Parse GnuPG status output
 *
 * @param statusMsg
 */
function parseImportResult(statusMsg) {
  // IMPORT_RES <count> <no_user_id> <imported> 0 <unchanged>
  //    <n_uids> <n_subk> <n_sigs> <n_revoc> <sec_read> <sec_imported> <sec_dups> <not_imported>

  let import_res = statusMsg.match(/^IMPORT_RES ([0-9]+) ([0-9]+) ([0-9]+) 0 ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+)/m);

  let keyList = [];
  let res = {
    errorMsg: "",
    exitCode: -1,
    importedKeys: [],
    importSum: 0,
    importUnchanged: 0
  };

  if (import_res !== null) {
    let secCount = parseInt(import_res[9], 10); // number of secret keys found
    let secImported = parseInt(import_res[10], 10); // number of secret keys imported
    let secDups = parseInt(import_res[11], 10); // number of secret keys already on the keyring

    if (secCount !== secImported + secDups) {
      res.errorMsg = EnigmailLocale.getString("import.secretKeyImportError");
      res.exitCode = 1;
    }
    else {
      res.importSum = parseInt(import_res[1], 10);
      res.importUnchanged = parseInt(import_res[4], 10);
      res.secCount = parseInt(import_res[9], 10); // number of secret keys found
      res.secImported = parseInt(import_res[10], 10); // number of secret keys imported
      res.secDups = parseInt(import_res[11], 10); // number of secret keys already on the keyring

      res.exitCode = 0;
      var statusLines = statusMsg.split(/\r?\n/);

      for (let j = 0; j < statusLines.length; j++) {
        var matches = statusLines[j].match(/IMPORT_OK ([0-9]+) (\w+)/);
        if (matches && (matches.length > 2)) {
          if (typeof(keyList[matches[2]]) !== "undefined") {
            keyList[matches[2]] |= Number(matches[1]);
          }
          else
            keyList[matches[2]] = Number(matches[1]);

          res.importedKeys.push(matches[2]);
          EnigmailLog.DEBUG("gpgme.js: parseImportResult: imported " + matches[2] + ":" + matches[1] + "\n");
        }
      }
    }
  }

  return res;
}

async function determineGpgVersion(gpgPath) {
  EnigmailLog.DEBUG(`gpgme.js: determineGpgVersion(${gpgPath})\n`);
  const args = ["--batch", "--no-tty", "--charset", "utf-8", "--display-charset", "utf-8", "--version", "--version"];

  const res = await EnigmailExecution.execAsync(gpgPath, args);

  if (res.exitCode !== 0) {
    EnigmailLog.ERROR(`gpgme.js: determineGpgVersion: gpg failed with exitCode ${res.exitCode} msg='${res.stdoutData} ${res.stderrData}'\n`);
    throw Components.results.NS_ERROR_FAILURE;
  }

  // detection for Gpg4Win wrapper
  if (res.stdoutData.search(/^gpgwrap.*;/) === 0) {
    const outLines = res.stdoutData.split(/[\n\r]+/);
    const firstLine = outLines[0];
    outLines.splice(0, 1);
    res.stdoutData = outLines.join("\n");
    gpgPath = firstLine.replace(/^.*;[ \t]*/, "");

    EnigmailLog.CONSOLE(`gpg4win-gpgwrapper detected; GnuPG path=${gpgPath}\n\n`);
  }

  const versionParts = res.stdoutData.replace(/[\r\n].*/g, "").replace(/ *\(gpg4win.*\)/i, "").split(/ /);
  const gpgVersion = versionParts[versionParts.length - 1];

  EnigmailLog.DEBUG(`gpgme.js: detected GnuPG version '${gpgVersion}'\n`);

  return {
    gpgVersion: gpgVersion,
    gpgPath: gpgPath
  };
}

function gpgUnescape(str) {
  let i = str.search(/%../);
  while (i >= 0) {
    let s = str.substr(i, 3);
    str = str.replace(s, unescape(s));
    i = str.search(/%../);
  }
  return str;
}


/**
 * Export Keys from GnuPG
 * @param {Object<nsIFile>} gpgPath: path to gpg executable
 * @param {String} keyId: list of keys separated by space
 * @param {Boolean} secretKey: if true, export secret key; if false export public key
 * @param {Boolean} minimalKey: if true, export a minimal key
 * @param {Boolean} asciiArmor: if true, export as ASCII armored data, otherwise as BASE64 binary data
 * @param {String} email: [optional] if set, only consider UIDs that match the given email address
 * @param {Array<Number>} subkeyDates: [optional] remove subkeys that don't match sepcific creation Dates
 *
 * @returns {Object}:
 *   - {Number} exitCode:  result code (0: OK)
 *   - {String} keyData:   ASCII armored key data material
 *   - {String} errorMsg:  error message in case exitCode !== 0
 */
async function exportKeyFromGnuPG(gpgPath, keyId, secretKey = false, asciiArmor = true, minimalKey = false, email, subkeyDates) {
  EnigmailLog.DEBUG(`gpgme.js: exportKeyFromGnuPG(${gpgPath}, ${keyId}, ${secretKey}, ${minimalKey})\n`);

  let args = ["--no-verbose", "--status-fd", "2", "--batch", "--yes"],
    exitCode = -1,
    errorMsg = "";

  if (asciiArmor) {
    args.push("-a");
  }

  if (minimalKey) {
    args.push("--export-options");
    args.push("export-minimal,no-export-attributes");
    args.push("--export-filter");
    args.push("keep-uid=" + (email ? "mbox=" + email : "primary=1"));

    // filter for specific subkeys
    let dropSubkeyFilter = "usage!~e && usage!~s";

    if (subkeyDates && subkeyDates.length > 0) {
      dropSubkeyFilter = subkeyDates.map(x => `key_created!=${x}`).join(" && ");
    }
    args = args.concat([
      "--export-filter", "drop-subkey=" + dropSubkeyFilter
    ]);
  }

  if (secretKey) {
    args.push("--export-secret-keys");
  }
  else {
    args.push("--export");
  }

  if (keyId) {
    args = args.concat(keyId.split(/[ ,\t]+/));
  }

  let res = await EnigmailExecution.execAsync(gpgPath, args, "");
  exitCode = res.exitCode;

  if (res.stdoutData) {
    exitCode = 0;
  }

  if (exitCode !== 0) {
    if (res.errorMsg) {
      errorMsg = EnigmailFiles.formatCmdLine(gpgPath, args);
      errorMsg += "\n" + res.errorMsg;
    }
  }

  if (!asciiArmor) {
    res.stdoutData = btoa(res.stdoutData);
  }

  return {
    keyData: res.stdoutData,
    exitCode: exitCode,
    errorMsg: errorMsg
  };
}

const GPG_SOURCE_SYSTEM = {
  GPG_ERR_SOURCE_UNKNOWN: 0,
  GPG_ERR_SOURCE_GCRYPT: 1,
  GPG_ERR_SOURCE_GPG: 2,
  GPG_ERR_SOURCE_GPGSM: 3,
  GPG_ERR_SOURCE_GPGAGENT: 4,
  GPG_ERR_SOURCE_PINENTRY: 5,
  GPG_ERR_SOURCE_SCD: 6,
  GPG_ERR_SOURCE_GPGME: 7,
  GPG_ERR_SOURCE_KEYBOX: 8,
  GPG_ERR_SOURCE_KSBA: 9,
  GPG_ERR_SOURCE_DIRMNGR: 10,
  GPG_ERR_SOURCE_GSTI: 11,
  GPG_ERR_SOURCE_GPA: 12,
  GPG_ERR_SOURCE_KLEO: 13,
  GPG_ERR_SOURCE_G13: 14,
  GPG_ERR_SOURCE_ASSUAN: 15,
  GPG_ERR_SOURCE_TLS: 17,
  GPG_ERR_SOURCE_ANY: 31
};

function getErrorMessage(errorNum) {
  const sourceSystem = errorNum >> 24;
  const errorCode = errorNum & 0xFFFFFF;

  let errorMessage = "";
  let statusFlags = 0;

  switch (errorCode) {
    case 32870: // error no tty
      if (sourceSystem === GPG_SOURCE_SYSTEM.GPG_ERR_SOURCE_PINENTRY) {
        errorMessage = EnigmailLocale.getString("errorHandling.pinentryCursesError") + "\n\n" + EnigmailLocale.getString("errorHandling.readFaq");
        statusFlags = EnigmailConstants.DISPLAY_MESSAGE;
      }
      break;
    case 11: // bad Passphrase
    case 87: // bad PIN
      errorMessage = EnigmailLocale.getString("badPhrase");
      statusFlags = EnigmailConstants.BAD_PASSPHRASE;
      break;
    case 177: // no passphrase
    case 178: // no PIN
      errorMessage = EnigmailLocale.getString("missingPassphrase");
      statusFlags = EnigmailConstants.MISSING_PASSPHRASE;
      break;
    case 99: // operation canceled
      if (sourceSystem === GPG_SOURCE_SYSTEM.GPG_ERR_SOURCE_PINENTRY) {
        errorMessage = EnigmailLocale.getString("missingPassphrase");
        statusFlags = EnigmailConstants.MISSING_PASSPHRASE;
      }
      break;
    case 77: // no agent
    case 78: // agent error
    case 80: // assuan server fault
    case 81: // assuan error
      errorMessage = EnigmailLocale.getString("errorHandling.gpgAgentError") + "\n\n" + EnigmailLocale.getString("errorHandling.readFaq");
      statusFlags = EnigmailConstants.DISPLAY_MESSAGE;
      break;
    case 85: // no pinentry
    case 86: // pinentry error
      errorMessage = EnigmailLocale.getString("errorHandling.pinentryError") + "\n\n" + EnigmailLocale.getString("errorHandling.readFaq");
      statusFlags = EnigmailConstants.DISPLAY_MESSAGE;
      break;
    case 92: // no dirmngr
    case 93: // dirmngr error
      errorMessage = EnigmailLocale.getString("errorHandling.dirmngrError") + "\n\n" + EnigmailLocale.getString("errorHandling.readFaq");
      statusFlags = EnigmailConstants.DISPLAY_MESSAGE;
      break;
    case 2:
    case 3:
    case 149:
    case 188:
      statusFlags = EnigmailConstants.UNKNOWN_ALGO;
      break;
    case 15:
      statusFlags = EnigmailConstants.BAD_ARMOR;
      break;
    case 58:
      statusFlags = EnigmailConstants.NODATA;
      break;
  }

  return {
    errorMessage: errorMessage,
    statusFlags: statusFlags
  };
}
