/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

"use strict";

const Services = ChromeUtils.import("resource://gre/modules/Services.jsm").Services;
const EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
const EnigmailPrefs = ChromeUtils.import("chrome://enigmail/content/modules/prefs.jsm").EnigmailPrefs;
const EnigmailFiles = ChromeUtils.import("chrome://enigmail/content/modules/files.jsm").EnigmailFiles;
const EnigmailArmor = ChromeUtils.import("chrome://enigmail/content/modules/armor.jsm").EnigmailArmor;
const EnigmailLocale = ChromeUtils.import("chrome://enigmail/content/modules/locale.jsm").EnigmailLocale;
const EnigmailTime = ChromeUtils.import("chrome://enigmail/content/modules/time.jsm").EnigmailTime;
const EnigmailConstants = ChromeUtils.import("chrome://enigmail/content/modules/constants.jsm").EnigmailConstants;
const pgpjs_keys = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-keys.jsm").pgpjs_keys;
const pgpjs_keyStore = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-keystore.jsm").pgpjs_keyStore;
const getOpenPGPLibrary = ChromeUtils.import("chrome://enigmail/content/modules/stdlib/openpgp-loader.jsm").getOpenPGPLibrary;

var EXPORTED_SYMBOLS = ["pgpjs_crypto"];

var pgpjs_crypto = {
  /**
   * Process an OpenPGP message
   *
   * @param {String} encrypted     The encrypted data
   * @param {Object} options       Decryption options
   *
   * @return {Promise<Object>} - Return object with decryptedData and status information:
   *     - {String} decryptedData
   *     - {Number} exitCode
   *     - {Number} statusFlags
   *     - {String} errorMsg
   *     - {String} blockSeparation
   *
   * Use Promise.catch to handle failed decryption.
   * retObj.errorMsg will be an error message in this case.
   */

  processPgpMessage: async function(encrypted, options) {
    EnigmailLog.DEBUG(`pgpjs-crypro-main.jsm: processPgpMessage(${encrypted.length})\n`);

    let result;
    try {
      result = await PgpJsWorkerParent.sendMessage("processPgpMessage", {
        encrypted,
        options
      });
    }
    catch (ex) {
      EnigmailLog.DEBUG(`pgpjs-crypto-main.jsm: processPgpMessage: ERROR: ${ex.toString()}\n`);
      result.errorMsg = ex.toString();
      result.exitCode = 1;
    }

    return this.prepareResultText(result);
  },

  verify: async function(data, options) {
    EnigmailLog.DEBUG(`pgpjs-crypto-main.jsm: verify(${data.length})\n`);

    let result = {
      statusFlags: 0,
      exitCode: 1,
      decryptedData: ""
    };

    let blocks = EnigmailArmor.locateArmoredBlocks(data);

    try {
      if (blocks && blocks.length > 0) {
        if (blocks[0].blocktype === "SIGNED MESSAGE") {
          result = await PgpJsWorkerParent.sendMessage("verify", {
            data: data.substring(blocks[0].begin, blocks[0].end),
            options
          });
        }
      }
    }
    catch (ex) {
      EnigmailLog.DEBUG(`pgpjs-crypto-main.jsm: verify: ERROR: ${ex.toString()}\n`);
      result.errorMsg = ex.toString();
      result.statusFlags = EnigmailConstants.UNVERIFIED_SIGNATURE;
    }
    return this.prepareResultText(result);
  },

  verifyDetached: async function(data, signature, returnData = false) {
    EnigmailLog.DEBUG(`pgpjs-crypto-main.jsm: verifyDetached(${data.length})\n`);

    let result = await PgpJsWorkerParent.sendMessage("verifyDetached", {
      data,
      signature,
      returnData
    });
    return this.prepareResultText(result);
  },


  verifyFile: async function(dataFilePath, signatureFilePath) {
    const PgpJS = getOpenPGPLibrary();

    let dataFile = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
    let sigFile = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
    EnigmailFiles.initPath(dataFile, dataFilePath);
    EnigmailFiles.initPath(sigFile, signatureFilePath);

    if (!dataFile.exists()) {
      throw new Error(`Data file ${dataFilePath} does not exist`);
    }
    if (!sigFile.exists()) {
      throw new Error(`Signature file ${signatureFilePath} does not exist`);
    }

    let data = EnigmailFiles.readBinaryFile(dataFile);
    let sig = EnigmailFiles.readBinaryFile(sigFile);

    if (sig.search(/^-----BEGIN PGP/m) < 0) {
      let msg = await PgpJS.signature.read(ensureUint8Array(sig));
      sig = msg.armor();
    }

    let ret = await this.verifyDetached(data, sig, false);

    ret = this.prepareResultText(ret);

    if (ret.statusFlags & (EnigmailConstants.BAD_SIGNATURE | EnigmailConstants.UNVERIFIED_SIGNATURE)) {
      throw ret.errorMsg ? ret.errorMsg : EnigmailLocale.getString("unverifiedSig") + " - " + EnigmailLocale.getString("msgSignedUnkownKey");
    }

    const detailArr = ret.sigDetails.split(/ /);
    const dateTime = EnigmailTime.getDateTime(detailArr[2], true, true);
    return ret.errorMsg + "\n" + EnigmailLocale.getString("keyAndSigDate", [ret.keyId, dateTime]);
  },

  /**
   * Encrypt (and possibly sign) some text data
   *
   * @param {String} text:             The data to encrypt.
   * @param {Array<Key>} publicKeys:   Array of keys to which to encrypt the message
   * @param {Key} signingKey:          If provided, the message will be signed using that key.
   *                                   If null, message will not be signed.
   */
  encryptData: async function(text, publicKeys, signingKey) {
    EnigmailLog.DEBUG(`pgpjs-crypto-main.jsm: encryptData(${text.length})\n`);
    const PgpJS = getOpenPGPLibrary();

    let publicKeyPackets = new PgpJS.PacketList();
    publicKeyPackets = publicKeyPackets.concat(await publicKeys.toPacketList());
    let armoredPk = PgpJS.armor(PgpJS.enums.armor.publicKey, publicKeyPackets.write());

    let armoredSk = null;

    if (signingKey) {
      let signingKeyPackets = new PgpJS.PacketList();
      signingKeyPackets = signingKeyPackets.concat(await signingKey.toPacketList());
      armoredSk = PgpJS.armor(PgpJS.enums.armor.privateKey, signingKeyPackets.write());
    }

    let result = await PgpJsWorkerParent.sendMessage("encryptData", {
      text,
      encryptionKeys: armoredPk,
      signingKeys: armoredSk
    });

    return result;
  },

  /**
   * Sign some text data
   *
   * @param {String} text:                The data to sign.
   * @param {Key} signingKey:             The key used to sign the text.
   * @param {Boolean} detachedSignature:  Create a detached signature (true) or clearsigned message (false).
   */
  signData: async function(text, signingKey, detachedSignature) {
    EnigmailLog.DEBUG(`pgpjs-crypto-main.jsm: signData(${text.length})\n`);
    const PgpJS = getOpenPGPLibrary();


    let signingKeyPackets = new PgpJS.PacketList();
    signingKeyPackets = signingKeyPackets.concat(await signingKey.toPacketList());
    let armoredSk = PgpJS.armor(PgpJS.enums.armor.privateKey, signingKeyPackets.write());

    let result = await PgpJsWorkerParent.sendMessage("signData", {
      text,
      signingKeys: armoredSk,
      detachedSignature
    });

    return result;
  },

  prepareResultText: function(resultData) {
    if (resultData.statusMsg === "%MISSING_MDC") {
      resultData.statusMsg = EnigmailLocale.getString("missingMdcError") + "\n";
    }

    let m = resultData.errorMsg.match(/^%(GOOD_SIG|BAD_SIG):(.*)/);
    if (m && m.length >= 3) {
      let str = "";
      switch (m[1]) {
        case "GOOD_SIG":
          str = "prefGood";
          break;
        case "BAD_SIG":
          str = "prefBad";
          break;
      }

      resultData.errorMsg = EnigmailLocale.getString(str, [m[2]]);
    }

    return resultData;
  },

  loadConfig: async function() {
    const PgpJS = getOpenPGPLibrary();

    const allowWeakKeys = EnigmailPrefs.getPref("allowWeakKeys");

    if (allowWeakKeys) {
      PgpJS.config.rejectPublicKeyAlgorithms = new Set();
      PgpJS.config.minRSABits = 1024;
    }
    else {
      const ALGO = PgpJS.enums.publicKey;
      PgpJS.config.minRSABits = 2047;
      PgpJS.config.rejectPublicKeyAlgorithms = new Set([ALGO.elgamal, ALGO.dsa]);
    }

    await PgpJsWorkerParent.sendMessage("loadConfig", {
      allowWeakKeys: allowWeakKeys
    });
  }
};

function ensureUint8Array(stringOrUint8Array) {
  if (typeof stringOrUint8Array === "string") {

    const result = new Uint8Array(stringOrUint8Array.length);
    for (let i = 0; i < stringOrUint8Array.length; i++) {
      result[i] = stringOrUint8Array.charCodeAt(i);
    }
    return result;

  }

  return stringOrUint8Array;
}


/**
 * Callback functions called from worker for tasks requiring chrome
 */

var WorkerRequestHandler = {
  /**
   * Get secret keys as armored string
   *
   * @param {Array<String>} keyIds
   * @returns {String}
   */
  getSecretKeysForIds: async function(keyIds) {
    EnigmailLog.DEBUG(`pgpjs-crypto-main.jsm: getSecretKeysForIds()\n`);
    let secretKeys = await pgpjs_keyStore.readSecretKeys(keyIds, false);

    return secretKeys;
  },

  getPublicKeysForIds: async function(keyIds) {
    EnigmailLog.DEBUG(`pgpjs-crypto-main.jsm: getPublicKeysForIds()\n`);
    let publicKeys = await pgpjs_keyStore.readPublicKeys(keyIds);

    return publicKeys;
  },

  getDecryptedSecretKey: async function(options) {
    EnigmailLog.DEBUG(`pgpjs-crypto-main.jsm: getDecryptedSecretKey()\n`);
    const PgpJS = getOpenPGPLibrary();

    let secretKey = await pgpjs_keyStore.getKeysForKeyIds(true, [options.secretKeyFpr], false);
    let dedryptedSecKey = await pgpjs_keys.decryptSecretKey(secretKey[0], options.decryptionReason);
    let packets = new PgpJS.PacketList();

    // remove all 3rd-party signatures that just grow the key
    for (let u in dedryptedSecKey.users) {
      dedryptedSecKey.users[u].otherCertifications = [];
    }

    if (dedryptedSecKey) {
      packets = packets.concat(await dedryptedSecKey.toPacketList());
      return PgpJS.armor(PgpJS.enums.armor.privateKey, packets.write());
    }

    return "";
  },

  downloadMissingKeys: async function(keyIds) {
    EnigmailLog.DEBUG(`pgpjs-crypto-main.jsm: downloadMissingKeys()\n`);

    const EnigmailKeyServer = ChromeUtils.import("chrome://enigmail/content/modules/keyserver.jsm").EnigmailKeyServer;
    const PgpJS = getOpenPGPLibrary();
    let packets = new PgpJS.PacketList();

    try {
      const keyserver = EnigmailPrefs.getAutoKeyRetrieveServer();

      if (keyserver && keyserver.length > 0) {
        const keyList = "0x" + keyIds.join(" 0x");
        const ret = await EnigmailKeyServer.download(keyList, keyserver);

        if (ret.result === 0 && ret.keyList.length > 0) {
          let foundKeys = await pgpjs_keyStore.getKeysForKeyIds(false, keyIds);
          packets = packets.concat(await foundKeys.toPacketList());
        }
      }
    }
    catch (x) {}

    if (packets.length > 0) {
      return PgpJS.armor(PgpJS.enums.armor.publicKey, packets.write());
    }
    else
      return "";
  },

  getKeydesc: function(pubKeyIds) {
    EnigmailLog.DEBUG(`pgpjs-crypto-main.jsm: getKeydesc()\n`);
    const EnigmailKeyRing = ChromeUtils.import("chrome://enigmail/content/modules/keyRing.jsm").EnigmailKeyRing;

    if (pubKeyIds.length > 0) {
      let encToArray = [];
      // for each key also show an associated user ID if known:
      for (let keyId of pubKeyIds) {
        // except for ID 00000000, which signals hidden keys
        if (keyId.search(/^0+$/) < 0) {
          let localKey = EnigmailKeyRing.getKeyById("0x" + keyId);
          if (localKey) {
            encToArray.push(`0x${keyId} (${localKey.userId})`);
          }
          else {
            encToArray.push(`0x${keyId}`);
          }
        }
        else {
          encToArray.push(EnigmailLocale.getString("hiddenKey"));
        }
      }
      return "\n  " + encToArray.join(",\n  ") + "\n";
    }

    return "";
  }
};

var pendingPromises = [];
var gTransactionId = 0;

const cryptoWorker = new Worker('chrome://enigmail/content/modules/cryptoAPI/pgpjs-crypto-worker.js');

cryptoWorker.onmessage = async function(e) {
  if ("logMessage" in e.data) {
    if (e.data.logLevel >= 5) {
      EnigmailLog.DEBUG(`${e.data.logMessage}\n`);
    }
    else if (e.data.logLevel === 0) {
      EnigmailLog.ERROR(`${e.data.logMessage}\n`);
    }
    return;
  }

  if (!("trxId" in e.data)) {
    EnigmailLog.ERROR(`pgpjs-crypto-worker.jsm. onmessage: cannot deliver message received from worker ${e.data}\n`);
  }

  if ("func" in e.data) {
    let method = e.data.func;
    let args = e.data.param || null;

    if (method in WorkerRequestHandler) {
      try {
        let workerResult = await WorkerRequestHandler[method](args);
        cryptoWorker.postMessage({
          trxId: e.data.trxId,
          result: workerResult
        });
      }
      catch (ex) {
        cryptoWorker.postMessage({
          trxId: e.data.trxId,
          error: `${ex.toString()}\n${ex.stack}`
        });
      }
    }
    else {
      EnigmailLog.ERROR(`pgpjs-crypto-worker.jsm: onmessage: Unknown function call ${e.data.func} received from worker\n`);
    }
    return;
  }

  if (pendingPromises[e.data.trxId]) {
    if ("result" in e.data) {
      pendingPromises[e.data.trxId].resolve(e.data.result);
    }
    else {
      EnigmailLog.ERROR(`pgpjs-crypto-worker.jsm: onmessage: ${e.data.error}\n`);
      pendingPromises[e.data.trxId].reject(e.data.error);
    }
    delete pendingPromises[e.data.trxId];
  }
};

cryptoWorker.onerror = function(e) {
  EnigmailLog.ERROR(`pgpjs-crypto-worker.jsm. onerror: Error received from worker: ${e.message}\n`);
};


const PgpJsWorkerParent = {

  sendMessage(functionName, param, transferables) {
    let trxId = ++gTransactionId;
    return new Promise((resolve, reject) => {
      cryptoWorker.postMessage({
        func: functionName,
        trxId: trxId,
        param: param
      }, transferables);

      pendingPromises[trxId] = {
        resolve,
        reject
      };
    });
  }
};
