/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */


"use strict";

/**
 * Load OpenPGP.js libray
 */

/* global importScripts: false, EnigmailConstants: false, EnigmailArmor: false */

importScripts('chrome://enigmail/content/modules/stdlib/openpgp-lib.js');
importScripts('chrome://enigmail/content/modules/armor.jsm');
importScripts('chrome://enigmail/content/modules/constants.jsm');

const PgpJS = self.openpgp;

/**
 * OpenPGP.js implementation of CryptoAPI
 *
 * Decryption-related functions
 */

var workerBody = {

  /**
   * Process an OpenPGP message
   *
   * @param {Boolean} allowWeakKeys Allow the use of weak keys (DSA, ElGamal, and short RSA keys)
   */
  loadConfig: function({
    allowWeakKeys
  }) {
    DEBUG_LOG(`loadConfig(${allowWeakKeys})\n`);

    if (allowWeakKeys) {
      PgpJS.config.rejectPublicKeyAlgorithms = new Set();
      PgpJS.config.minRSABits = 1024;
    }
    else {
      const ALGO = PgpJS.enums.publicKey;
      PgpJS.config.minRSABits = 2047;
      PgpJS.config.rejectPublicKeyAlgorithms = new Set([ALGO.elgamal, ALGO.dsa]);
    }
  },

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

  processPgpMessage: async function({
    encrypted,
    options
  }) {
    DEBUG_LOG(`processPgpMessage(${encrypted.length})\n`);

    const retData = getReturnObj();

    try {
      let message;
      if (encrypted.search(/^-----BEGIN PGP/m) >= 0) {
        message = await PgpJS.readMessage({
          armoredMessage: encrypted
        });
      }
      else {
        let encArr = ensureUint8Array(encrypted);
        message = await PgpJS.readMessage({
          binaryMessage: encArr
        });
      }

      let idx = message.packets.indexOfTag(PgpJS.enums.packet.compressedData);
      if (idx.length > 0 && idx[0] === 0) {
        message = message.unwrapCompressed();
      }

      // determine with which keys the message is encrypted
      let pubKeyIds = message.getEncryptionKeyIDs().map(keyId => {
        return keyId.toHex().toUpperCase();
      });

      if (pubKeyIds.length === 0 && message.getSigningKeyIDs().length > 0) {
        // message is signed only
        return this.verifyMessage(message, true);
      }

      idx = message.packets.indexOfTag(PgpJS.enums.packet.literalData);
      if (idx.length > 0 && idx[0] === 0) {
        let litDataArr = message.getLiteralData();
        retData.decryptedData += arrayBufferToString(litDataArr);
        retData.statusFlags = 0;
        return retData;
      }

      return this.decryptMessage(message, pubKeyIds, options);
    }
    catch (ex) {
      DEBUG_LOG(`processPgpMessage: ERROR: ${ex.toString()}\n${ex.stack}\n${encrypted}\n`);
      retData.errorMsg = ex.toString();
      retData.exitCode = 1;
    }

    return retData;
  },


  decryptMessage: async function(message, pubKeyIds, options) {
    DEBUG_LOG(`decryptMessage(${pubKeyIds.join(", ")})\n`);

    const retData = getReturnObj();
    let encToDetails = "";
    let secretKeys = [];

    try {
      encToDetails = await requestMessage("getKeydesc", pubKeyIds);

      // get OpenPGP.js key objects for secret keys
      let armoredSecretKeys = await requestMessage("getSecretKeysForIds", pubKeyIds);

      if (armoredSecretKeys.length === 0) {
        retData.statusFlags |= EnigmailConstants.NO_SECKEY;
      }
      else {
        secretKeys = await PgpJS.readKeys({
          armoredKeys: armoredSecretKeys
        });
      }

      // try to decrypt the message using the secret keys one-by-one
      for (let sk of secretKeys) {
        let decryptedSecKey = await requestMessage("getDecryptedSecretKey", {
          secretKeyFpr: sk.getFingerprint().toUpperCase(),
          decryptionReason: EnigmailConstants.KEY_DECRYPT_REASON_ENCRYPTED_MSG
        });

        if (decryptedSecKey.length > 0) {
          let secKey = await PgpJS.readKeys({
            armoredKeys: decryptedSecKey
          });

          secKey.revocationSignatures = []; // remove revocation sigs to allow decryption
          let result = await PgpJS.decrypt({
            message: message,
            format: "binary",
            decryptionKeys: secKey
          });

          let verifiation;
          if (result && ("data" in result)) {
            retData.decryptedData = ensureString(result.data);
            retData.statusFlags = EnigmailConstants.DECRYPTION_OKAY;

            if (options.uiFlags & EnigmailConstants.UI_PGP_MIME) {
              retData.statusFlags |= EnigmailConstants.PGP_MIME_ENCRYPTED;
            }

            // check signature and return first verified signature
            if ("signatures" in result && result.signatures.length > 0) {
              let pkt = new PgpJS.PacketList();

              for (let sig of result.signatures) {
                let sigPackets = await sig.signature;
                pkt = pkt.concat(sigPackets.packets);
              }

              verifiation = await this.verifyDetached({
                data: result.data,
                signature: pkt
              });

              if (verifiation.exitCode !== 2) {
                retData.statusFlags += verifiation.statusFlags;
                retData.sigDetails = verifiation.sigDetails;
                retData.keyId = verifiation.keyId;
                retData.userId = verifiation.userId;
                retData.errorMsg = verifiation.errorMsg;
              }
            }
          }

          if ("filename" in result) {
            retData.encryptedFileName = result.filename;
          }

          break;
        }
        else {
          DEBUG_LOG(`decrypt invalid or no passphrase supplied\n`);
          retData.statusFlags |= EnigmailConstants.BAD_PASSPHRASE;
        }
      }
    }
    catch (ex) {
      if (("message" in ex) && ex.message.search(/(Message .*not authenticated|missing MDC|Modification detected)/) > 0) {
        retData.statusFlags |= EnigmailConstants.MISSING_MDC;
        retData.statusMsg = "%MISSING_MDC";
      }
      else {
        DEBUG_LOG(`decryptMessage: ERROR: ${ex.toString()}\n`);
        retData.exitCode = 1;
        retData.errorMsg = ex.toString();
      }
    }

    retData.encToDetails = encToDetails;
    return retData;
  },

  verify: async function({
    data,
    options
  }) {
    DEBUG_LOG(`verify(${data.length})\n`);

    let result = getReturnObj();

    result.statusFlags = 0;
    result.exitCode = 1;
    result.decryptedData = "";

    try {
      let msg = await PgpJS.readCleartextMessage({
        cleartextMessage: data
      });

      let binaryData = extractDataFromClearsignedMsg(data);

      if (msg && "signature" in msg) {
        result = await this.verifyDetached({
          data: binaryData,
          signature: msg.signature.armor(),
          returnData: true
        });
      }
    }
    catch (ex) {
      DEBUG_LOG(`verify: ERROR: ${ex.toString()}\n`);
      result.errorMsg = ex.toString();
      result.statusFlags = EnigmailConstants.UNVERIFIED_SIGNATURE;
    }

    return result;
  },

  /**
   * Verify a message with a detached signature
   *
   * @param {String|Uint8Array} data: the data to verify
   * @param {String} signature: ASCII armored signature
   * @param {Boolean} returnData: if true, inculde the verified data in the result
   *
   * @return {Promise<Object>}: ResultObj
   */
  verifyDetached: async function({
    data,
    signature,
    returnData = false
  }) {
    DEBUG_LOG(`verifyDetached(${data.length}, ${signature.length})\n`);
    try {
      let sigString;

      if (typeof(signature) === "string") {
        sigString = signature;
      }
      else {
        sigString = await PgpJS.armor(PgpJS.enums.armor.signature, signature.write());
      }

      let msg;
      if (typeof(data) === "string") {
        msg = await PgpJS.createMessage({
          text: data
        });
      }
      else {
        msg = await PgpJS.createMessage({
          binary: data
        });
      }

      await msg.appendSignature(sigString);

      return this.verifyMessage(msg, returnData);
    }
    catch (ex) {
      DEBUG_LOG(`verifyDetached: ERROR: ${ex.toString()}\n`);
      return {
        exitCode: 1,
        statusFlags: EnigmailConstants.NO_PUBKEY,
        decryptedData: "",
        errorMsg: ex.toString()
      };
    }
  },

  /**
   * Verify a message and return the signature verification status
   *
   * @param {Object} messageObj: OpenPGP.js Message
   * @param {Boolean} returnData: if true, inculde the verified data in the result
   *
   * @return {Promise<Object>} ResultObj
   */
  verifyMessage: async function(messageObj, returnData = false) {
    DEBUG_LOG(`verifyMessage()\n`);
    const SIG_STATUS = {
      unknown_key: 0,
      bad_signature: 1,
      good_sig_invalid_key: 2,
      good_sig_expired_key: 3,
      valid_signature: 4
    };

    const result = {
      statusFlags: EnigmailConstants.UNVERIFIED_SIGNATURE,
      exitCode: 2,
      sigDetails: "",
      keyId: "",
      userId: "",
      errorMsg: "",
      blockSeparation: "",
      decryptedData: ""
    };

    let currentKey = null,
      signatureStatus = -1;

    let keyIds = messageObj.getSigningKeyIDs().map(keyId => {
      return keyId.toHex().toUpperCase();
    });

    let armoredPubKeys = await requestMessage("getPublicKeysForIds", keyIds);

    if (armoredPubKeys.length === 0) {
      armoredPubKeys = await requestMessage("downloadMissingKeys", keyIds);
    }

    if (armoredPubKeys.length === 0) {
      DEBUG_LOG(`verifyMessage: no public key found\n`);
      result.keyId = keyIds[0];
      return result;
    }

    let pubKeys = await PgpJS.readKeys({
      armoredKeys: armoredPubKeys
    });

    DEBUG_LOG(`verifyMessage: found ${pubKeys.length} key(s)\n`);

    for (let key of pubKeys) {
      if (await key.isRevoked()) {
        // remove revocation signatures to get a valid key (required for verification)
        key._enigmailRevoked = true;
        key.revocationSignatures = [];
      }
    }

    let ret = {};
    for (let key of pubKeys) {
      try {
        ret = (await PgpJS.verify({
          message: messageObj,
          verificationKeys: key
        }));
        DEBUG_LOG(`verifyMessage: message verification succeeded\n`);
      }
      catch (x) {
        DEBUG_LOG(`verifyMessage: message verification failed with ${x.toString()}\n`);
      }
      break;
    }


    try {
      if (returnData && ("data" in ret)) {
        result.decryptedData = ensureString(ret.data);
      }

      for (let sig of ret.signatures) {
        let currentStatus = -1,
          sigValid = false;
        try {
          sigValid = await sig.verified;
        }
        catch (ex) {
          DEBUG_LOG(`verifyMessage: signature verification failed with ${ex.toString()}\n`);
        }

        currentKey = null;
        let keyId = sig.keyID.toHex();

        for (let k of pubKeys) {
          if (k.getKeyID().toHex() === keyId) {
            currentKey = k;
            break;
          }
          else {
            for (let sk of k.getSubkeys()) {
              if (sk.getKeyID().toHex() === keyId) {
                currentKey = k;
                break;
              }
            }
          }
        }

        if (currentKey === null) {
          DEBUG_LOG(`verifyMessage: key not found - this should not happen\n`);
          currentStatus = SIG_STATUS.unknown_key;
          result.keyId = keyId.toUpperCase();
        }
        else if (currentKey._enigmailKeyStatus === "disabled" || !sigValid) {
          currentStatus = SIG_STATUS.bad_signature;
          result.keyId = keyId.toUpperCase();
        }
        else {
          if (!sigValid) {
            currentStatus = SIG_STATUS.bad_signature;
          }
          else {
            let keyStatus = await getKeyStatusCode(currentKey);

            if (currentKey._enigmailRevoked) keyStatus = "r";

            switch (keyStatus) {
              case "i":
              case "r":
                currentStatus = SIG_STATUS.good_sig_invalid_key;
                break;
              case "e":
                currentStatus = SIG_STATUS.good_sig_expired_key;
                break;
              case "f":
                currentStatus = SIG_STATUS.valid_signature;
                break;
              default:
                currentStatus = SIG_STATUS.unknown_key;
            }
          }

          if (currentStatus >= signatureStatus) {
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
            const pkt = (await sig.signature).packets[0];
            result.keyId = currentKey.getFingerprint().toUpperCase();
            result.sigDetails = result.keyId + " " +
              pkt.created.toISOString().substr(0, 10) + " " +
              (pkt.created.getTime() / 1000) + " " +
              (pkt.signatureNeverExpires ? "0" : pkt.signatureExpirationTime.getTime() / 1000) + " " +
              pkt.version + " 0 " +
              pkt.publicKeyAlgorithm + " " +
              pkt.hashAlgorithm + " 00 " + result.keyId;
          }
        }

        signatureStatus = Math.max(signatureStatus, currentStatus);
      }

      result.exitCode = 0;
      switch (signatureStatus) {
        case SIG_STATUS.unknown_key:
          result.statusFlags = EnigmailConstants.NO_PUBKEY | EnigmailConstants.UNVERIFIED_SIGNATURE;
          break;
        case SIG_STATUS.bad_signature:
          result.statusFlags = EnigmailConstants.BAD_SIGNATURE;
          result.exitCode = 1;
          break;
        case SIG_STATUS.good_sig_invalid_key:
          result.statusFlags = EnigmailConstants.GOOD_SIGNATURE | EnigmailConstants.REVOKED_KEY;
          break;
        case SIG_STATUS.good_sig_expired_key:
          result.statusFlags = EnigmailConstants.GOOD_SIGNATURE | EnigmailConstants.EXPIRED_KEY;
          break;
        case SIG_STATUS.valid_signature:
          result.statusFlags = EnigmailConstants.GOOD_SIGNATURE | EnigmailConstants.TRUSTED_IDENTITY;
      }

      if (currentKey) {
        result.userId = currentKey.users[0].userID.userID;
      }

      if (result.statusFlags & EnigmailConstants.GOOD_SIGNATURE) {
        result.errorMsg = `%GOOD_SIG:${result.userId}`;
      }
      else if (result.statusFlags & EnigmailConstants.BAD_SIGNATURE) {
        result.errorMsg = `%BAD_SIG:${result.userId}`;
      }
    }
    catch (ex) {
      DEBUG_LOG(`verifyMessage: ERROR: ${ex.toString()} ${ex.stack}\n`);
    }

    return result;
  },

  encryptData: async function({
    text,
    encryptionKeys,
    signingKeys
  }) {

    let publicKeys = await PgpJS.readKeys({
      armoredKeys: encryptionKeys
    });

    let privateKeys = undefined;

    if (signingKeys) {
      privateKeys = await PgpJS.readPrivateKeys({
        armoredKeys: signingKeys
      });
    }

    return await PgpJS.encrypt({
      message: await PgpJS.createMessage({
        text
      }),
      encryptionKeys: publicKeys,
      signingKeys: privateKeys, // for signing
      format: "armored"
    });
  },

  signData: async function({
    text,
    signingKeys,
    detachedSignature
  }) {
    let privateKeys = await PgpJS.readPrivateKeys({
      armoredKeys: signingKeys
    });

    if (detachedSignature) {
      return await PgpJS.sign({
        message: await PgpJS.createMessage({
          text
        }),
        signingKeys: privateKeys,
        detached: detachedSignature,
        format: "armored"
      });
    }
    else {
      return await PgpJS.sign({
        message: await PgpJS.createCleartextMessage({
          text
        }),
        signingKeys: privateKeys,
        detached: detachedSignature,
        format: "armored"
      });
    }


  }
};

/**
 * Take a string or Uint8Array and if needed convert it to a string.
 *
 * @param {String|Uint8Array} stringOrUint8Array: input data
 *
 * @return {String}
 */
function ensureString(stringOrUint8Array) {
  if (typeof stringOrUint8Array === "string") {
    return stringOrUint8Array;
  }

  return arrayBufferToString(stringOrUint8Array);
}

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
 * Read from a stream and return a string
 *
 * @param reader Stream to read from
 * @returns {Promise<String>}
 */
function readFromStream(reader) {
  let result = "";

  return new Promise((resolve, reject) => {
    reader.read().then(function processText({
      done,
      value
    }) {
      // Result objects contain two properties:
      // done  - true if the stream has already given you all its data.
      // value - some data. Always undefined when done is true.
      if (done) {
        resolve(result);
        return null;
      }

      // value for fetch streams is a Uint8Array
      result += ensureString(value);

      // Read some more, and call this function again
      return reader.read().then(processText);
    });
  });
}


function getReturnObj() {
  return {
    decryptedData: "",
    exitCode: 0,
    statusFlags: EnigmailConstants.DECRYPTION_FAILED,
    userId: "",
    sigDetails: "",
    keyId: "",
    errorMsg: "",
    encToDetails: "",
    blockSeparation: ""
  };
}

async function getKeyStatusCode(key) {
  let now = new Date();

  try {
    if (await key.isRevoked(null, null, now)) {
      return "r";
    }
    else if (!key.users.some(user => user.userID && user.selfCertifications.length)) {
      return "i";
    }
    else {
      const {
        user,
        selfCertification
      } = await key.getPrimaryUser(now, {}) || {};

      if (!user) return "i";

      // check for expiration time
      if (isDataExpired(key.keyPacket, selfCertification, now)) {
        return "e";
      }
    }
  }
  catch (x) {
    return "i";
  }

  return "f";
}

function isDataExpired(keyPacket, signature, date = new Date()) {
  const normDate = normalizeDate(date);

  if (normDate !== null) {
    const expirationTime = getExpirationTime(keyPacket, signature);

    return !(keyPacket.created <= normDate && normDate < expirationTime) ||
      (signature && signature.isExpired(date));
  }

  return false;
}

function normalizeDate(time = Date.now()) {
  return time === null ? time : new Date(Math.floor(Number(time) / 1000) * 1000);
}

function getExpirationTime(keyPacket, signature) {
  let expirationTime;
  try {
    // check V4 expiration time
    if (signature.keyNeverExpires === false) {
      expirationTime = keyPacket.created.getTime() + signature.keyExpirationTime * 1000;
    }

    return expirationTime ? new Date(expirationTime) : Infinity;
  }
  catch (ex) {
    return Infinity;
  }
}

function extractDataFromClearsignedMsg(dataStr) {
  dataStr = dataStr.replace(/\r?\n/g, "\r\n"); // ensure CRLF
  dataStr = dataStr.replace(/^- /mg, ""); // Remove dash-escapes
  let start = dataStr.search(/\r\n\r\n/);
  let end = dataStr.search(/^-----BEGIN PGP SIGNATURE-----/m);

  if (start < 0 || end < 0 || end < start) return "";

  return dataStr.substring(start + 4, end - 2);
}

/**
 * Convert an ArrayBuffer (or Uint8Array) object into a string
 */
function arrayBufferToString(buffer) {
  const MAXLEN = 102400;

  let uArr = new Uint8Array(buffer);
  let ret = "";
  let len = buffer.byteLength;

  for (let j = 0; j < Math.floor(len / MAXLEN) + 1; j++) {
    ret += String.fromCharCode.apply(null, uArr.subarray(j * MAXLEN, ((j + 1) * MAXLEN)));
  }

  return ret;
}

function getDateTime(dateNum, withDate, withTime) {
  const DATE_2DIGIT = "2-digit";
  const DATE_4DIGIT = "numeric";

  if (dateNum && dateNum !== 0) {
    let dat = new Date(dateNum * 1000);

    var options = {};

    if (withDate) {
      options.day = DATE_2DIGIT;
      options.month = DATE_2DIGIT;
      let year = dat.getFullYear();
      if (year > 2099) {
        options.year = DATE_4DIGIT;
      }
      else {
        options.year = DATE_2DIGIT;
      }
    }
    if (withTime) {
      options.hour = DATE_2DIGIT;
      options.minute = DATE_2DIGIT;
    }

    return new Intl.DateTimeFormat(undefined, options).format(dat);
  }
  else {
    return "";
  }
}

/*************************************************************************
 *
 * Implementation of Worker
 *
 **************************************************************************/


var pendingPromises = [],
  gTransactionId = 0;

/**
 * Send a message to the worker parent for requesting data
 *
 * @param {String} functionName
 * @param {Object} param
 * @param {Object} transferables
 *
 * @returns Promise<Object>
 */
async function requestMessage(functionName, param, transferables) {

  let trxId = ++gTransactionId;
  return new Promise((resolve, reject) => {
    postMessage({
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

/**
 * Send and receive messages to/from Worker parent
 */
onmessage = async function(e) {
  if (("result" in e.data) && ("trxId" in e.data)) {
    if (pendingPromises[e.data.trxId]) {
      pendingPromises[e.data.trxId].resolve(e.data.result);
      delete pendingPromises[e.data.trxId];
    }
    return;
  }

  if (("error" in e.data) && ("trxId" in e.data)) {
    if (pendingPromises[e.data.trxId]) {
      pendingPromises[e.data.trxId].reject({
        message: e.data.error
      });
      delete pendingPromises[e.data.trxId];
    }
    return;
  }

  if (!("func" in e.data && "trxId" in e.data)) {
    DEBUG_LOG('Worker: Message received invalid data from main script');

    if ("trxId" in e.data) {
      postMessage({
        trxId: e.data.trxId,
        error: "No function provided"
      });
    }
    return;
  }

  let method = e.data.func;
  let args = e.data.param || null;

  if (!(method in workerBody)) {
    postMessage({
      trxId: e.data.trxId,
      error: `Invalid method '${method}' invoked`
    });
    return;
  }

  try {
    let workerResult = await workerBody[method](args);
    DEBUG_LOG('Posting message back to main script');
    postMessage({
      trxId: e.data.trxId,
      result: workerResult
    });
  }
  catch (ex) {
    postMessage({
      trxId: e.data.trxId,
      error: `${ex.toString()}\n${ex.stack}`
    });
  }
};


onerror = function(e) {
  ERROR_LOG('Received error from main script');
};


function DEBUG_LOG(msg) {
  postMessage({
    logMessage: "pgpjs-crypto-worker.js: " + msg,
    logLevel: 5
  });
}

function ERROR_LOG(msg) {
  postMessage({
    logMessage: "pgpjs-crypto-worker.js: " + msg,
    logLevel: 0
  });
}
