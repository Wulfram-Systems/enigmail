/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */


"use strict";

var EXPORTED_SYMBOLS = ["EnigmailPersistentCrypto"];

const EnigmailLazy = ChromeUtils.import("chrome://enigmail/content/modules/lazy.jsm").EnigmailLazy;
const EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
const EnigmailArmor = ChromeUtils.import("chrome://enigmail/content/modules/armor.jsm").EnigmailArmor;
const EnigmailLocale = ChromeUtils.import("chrome://enigmail/content/modules/locale.jsm").EnigmailLocale;
const GlodaUtils = ChromeUtils.import("chrome://enigmail/content/modules/glodaUtils.jsm").GlodaUtils;
const EnigmailCompat = ChromeUtils.import("chrome://enigmail/content/modules/compat.jsm").EnigmailCompat;
const EnigmailCore = ChromeUtils.import("chrome://enigmail/content/modules/core.jsm").EnigmailCore;
const EnigmailMime = ChromeUtils.import("chrome://enigmail/content/modules/mime.jsm").EnigmailMime;
const EnigmailData = ChromeUtils.import("chrome://enigmail/content/modules/data.jsm").EnigmailData;
const EnigmailTimer = ChromeUtils.import("chrome://enigmail/content/modules/timer.jsm").EnigmailTimer;
const EnigmailConstants = ChromeUtils.import("chrome://enigmail/content/modules/constants.jsm").EnigmailConstants;
const jsmime = ChromeUtils.import("resource:///modules/jsmime.jsm").jsmime;
const EnigmailStdlib = ChromeUtils.import("chrome://enigmail/content/modules/stdlib.jsm").EnigmailStdlib;
const EnigmailCryptoAPI = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI.jsm").EnigmailCryptoAPI;
const EnigmailStreams = ChromeUtils.import("chrome://enigmail/content/modules/streams.jsm").EnigmailStreams;

const getFixExchangeMsg = EnigmailLazy.loader("enigmail/fixExchangeMsg.jsm", "EnigmailFixExchangeMsg");
const getDialog = EnigmailLazy.loader("enigmail/dialog.jsm", "EnigmailDialog");

const STATUS_OK = 0;
const STATUS_FAILURE = 1;
const STATUS_NOT_REQUIRED = 2;

const IOSERVICE_CONTRACTID = "@mozilla.org/network/io-service;1";

/*
 *  Decrypt a message and copy it to a folder
 *
 * @param nsIMsgDBHdr hdr   Header of the message
 * @param String destFolder   Folder URI
 * @param Boolean move      If true the original message will be deleted
 *
 * @return a Promise that we do that
 */
var EnigmailPersistentCrypto = {

  /***
   *  dispatchMessages
   *
   *  Because Thunderbird throws all messages at once at us thus we have to rate limit the dispatching
   *  of the message processing. Because there is only a negligible performance gain when dispatching
   *  several message at once we serialize to not overwhelm low power devices.
   *
   *  If targetFolder is null the message will be copied / moved in the same folder as the original
   *  message.
   *
   *  If targetKey is not null the message will be encrypted again to the targetKey.
   *
   *  The function is implemented asynchronously.
   *
   *  Parameters
   *   aMsgHdrs:     Array of nsIMsgDBHdr
   *   targetFolder: String; target folder URI or null
   *   copyListener: listener for async request (nsIMsgCopyServiceListener)
   *   move:         Boolean: type of action; true = "move" / false = "copy"
   *   targetKey:    KeyObject of target key if encryption is requested
   *
   **/

  dispatchMessages: function(aMsgHdrs, targetFolder, copyListener, move, targetKey) {
    EnigmailLog.DEBUG("persistentCrypto.jsm: dispatchMessages()\n");

    let enigmailSvc = EnigmailCore.getService();
    if (copyListener && !enigmailSvc) {
      // could not initiate Enigmail - do nothing
      copyListener.OnStopCopy(0);
      return;
    }

    if (copyListener) {
      copyListener.OnStartCopy();
    }
    let promise = EnigmailPersistentCrypto.cryptMessage(aMsgHdrs[0], targetFolder, move, targetKey);

    let processNext = function(data) {
      aMsgHdrs.splice(0, 1);
      if (aMsgHdrs.length > 0) {
        EnigmailPersistentCrypto.dispatchMessages(aMsgHdrs, targetFolder, copyListener, move, targetKey);
      }
      else {
        // last message was finished processing
        if (copyListener) {
          copyListener.OnStopCopy(0);
        }
        EnigmailLog.DEBUG("persistentCrypto.jsm: dispatchMessages - DONE\n");
      }
    };

    promise.then(processNext);

    promise.catch(function(err) {
      processNext(null);
    });
  },

  /***
   *  cryptMessage
   *
   *  Decrypts a message. If targetKey is not null it
   *  encrypts a message to the target key afterwards.
   *
   *  Parameters
   *   hdr:        nsIMsgDBHdr of the message to encrypt
   *   destFolder: String; target folder URI
   *   move:       Boolean: type of action; true = "move" / false = "copy"
   *   targetKey:  KeyObject of target key if encryption is requested
   **/
  cryptMessage: function(hdr, destFolder, move, targetKey) {
    return new Promise(
      function(resolve, reject) {
        let msgUriSpec = hdr.folder.getUriForMsg(hdr);
        let msgUrl = EnigmailCompat.getUrlFromUriSpec(msgUriSpec);
        if (!destFolder) {
          destFolder = hdr.folder.URI;
        }

        const crypt = new CryptMessageIntoFolder(destFolder, move, resolve, targetKey);

        try {
          EnigmailMime.getMimeTreeFromUrl(msgUrl, true,
            function f_(mime) {
              crypt.messageParseCallback(mime, hdr, msgUrl);
            });
        }
        catch (ex) {
          reject("msgHdrsDeleteoMimeMessage failed: " + ex.toString());
        }
        return;
      }
    );
  },

  copyMessageToFolder(originalMsgHdr, targetFolderUri, deleteOrigMsg, content, selectNew, win = null) {
    EnigmailLog.DEBUG("persistentCrypto.jsm: copyMessageToFolder()\n");
    return new Promise((resolve, reject) => {

      // Create the temporary file where the new message will be stored.
      const tempFile = Cc["@mozilla.org/file/directory_service;1"].getService(Ci.nsIProperties).get("TmpD", Ci.nsIFile);
      tempFile.append("message.eml");
      tempFile.createUnique(0, 0o600);

      const outputStream = Cc["@mozilla.org/network/file-output-stream;1"].createInstance(Ci.nsIFileOutputStream);
      outputStream.init(tempFile, 2, 0x200, false); // open as "write only"
      outputStream.write(content, content.length);
      outputStream.close();

      // Delete file on exit, because Windows locks the file
      const extAppLauncher = Cc["@mozilla.org/uriloader/external-helper-app-service;1"].getService(Ci.nsPIExternalAppLauncher);
      extAppLauncher.deleteTemporaryFileOnExit(tempFile);

      const msgFolder = originalMsgHdr.folder;

      // The following technique was copied from nsDelAttachListener in Thunderbird's
      // nsMessenger.cpp. There is a "unified" listener which serves as copy and delete
      // listener. In all cases, the `OnStopCopy()` of the delete listener selects the
      // replacement message.
      // The deletion happens in `OnStopCopy()` of the copy listener for local messages
      // and in `OnStopRunningUrl()` for IMAP messages if the folder is displayed since
      // otherwise `OnStopRunningUrl()` doesn't run.

      let copyListener, newKey;
      let statusCode = 0;
      let deletedOld = false;
      const destFolder = targetFolderUri ? EnigmailCompat.getExistingFolder(targetFolderUri) : msgFolder;

      copyListener = {
        QueryInterface(iid) {
          if (iid.equals(Ci.nsIMsgCopyServiceListener) ||
            iid.equals(Ci.nsIUrlListener) ||
            iid.equals(Ci.nsISupports)) {
            return this;
          }
          throw Cr.NS_NOINTERFACE;
        },
        GetMessageId(messageId) {
          // Maybe enable this later. Most of the Thunderbird code does not supply this.
          // messageId = { value: msgHdr.messageId };
        },
        SetMessageKey(key) {
          EnigmailLog.DEBUG(`persistentCrypto.jsm: copyMessageToFolder: Result of CopyFileMessage() is new message with key ${key}\n`);
          newKey = key;
        },
        applyFlags() {
          let newHdr = destFolder.GetMessageHeader(newKey);
          newHdr.markRead(originalMsgHdr.isRead);
          newHdr.markFlagged(originalMsgHdr.isFlagged);
          newHdr.subject = originalMsgHdr.subject;
        },
        deleteMsg() {
          if ((!deleteOrigMsg) || deletedOld) {
            resolve(true);
            return;
          }
          try {
            EnigmailLog.DEBUG(`persistentCrypto.jsm: copyMessageToFolder: Deleting old message with key ${originalMsgHdr.messageKey}\n`);
            const msgArray = Cc["@mozilla.org/array;1"].createInstance(Ci.nsIMutableArray);
            msgArray.appendElement(originalMsgHdr, false);
            msgFolder.deleteMessages(msgArray, null, true, false, null, false);
          }
          catch (ex) {
            EnigmailLog.ERROR(ex.toString());
          }
          deletedOld = true;
          resolve(true);
        },
        OnStartRunningUrl() {},
        OnStopRunningUrl() {
          // This is not called for local and off-screen folders, hence we delete in `OnStopCopy()`.
          if (statusCode !== 0) return;
          EnigmailLog.DEBUG("persistentCrypto.jsm: copyMessageToFolder: Triggering deletion from OnStopRunningUrl()\n");
          this.applyFlags();
          this.deleteMsg();
        },
        OnStartCopy() {},
        OnStopCopy(status) {
          statusCode = status;
          if (statusCode !== 0) {
            EnigmailLog.ERROR(`persistentCrypto.jsm: ${statusCode} replacing message, folder="${msgFolder.name}", key=${originalMsgHdr.messageKey}/${newKey}\n`);
            resolve(false);
            return;
          }

          try {
            tempFile.remove();
          }
          catch (ex) {}

          if (msgFolder.folderURL.startsWith("mailbox:") ||
            // IMAP's `OnStopRunningUrl()` does not run for off-screen folders.
            (win && win.gDBView && win.gDBView.msgFolder != msgFolder) ||
            // If we don't have a window or view, delete the message here
            // since we don't know whether `OnStopRunningUrl()` will run.
            !win || !win.gDBView) {
            EnigmailLog.DEBUG("persistentCrypto.jsm: copyMessageToFolder: Triggering deletion from OnStopCopy()\n");
            this.applyFlags();
            this.deleteMsg();
            return;
          }
          else {
            EnigmailLog.DEBUG("persistentCrypto.jsm: copyMessageToFolder: Not triggering deletion from OnStopCopy()\n");
          }
          resolve(true);
        }
      };

      EnigmailCompat.copyFileToMailFolder(tempFile, destFolder, originalMsgHdr.flags, "", copyListener, null);
    });
  }
};

function CryptMessageIntoFolder(destFolder, move, resolve, targetKey) {
  this.destFolder = destFolder;
  this.move = move;
  this.resolve = resolve;
  this.targetKey = targetKey;
  this.messageDecrypted = false;

  this.mimeTree = null;
  this.decryptionTasks = [];
  this.subject = "";
}

CryptMessageIntoFolder.prototype = {
  messageParseCallback: async function(mimeTree, msgHdr, msgUrl) {
    this.mimeTree = mimeTree;
    this.hdr = msgHdr;
    this.msgUrl = msgUrl;

    if (mimeTree.headers.has("subject")) {
      this.subject = mimeTree.headers.get("subject");
    }

    await this.decryptMimeTree(mimeTree);

    let msg = "";

    // Encrypt the message if a target key is given.
    if (this.targetKey) {
      msg = await this.encryptToKey(mimeTree);
      if (!msg) {
        // do nothing (still better than destroying the message)
        this.resolve(true);
        return;
      }
      else {
        this.messageDecrypted = true;
      }
    }
    else if (this.messageDecrypted) {
      msg = this.mimeToString(mimeTree, true);
    }

    if (this.messageDecrypted) {
      this.resolve(await this.storeMessage(msg));
    }
    else
      this.resolve(true);
  },

  getRawMessageData: function(msgUrl) {
    return new Promise((resolve, reject) => {
      try {
        const f = function _cb(data) {
          EnigmailLog.DEBUG(`persistentCrypto.jsm: getRawMessageData - got data (${data.length})\n`);
          resolve(data);
        };

        let bufferListener = EnigmailStreams.newStringStreamListener(f);
        let ioServ = Cc[IOSERVICE_CONTRACTID].getService(Components.interfaces.nsIIOService);
        let msgUri = ioServ.newURI(msgUrl, null, null);

        let channel = EnigmailStreams.createChannel(msgUrl);
        channel.asyncOpen(bufferListener, msgUri);
      }
      catch (ex) {
        EnigmailLog.DEBUG(`persistentCrypto.jsm: getRawMessageData - exception ${ex.toString()}\n`);
        reject(ex);
      }
    });
  },

  encryptToKey: async function(mimeTree) {
    EnigmailLog.DEBUG("persistentCrypto.jsm: encryptToKey()\n");

    let inputMsg = "";
    const cApi = EnigmailCryptoAPI();

    if (mimeTree.fullContentType &&
      mimeTree.fullContentType.search(/^multipart\/signed/i) === 0 &&
      !mimeTree.body) {
      // make sure we get the unmodified raw message for PGP/MIME (or S/MIME) signed messages
      inputMsg = await this.getRawMessageData(`${this.msgUrl.spec}`);
      let bodyIdx = inputMsg.search(/\r?\n\r?\n/);
      if (bodyIdx > 0) {
        inputMsg = inputMsg.substr(bodyIdx + 2);
      }
    }
    else {
      inputMsg = this.mimeToString(mimeTree, false, true);
    }

    if (!mimeTree.fullContentType) {
      // if no content-type is provided, it's text/plain by definition (RFC 2045)
      mimeTree.fullContentType = "text/plain";
      mimeTree.headers._rawHeaders.set("content-type", ["text/plain"]);
    }

    if (mimeTree.fullContentType.search(/^multipart\/encrypted/i) < 0) {
      // add header for MIME part, unless it's originally a PGP/MIME encrypted message
      let msgHeader = formatMimeHeader("content-type", mimeTree.headers._rawHeaders.get("content-type")) + "\n";

      if (mimeTree.headers._rawHeaders.has("content-transfer-encoding")) {
        msgHeader += formatMimeHeader("content-transfer-encoding", mimeTree.headers._rawHeaders.get("content-transfer-encoding")) + "\n";
      }

      if (mimeTree.headers._rawHeaders.has("content-disposition")) {
        msgHeader += formatMimeHeader("content-disposition", mimeTree.headers._rawHeaders.get("content-disposition")) + "\n";
      }

      inputMsg = msgHeader + "\n" + inputMsg;
    }


    let ret = null;
    try {
      ret = await cApi.encryptMessage(
        "0x" + this.targetKey.fpr,
        "0x" + this.targetKey.fpr,
        "",
        EnigmailConstants.SEND_ENCRYPTED | EnigmailConstants.SEND_ALWAYS_TRUST,
        inputMsg
      );

      if (ret.data.length === 0) return null;
    }
    catch (ex) {
      EnigmailLog.DEBUG("persistentCrypto.jsm: Encryption failed: " + ex + "\n");
      return null;
    }

    // Build the pgp-encrypted mime structure
    let msg = "";

    // First the original headers
    for (let hdr of mimeTree.headers._rawHeaders.keys()) {
      if (hdr != "content-type" &&
        hdr != "content-transfer-encoding" &&
        hdr != "content-disposition") {

        msg += formatMimeHeader(hdr, mimeTree.headers._rawHeaders.get(hdr)) + " \n";
      }
    }

    // Then multipart/encrypted ct
    let boundary = EnigmailMime.createBoundary();
    msg += "Content-Transfer-Encoding: 7Bit\n";
    msg += "Content-Type: multipart/encrypted; ";
    msg += "boundary=\"" + boundary + "\"; protocol=\"application/pgp-encrypted\"\n\n";
    msg += "This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)\n";

    // pgp-encrypted part
    msg += "--" + boundary + "\n";
    msg += "Content-Type: application/pgp-encrypted\n";
    msg += "Content-Disposition: attachment\n";
    msg += "Content-Transfer-Encoding: 7Bit\n\n";
    msg += "Version: 1\n\n";

    // the octet stream
    msg += "--" + boundary + "\n";
    msg += "Content-Type: application/octet-stream; name=\"encrypted.asc\"\n";
    msg += "Content-Description: OpenPGP encrypted message\n";
    msg += "Content-Disposition: inline; filename=\"encrypted.asc\"\n";
    msg += "Content-Transfer-Encoding: 7Bit\n\n";
    msg += ret.data;

    // Bottom boundary
    msg += "\n--" + boundary + "--\n";

    // Fix up the line endings to be a proper dosish mail
    msg = msg.replace(/\r/ig, "").replace(/\n/ig, "\r\n");

    return msg;
  },

  /**
   *  Walk through the MIME message structure and decrypt the body if there is something to decrypt
   */
  decryptMimeTree: async function(mimePart) {
    EnigmailLog.DEBUG("persistentCrypto.jsm: decryptMimeTree:\n");

    if (this.isBrokenByExchange(mimePart)) {
      this.fixExchangeMessage(mimePart);
    }

    if (this.isPgpMime(mimePart)) {
      await this.decryptPGPMIME(mimePart);
    }
    else if (isAttachment(mimePart)) {
      await this.decryptAttachment(mimePart);
    }
    else {
      await this.decryptINLINE(mimePart);
    }

    for (let i in mimePart.subParts) {
      await this.decryptMimeTree(mimePart.subParts[i]);
    }
  },

  /***
   *
   * Detect if mime part is PGP/MIME message that got modified by MS-Exchange:
   *
   * - multipart/mixed Container with
   *   - application/pgp-encrypted Attachment with name "PGPMIME Version Identification"
   *   - application/octet-stream Attachment with name "encrypted.asc" having the encrypted content in base64
   * - see:
   *   - https://www.enigmail.net/forum/viewtopic.php?f=4&t=425
   *   - https://sourceforge.net/p/enigmail/forum/support/thread/4add2b69/
   */

  isBrokenByExchange: function(mime) {
    EnigmailLog.DEBUG("persistentCrypto.jsm: isBrokenByExchange:\n");

    try {
      if (mime.subParts && mime.subParts.length === 3 &&
        mime.fullContentType.toLowerCase().indexOf("multipart/mixed") >= 0 &&
        mime.subParts[0].subParts.length === 0 &&
        mime.subParts[0].fullContentType.search(/multipart\/encrypted/i) < 0 &&
        mime.subParts[0].fullContentType.toLowerCase().indexOf("text/plain") >= 0 &&
        mime.subParts[1].fullContentType.toLowerCase().indexOf("application/pgp-encrypted") >= 0 &&
        mime.subParts[1].fullContentType.toLowerCase().search(/multipart\/encrypted/i) < 0 &&
        mime.subParts[1].fullContentType.toLowerCase().search(/PGPMIME Versions? Identification/i) >= 0 &&
        mime.subParts[2].fullContentType.toLowerCase().indexOf("application/octet-stream") >= 0 &&
        mime.subParts[2].fullContentType.toLowerCase().indexOf("encrypted.asc") >= 0) {

        EnigmailLog.DEBUG("persistentCrypto.jsm: isBrokenByExchange: found message broken by MS-Exchange\n");
        return true;
      }
    }
    catch (ex) {}

    return false;
  },

  isPgpMime: function(mimePart) {
    EnigmailLog.DEBUG("persistentCrypto.jsm: isPgpMime()\n");

    try {
      if (mimePart.headers.has("content-type")) {
        if (mimePart.headers.get("content-type").type.toLowerCase() === "multipart/encrypted" &&
          mimePart.headers.get("content-type").get("protocol").toLowerCase() === "application/pgp-encrypted" &&
          mimePart.subParts.length === 2) {
          return true;
        }
      }
    }
    catch (x) {}
    return false;
  },

  decryptPGPMIME: async function(mimePart) {
    EnigmailLog.DEBUG("persistentCrypto.jsm: decryptPGPMIME(" + mimePart.partNum + ")\n");

    if (!mimePart.subParts[1]) throw "Not a correct PGP/MIME message";

    const options = {
      uiFlags: EnigmailConstants.UI_INTERACTIVE | EnigmailConstants.UI_UNVERIFIED_ENC_OK |
        EnigmailConstants.UI_IGNORE_MDC_ERROR
    };

    const cApi = EnigmailCryptoAPI();
    let ret = null;

    try {
      ret = await cApi.decrypt(mimePart.subParts[1].body, options);
    }
    catch (ex) {
      ret = {
        data: null,
        statusFlags: 0,
        errorMsg: ""
      };
    }


    if (!ret.decryptedData || ret.decryptedData.length === 0) {
      if (ret.statusFlags & EnigmailConstants.DISPLAY_MESSAGE) {
        getDialog().alert(null, ret.errorMsg);
        throw "Decryption impossible";
      }
    }

    EnigmailLog.DEBUG("persistentCrypto.jsm: analyzeDecryptedData: got " + ret.decryptedData.length + " bytes\n");

    if (EnigmailLog.getLogLevel() > 5) {
      EnigmailLog.DEBUG("*** start data ***\n'" + ret.decryptedData + "'\n***end data***\n");
    }

    if (ret.decryptedData.length === 0) {
      // fail if no data found
      return;
    }

    let bodyIndex = ret.decryptedData.search(/\n\s*\r?\n/);
    if (bodyIndex < 0) {
      bodyIndex = 0;
    }
    else {
      ++bodyIndex;
    }

    if (ret.decryptedData.substr(bodyIndex).search(/\r?\n$/) === 0) {
      return;
    }

    let m = Cc["@mozilla.org/messenger/mimeheaders;1"].createInstance(Ci.nsIMimeHeaders);
    m.initialize(ret.decryptedData.substr(0, bodyIndex));
    let ct = m.extractHeader("content-type", false) || "";
    let part = mimePart.partNum;

    if (part.length > 0 && part.search(/[^01.]/) < 0) {
      if (ct.search(/protected-headers/i) >= 0) {
        if (m.hasHeader("subject")) {
          let subject = m.extractHeader("subject", false) || "";
          subject = subject.replace(/^(Re: )+/, "Re: ");
          this.mimeTree.headers._rawHeaders.set("subject", [subject]);
        }
      }
      else if (this.mimeTree.headers.get("subject") === "p≡p") {
        let subject = getPepSubject(ret.decryptedData);
        if (subject) {
          subject = subject.replace(/^(Re: )+/, "Re: ");
          this.mimeTree.headers._rawHeaders.set("subject", [subject]);
        }
      }
      else if ((!(ret.statusFlags & EnigmailConstants.GOOD_SIGNATURE)) && ct.search(/^multipart\/signed/i) === 0) {
        // RFC 3156, Section 6.1 message

        let innerMsg = EnigmailMime.getMimeTree(ret.decryptedData, false);
        if (innerMsg.subParts.length > 0) {
          ct = innerMsg.subParts[0].fullContentType;
          let hdrMap = innerMsg.subParts[0].headers._rawHeaders;
          if (ct.search(/protected-headers/i) >= 0 && hdrMap.has("subject")) {
            let subject = innerMsg.subParts[0].headers._rawHeaders.get("subject").join("");
            subject = subject.replace(/^(Re: )+/, "Re: ");
            this.mimeTree.headers._rawHeaders.set("subject", [subject]);
          }
        }
      }
    }

    let boundary = getBoundary(mimePart);
    if (!boundary)
      boundary = EnigmailMime.createBoundary();

    // append relevant headers
    mimePart.headers.get("content-type").type = "multipart/mixed";
    mimePart.headers._rawHeaders.set("content-type", ['multipart/mixed; boundary="' + boundary + '"']);
    mimePart.subParts = [{
      body: ret.decryptedData,
      decryptedPgpMime: true,
      partNum: mimePart.partNum + ".1",
      headers: {
        _rawHeaders: new Map(),
        get: function() {
          return null;
        },
        has: function() {
          return false;
        }
      },
      subParts: []
    }];


    this.messageDecrypted = true;
  },

  decryptAttachment: async function(mimePart) {

    EnigmailLog.DEBUG("persistentCrypto.jsm: decryptAttachment()\n");
    let attachmentHead = mimePart.body.substr(0, 30);
    if (attachmentHead.search(/-----BEGIN PGP \w{5,10} KEY BLOCK-----/) >= 0) {
      // attachment appears to be a PGP key file, we just go-a-head
      return;
    }

    let attachmentName = getAttachmentName(mimePart);
    attachmentName = attachmentName ? attachmentName.replace(/\.(pgp|asc|gpg)$/, "") : "";

    let exitCode = -1,
      ret = null;
    const cApi = EnigmailCryptoAPI();

    do {
      // loop to allow for multiple tries of the passphrase
      try {
        ret = await cApi.decrypt(mimePart.body, {
          uiFlags: EnigmailConstants.UI_INTERACTIVE | EnigmailConstants.UI_UNVERIFIED_ENC_OK |
            EnigmailConstants.UI_IGNORE_MDC_ERROR
        });
      }
      catch (ex) {
        ret = {
          exitCode: -1,
          decryptedData: "",
          statusFlags: 0
        };
      }

      if ((ret.decryptedData && ret.decryptedData.length > 0) ||
        (ret.statusFlags & EnigmailConstants.DECRYPTION_OKAY)) {
        EnigmailLog.DEBUG("persistentCrypto.jsm: decryptAttachment: decryption OK\n");
        exitCode = 0;
      }
      else if (ret.statusFlags & (EnigmailConstants.DECRYPTION_FAILED | EnigmailConstants.MISSING_MDC)) {
        EnigmailLog.DEBUG("persistentCrypto.jsm: decryptAttachment: decryption without MDC protection\n");
        exitCode = 0;
      }
      else if (ret.statusFlags & EnigmailConstants.DECRYPTION_FAILED) {
        EnigmailLog.DEBUG("persistentCrypto.jsm: decryptAttachment: decryption failed\n");
        // since we cannot find out if the user wants to cancel
        // we should ask
        let msg = EnigmailLocale.getString("converter.decryptAtt.failed", [attachmentName, this.subject]);

        if (!getDialog().confirmDlg(null, msg,
            EnigmailLocale.getString("dlg.button.retry"), EnigmailLocale.getString("dlg.button.skip"))) {
          return;
        }
      }
      else if (ret.statusFlags & EnigmailConstants.DECRYPTION_INCOMPLETE) {
        // failure; message not complete
        EnigmailLog.DEBUG("persistentCrypto.jsm: decryptAttachment: decryption incomplete\n");
        return;
      }
      else {
        // there is nothing to be decrypted
        EnigmailLog.DEBUG("persistentCrypto.jsm: decryptAttachment: no decryption required\n");
        return;
      }

    } while (exitCode !== 0);


    EnigmailLog.DEBUG("persistentCrypto.jsm: decryptAttachment: decrypted to " + ret.decryptedData.length + " bytes\n");
    if (ret.encryptedFileName && ret.encryptedFileName.length > 0) {
      attachmentName = ret.encryptedFileName;
    }

    this.decryptedMessage = true;
    mimePart.body = ret.decryptedData;
    mimePart.headers._rawHeaders.set("content-disposition", `attachment; filename="${attachmentName}"`);
    mimePart.headers._rawHeaders.set("content-transfer-encoding", ["base64"]);
    let origCt = mimePart.headers.get("content-type");
    let ct = origCt.type;


    for (let i of origCt.entries()) {
      if (i[0].toLowerCase() === "name") {
        i[1] = i[1].replace(/\.(pgp|asc|gpg)$/, "");
      }
      ct += `; ${i[0]}="${i[1]}"`;
    }

    mimePart.headers._rawHeaders.set("content-type", [ct]);
  },


  decryptINLINE: async function(mimePart) {
    EnigmailLog.DEBUG("persistentCrypto.jsm: decryptINLINE()\n");

    if (("decryptedPgpMime" in mimePart) && mimePart.decryptedPgpMime) {
      return 0;
    }

    if ("body" in mimePart && mimePart.body.length > 0) {
      let ct = getContentType(mimePart);

      if (ct === "text/html") {
        mimePart.body = this.stripHTMLFromArmoredBlocks(mimePart.body);
      }

      const uiFlags = EnigmailConstants.UI_INTERACTIVE | EnigmailConstants.UI_UNVERIFIED_ENC_OK |
        EnigmailConstants.UI_IGNORE_MDC_ERROR;

      var plaintexts = [];
      var blocks = EnigmailArmor.locateArmoredBlocks(mimePart.body);
      var tmp = [];

      for (let i = 0; i < blocks.length; i++) {
        if (blocks[i].blocktype == "MESSAGE") {
          tmp.push(blocks[i]);
        }
      }

      blocks = tmp;

      if (blocks.length < 1) {
        return 0;
      }

      let charset = "utf-8";
      const cApi = EnigmailCryptoAPI();

      for (let i = 0; i < blocks.length; i++) {
        let plaintext = null;
        do {
          let ciphertext = mimePart.body.substring(blocks[i].begin, blocks[i].end + 1);

          if (ciphertext.length === 0) {
            break;
          }

          let hdr = ciphertext.search(/(\r\r|\n\n|\r\n\r\n)/);
          if (hdr > 0) {
            let chset = ciphertext.substr(0, hdr).match(/^(charset:)(.*)$/mi);
            if (chset && chset.length == 3) {
              charset = chset[2].trim();
            }
          }

          let ret = null;
          try {
            ret = await cApi.decrypt(ciphertext, {
              uiFlags: uiFlags
            });

            plaintext = ret.decryptedData;
          }
          catch (ex) {
            ret = {
              errorMsg: "",
              statusFlags: 0,
              exitCode: -1
            };
          }

          if (!plaintext || plaintext.length === 0) {
            if (ret.statusFlags & EnigmailConstants.DISPLAY_MESSAGE) {
              getDialog().alert(null, ret.errorMsg);
              this.messageDecrypted = false;
              return -1;
            }

            if (ret.statusFlags & (EnigmailConstants.DECRYPTION_FAILED | EnigmailConstants.MISSING_MDC)) {
              EnigmailLog.DEBUG("persistentCrypto.jsm: decryptINLINE: no MDC protection, decrypting anyway\n");
            }
            if (ret.statusFlags & EnigmailConstants.DECRYPTION_FAILED) {
              // since we cannot find out if the user wants to cancel
              // we should ask
              let msg = EnigmailLocale.getString("converter.decryptBody.failed", this.subject);

              if (!getDialog().confirmDlg(null, msg,
                  EnigmailLocale.getString("dlg.button.retry"), EnigmailLocale.getString("dlg.button.skip"))) {
                this.messageDecrypted = false;
                return -1;
              }
            }
            else if (ret.statusFlags & EnigmailConstants.DECRYPTION_INCOMPLETE) {
              this.messageDecrypted = false;
              return -1;
            }
            else {
              plaintext = " ";
            }
          }

          if (ct === "text/html") {
            plaintext = plaintext.replace(/\n/ig, "<br/>\n");
          }

          let subject = "";
          if (this.mimeTree.headers.has("subject")) {
            subject = this.mimeTree.headers.get("subject");
          }

          if (i == 0 && this.mimeTree.headers.subject === "pEp" &&
            mimePart.partNum.length > 0 && mimePart.partNum.search(/[^01.]/) < 0) {

            let m = EnigmailMime.extractSubjectFromBody(plaintext);
            if (m) {
              plaintext = m.messageBody;
              this.mimeTree.headers._rawHeaders.set("subject", [m.subject]);
            }
          }

          if (plaintext) {
            plaintexts.push(plaintext);
          }
        } while (!plaintext || plaintext === "");
      }


      var decryptedMessage = mimePart.body.substring(0, blocks[0].begin) + plaintexts[0];
      for (let i = 1; i < blocks.length; i++) {
        decryptedMessage += mimePart.body.substring(blocks[i - 1].end + 1, blocks[i].begin + 1) + plaintexts[i];
      }

      decryptedMessage += mimePart.body.substring(blocks[(blocks.length - 1)].end + 1);

      // enable base64 encoding if non-ASCII character(s) found
      let j = decryptedMessage.search(/[^\x01-\x7F]/); // eslint-disable-line no-control-regex
      if (j >= 0) {
        mimePart.headers._rawHeaders.set('content-transfer-encoding', ['base64']);
      }
      else {
        mimePart.headers._rawHeaders.set('content-transfer-encoding', ['8bit']);
      }
      mimePart.body = decryptedMessage;

      let origCharset = getCharset(mimePart);
      if (origCharset) {
        mimePart.headers._rawHeaders.set('content-type', getHeaderValue(mimePart, 'content-type').toString().replace(origCharset, charset));
      }
      else {
        mimePart.headers._rawHeaders.set('content-type', getHeaderValue(mimePart, 'content-type') + "; charset=" + charset);
      }

      this.messageDecrypted = true;
      return 1;
    }

    let ct = getContentType(mimePart);
    EnigmailLog.DEBUG("persistentCrypto.jsm: Decryption skipped:  " + ct + "\n");

    return 0;
  },

  stripHTMLFromArmoredBlocks: function(text) {

    var index = 0;
    var begin = text.indexOf("-----BEGIN PGP");
    var end = text.indexOf("-----END PGP");

    while (begin > -1 && end > -1) {
      let sub = text.substring(begin, end);

      sub = sub.replace(/(<([^>]+)>)/ig, "");
      sub = sub.replace(/&[A-z]+;/ig, "");

      text = text.substring(0, begin) + sub + text.substring(end);

      index = end + 10;
      begin = text.indexOf("-----BEGIN PGP", index);
      end = text.indexOf("-----END PGP", index);
    }

    return text;
  },


  /******
   *
   *    We have the technology we can rebuild.
   *
   *    Function to reassemble the message from the MIME Tree
   *    into a String.
   *
   ******/

  mimeToString: function(mimePart, includeHeaders, convertCharset = false) {
    EnigmailLog.DEBUG("persistentCrypto.jsm: mimeToString: part: '" + mimePart.partNum + "'\n");

    let msg = "",
      encoding = "";
    if (mimePart.body.length > 0) {
      encoding = getTransferEncoding(mimePart);
      if (!encoding) encoding = "8bit";

      if (encoding === "quoted-printable") {
        mimePart.headers._rawHeaders.set("content-transfer-encoding", ["base64"]);
        encoding = "base64";
      }

      if (encoding === "base64") {
        // eslint-disable-next-line no-control-regex
        if (mimePart.body.search(/[^\x00-\xFF]/) >= 0) {
          // convert to UTF-8 if ASCII character > 255 found
          mimePart.body = EnigmailData.convertFromUnicode(mimePart.body, "utf-8");
          setCharset(mimePart, "utf-8");
        }
      }

      if (convertCharset && encoding === "8bit") {
        let cs = getCharset(mimePart);
        if (cs && (cs.search(/utf-?8/i) < 0)) {
          mimePart.body = EnigmailData.convertFromUnicode(mimePart.body, cs);
          mimePart.headers._rawHeaders.set("content-transfer-encoding", ["base64"]);
          encoding = "base64";
        }
      }
    }

    let rawHdr = mimePart.headers._rawHeaders;

    if (includeHeaders && rawHdr.size > 0) {
      for (let hdr of rawHdr.keys()) {
        msg += formatMimeHeader(hdr, rawHdr.get(hdr)) + "\r\n";
      }

      msg += "\r\n";
    }

    if (mimePart.body.length > 0) {
      if (encoding === "base64") {
        msg += EnigmailData.encodeBase64(mimePart.body);
      }
      else {
        msg += mimePart.body;
      }

    }

    if (mimePart.subParts.length > 0) {
      let boundary = EnigmailMime.getBoundary(rawHdr.get("content-type").join(""));

      for (let i in mimePart.subParts) {
        msg += `--${boundary}\r\n`;
        msg += this.mimeToString(mimePart.subParts[i], true);
        if (msg.search(/[\r\n]$/) < 0) {
          msg += "\r\n";
        }
      }

      msg += `--${boundary}--\r\n`;
    }
    return msg;
  },

  storeMessage: function(msg) {
    return EnigmailPersistentCrypto.copyMessageToFolder(this.hdr, this.destFolder, this.move, msg, false);
  },

  fixExchangeMessage: function(mimePart) {
    EnigmailLog.DEBUG("persistentCrypto.jsm: fixExchangeMessage()\n");

    const FixEx = getFixExchangeMsg();

    let msg = this.mimeToString(mimePart, true);
    let app = FixEx.determineCreatorApp(msg);

    try {
      let fixedMsg = FixEx.getRepairedMessage(msg);
      let replacement = EnigmailMime.getMimeTree(fixedMsg, true);

      for (let i in replacement) {
        mimePart[i] = replacement[i];
      }
    }
    catch (ex) {}
  }
};


/**
 * Format a mime header
 *
 * e.g. content-type -> Content-Type
 */

function formatHeader(headerLabel) {
  return headerLabel.replace(/^.|(-.)/g, function(match) {
    return match.toUpperCase();
  });
}

function formatMimeHeader(headerLabel, headerValue) {
  if (Array.isArray(headerValue)) {
    headerValue = headerValue.join("");
  }
  if (headerLabel.search(/^(sender|from|reply-to|to|cc|bcc)$/i) === 0) {
    return formatHeader(headerLabel) + ": " + EnigmailMime.formatHeaderData(EnigmailMime.formatEmailAddress(headerValue));
  }
  else {
    return formatHeader(headerLabel) + ": " + EnigmailMime.formatHeaderData(EnigmailMime.encodeHeaderValue(headerValue));
  }
}


function prettyPrintHeader(headerLabel, headerData) {
  let hdrData = "";
  if (Array.isArray(headerData)) {
    let h = [];
    for (let i in headerData) {
      h.push(formatMimeHeader(headerLabel, GlodaUtils.deMime(headerData[i])));
    }
    return h.join("\r\n");
  }
  else {
    return formatMimeHeader(headerLabel, GlodaUtils.deMime(String(headerData)));
  }
}

function getHeaderValue(mimeStruct, header) {
  EnigmailLog.DEBUG("persistentCrypto.jsm: getHeaderValue: '" + header + "'\n");

  try {
    if (mimeStruct.headers.has(header)) {
      let hdrVal = mimeStruct.headers.get(header);
      if (typeof hdrVal == "string") {
        return hdrVal;
      }
      else {
        return mimeStruct.headers.getRawHeader(header);
      }
    }
    else {
      return "";
    }
  }
  catch (ex) {
    EnigmailLog.DEBUG("persistentCrypto.jsm: getHeaderValue: header not present\n");
    return "";
  }
}

/***
 * get the formatted headers for MimeMessage objects
 *
 * @headerArr:        Array of headers (key/value pairs), such as mime.headers
 * @ignoreHeadersArr: Array of headers to exclude from returning
 *
 * @return:   String containing formatted header list
 */
function getRfc822Headers(headerArr, contentType, ignoreHeadersArr) {
  let hdrs = "";

  let ignore = [];
  if (contentType.indexOf("multipart/") >= 0) {
    ignore = ['content-transfer-encoding',
      'content-disposition',
      'content-description'
    ];
  }

  if (ignoreHeadersArr) {
    ignore = ignore.concat(ignoreHeadersArr);
  }

  for (let i in headerArr) {
    if (ignore.indexOf(i) < 0) {
      hdrs += prettyPrintHeader(i, headerArr[i]) + "\r\n";
    }
  }

  return hdrs;
}

function getContentType(mime) {
  try {
    if (mime && ("headers" in mime) && mime.headers.has("content-type")) {
      return mime.headers.get("content-type").type.toLowerCase();
    }
  }
  catch (e) {
    EnigmailLog.DEBUG("persistentCrypto.jsm: getContentType: " + e + "\n");
  }
  return null;
}

// return the content of the boundary parameter
function getBoundary(mime) {
  try {
    if (mime && ("headers" in mime) && mime.headers.has("content-type")) {
      return mime.headers.get("content-type").get("boundary");
    }
  }
  catch (e) {
    EnigmailLog.DEBUG("persistentCrypto.jsm: getBoundary: " + e + "\n");
  }
  return null;
}

function getCharset(mime) {
  try {
    if (mime && ("headers" in mime) && mime.headers.has("content-type")) {
      let c = mime.headers.get("content-type").get("charset");
      if (c) return c.toLowerCase();
    }
  }
  catch (e) {
    EnigmailLog.DEBUG("persistentCrypto.jsm: getCharset: " + e + "\n");
  }
  return null;
}

/**
 * Replace the charset of a given message
 *
 * @param {Object} mime: mime part to work on
 * @param {String} newCharset: the new character set to use
 */
function setCharset(mime, newCharset) {
  try {
    if (mime && ("headers" in mime) && mime.headers.has("content-type")) {
      mime.headers.get("content-type").set("charset", newCharset);
      let ct = mime.headers.get("content-type").type;
      let it = mime.headers.get("content-type").entries();
      for (let i of it) {
        ct += '; ' + i[0] + '="' + i[1] + '"';
      }
      mime.headers._rawHeaders.set("content-type", [ct]);
    }
  }
  catch (e) {
    EnigmailLog.DEBUG("persistentCrypto.jsm: setCharset: " + e + "\n");
  }
}


function getProtocol(mime) {
  try {
    if (mime && ("headers" in mime) && mime.headers.has("content-type")) {
      let c = mime.headers.get("content-type").get("protocol");
      if (c) return c.toLowerCase();
    }
  }
  catch (e) {
    EnigmailLog.DEBUG("persistentCrypto.jsm: getProtocol: " + e + "\n");
  }
  return "";
}

function getTransferEncoding(mime) {
  try {
    if (mime && ("headers" in mime) && mime.headers._rawHeaders.has("content-transfer-encoding")) {
      let c = mime.headers._rawHeaders.get("content-transfer-encoding")[0];
      if (c) return c.toLowerCase();
    }
  }
  catch (e) {
    EnigmailLog.DEBUG("persistentCrypto.jsm: getTransferEncoding: " + e + "\n");
  }
  return "8Bit";
}

function isAttachment(mime) {
  try {
    if (mime && ("headers" in mime)) {
      if (mime.fullContentType.search(/^multipart\//i) === 0) return false;
      if (mime.fullContentType.search(/^text\//i) < 0) return true;

      if (mime.headers.has("content-disposition")) {
        let c = mime.headers.get("content-disposition")[0];
        if (c) {
          if (c.search(/^attachment/i) === 0) {
            return true;
          }
        }
      }
    }
  }
  catch (x) {}
  return false;
}


function getAttachmentName(mime) {
  try {
    if (mime && ("headers" in mime) && mime.headers.has("content-disposition")) {
      let c = mime.headers.get("content-disposition")[0];
      if (c) {
        if (c.search(/^attachment/i) === 0) {
          return EnigmailMime.getParameter(c, "filename");
        }
      }
    }
  }
  catch (e) {
    EnigmailLog.DEBUG("persistentCrypto.jsm: getAttachmentName: " + e + "\n");
  }
  return null;
}


function getPepSubject(mimeString) {
  EnigmailLog.DEBUG("persistentCrypto.jsm: getPepSubject()\n");

  let subject = null;

  let emitter = {
    ct: "",
    firstPlainText: false,
    startPart: function(partNum, headers) {
      EnigmailLog.DEBUG("persistentCrypto.jsm: getPepSubject.startPart: partNum=" + partNum + "\n");
      try {
        this.ct = String(headers.getRawHeader("content-type")).toLowerCase();
        if (!subject && !this.firstPlainText) {
          let s = headers.getRawHeader("subject");
          if (s) {
            subject = String(s);
            this.firstPlainText = true;
          }
        }
      }
      catch (ex) {
        this.ct = "";
      }
    },

    endPart: function(partNum) {},

    deliverPartData: function(partNum, data) {
      EnigmailLog.DEBUG("persistentCrypto.jsm: getPepSubject.deliverPartData: partNum=" + partNum + " ct=" + this.ct + "\n");
      if (!this.firstPlainText && this.ct.search(/^text\/plain/) === 0) {
        // check data
        this.firstPlainText = true;

        let o = EnigmailMime.extractSubjectFromBody(data);
        if (o) {
          subject = o.subject;
        }
      }
    }
  };

  let opt = {
    strformat: "unicode",
    bodyformat: "decode"
  };

  try {
    let p = new jsmime.MimeParser(emitter, opt);
    p.deliverData(mimeString);
  }
  catch (ex) {}

  return subject;
}

/**
 * Lazy deletion of original messages
 */
function deleteOriginalMail(msgHdr) {
  EnigmailLog.DEBUG("persistentCrypto.jsm: deleteOriginalMail(" + msgHdr.messageKey + ")\n");

  let delMsg = function() {
    try {
      EnigmailLog.DEBUG("persistentCrypto.jsm: deleting original message " + msgHdr.messageKey + "\n");
      EnigmailStdlib.msgHdrsDelete([msgHdr]);
    }
    catch (e) {
      EnigmailLog.DEBUG("persistentCrypto.jsm: deletion failed. Error: " + e.toString() + "\n");
    }
  };

  EnigmailTimer.setTimeout(delMsg, 500);
}
