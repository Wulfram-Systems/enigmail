/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */


"use strict";

var EXPORTED_SYMBOLS = ["EnigmailFixExchangeMsg"];

const EnigmailCompat = ChromeUtils.import("chrome://enigmail/content/modules/compat.jsm").EnigmailCompat;
const EnigmailCore = ChromeUtils.import("chrome://enigmail/content/modules/core.jsm").EnigmailCore;
const EnigmailFuncs = ChromeUtils.import("chrome://enigmail/content/modules/funcs.jsm").EnigmailFuncs;
const EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
const EnigmailStreams = ChromeUtils.import("chrome://enigmail/content/modules/streams.jsm").EnigmailStreams;
const EnigmailMime = ChromeUtils.import("chrome://enigmail/content/modules/mime.jsm").EnigmailMime;
const EnigmailPersistentCrypto = ChromeUtils.import("chrome://enigmail/content/modules/persistentCrypto.jsm").EnigmailPersistentCrypto;

const IOSERVICE_CONTRACTID = "@mozilla.org/network/io-service;1";

/*
 *  Fix a broken message from MS-Exchange and replace it with the original message
 *
 * @param nsIMsgDBHdr hdr          Header of the message to fix (= pointer to message)
 * @param String brokenByApp       Type of app that created the message. Currently one of
 *                                  exchange, iPGMail
 * @param String destFolderUri     optional destination Folder URI
 * @param nsIWindow  win           optional messenger window
 *
 * @return Promise; upon success, the promise returns the messageKey
 */
var EnigmailFixExchangeMsg = {
  fixExchangeMessage: async function(hdr, brokenByApp, destFolderUri = null, win = null) {
    let msgUriSpec = hdr.folder.getUriForMsg(hdr);
    EnigmailLog.DEBUG("fixExchangeMsg.jsm: fixExchangeMessage: msgUriSpec: " + msgUriSpec + "\n");

    this.hdr = hdr;
    this.window = win;
    this.brokenByApp = brokenByApp;
    this.destFolderUri = destFolderUri;

    let messenger = Cc["@mozilla.org/messenger;1"].createInstance(Ci.nsIMessenger);
    this.msgSvc = messenger.messageServiceFromURI(msgUriSpec);

    try {
      let fixedMsgData = await this.getMessageBody();

      EnigmailLog.DEBUG("fixExchangeMsg.jsm: fixExchangeMessage: got fixedMsgData\n");
      if (this.checkMessageStructure(fixedMsgData)) {
        await this.copyToTargetFolder(fixedMsgData);
      }
      else {
        throw "copyToTargetFolder failed";
      }
    }
    catch (reason) {
      EnigmailLog.DEBUG("fixExchangeMsg.jsm: fixExchangeMessage: caught rejection: " + reason + "\n");
    }
  },

  getMessageBody: function() {
    EnigmailLog.DEBUG("fixExchangeMsg.jsm: getMessageBody:\n");

    var self = this;

    return new Promise(
      function(resolve, reject) {
        let url = EnigmailCompat.getUrlFromUriSpec(self.hdr.folder.getUriForMsg(self.hdr));

        EnigmailLog.DEBUG("fixExchangeMsg.jsm: getting data from URL " + url + "\n");

        let s = EnigmailStreams.newStringStreamListener(
          function analyzeData(data) {
            EnigmailLog.DEBUG("fixExchangeMsg.jsm: analyzeDecryptedData: got " + data.length + " bytes\n");

            if (EnigmailLog.getLogLevel() > 5) {
              EnigmailLog.DEBUG("*** start data ***\n'" + data + "'\n***end data***\n");
            }

            try {
              let msg = self.getRepairedMessage(data);

              if (msg) {
                resolve(msg);
              }
              else
                reject(2);
              return;

            }
            catch (ex) {
              reject(ex);
            }
          }
        );

        var ioServ = Components.classes[IOSERVICE_CONTRACTID].getService(Components.interfaces.nsIIOService);
        try {
          let channel = EnigmailStreams.createChannel(url);
          channel.asyncOpen(s, null);
        }
        catch (e) {
          EnigmailLog.DEBUG("fixExchangeMsg.jsm: getMessageBody: exception " + e + "\n");
        }
      }
    );
  },

  getRepairedMessage: function(data) {
    this.determineCreatorApp(data);

    let hdrEnd = data.search(/\r?\n\r?\n/);

    if (hdrEnd <= 0) {
      // cannot find end of header data
      throw 0;
    }

    let hdrLines = data.substr(0, hdrEnd).split(/\r?\n/);
    let hdrObj = this.getFixedHeaderData(hdrLines);

    if (hdrObj.headers.length === 0 || hdrObj.boundary.length === 0) {
      throw 1;
    }

    let boundary = hdrObj.boundary;
    let body;

    switch (this.brokenByApp) {
      case "exchange":
        body = this.getCorrectedExchangeBodyData(data.substr(hdrEnd + 2), boundary);
        break;
      case "iPGMail":
        body = this.getCorrectediPGMailBodyData(data.substr(hdrEnd + 2), boundary);
        break;
      default:
        EnigmailLog.ERROR("fixExchangeMsg.jsm: getRepairedMessage: unknown appType " + self.brokenByApp + "\n");
        throw 99;
    }

    if (body) {
      return hdrObj.headers + "\r\n" + body;
    }
    else {
      throw 2;
    }
  },

  determineCreatorApp: function(msgData) {
    // perform extra testing if iPGMail is assumed
    if (this.brokenByApp === "exchange") return;

    let msgTree = EnigmailMime.getMimeTree(msgData, false);

    try {
      let isIPGMail =
        msgTree.subParts.length === 3 &&
        msgTree.subParts[0].headers.get("content-type").type.toLowerCase() === "text/plain" &&
        msgTree.subParts[1].headers.get("content-type").type.toLowerCase() === "application/pgp-encrypted" &&
        msgTree.subParts[2].headers.get("content-type").type.toLowerCase() === "text/plain";

      if (!isIPGMail) {
        this.brokenByApp = "exchange";
      }
    }
    catch (x) {}
  },

  /**
   *  repair header data, such that they are working for PGP/MIME
   *
   *  @return: object: {
   *        headers:  String - all headers ready for appending to message
   *        boundary: String - MIME part boundary (incl. surrounding "" or '')
   *      }
   */
  getFixedHeaderData: function(hdrLines) {
    EnigmailLog.DEBUG("fixExchangeMsg.jsm: getFixedHeaderData: hdrLines[]:'" + hdrLines.length + "'\n");
    let r = {
      headers: "",
      boundary: ""
    };

    for (let i = 0; i < hdrLines.length; i++) {
      if (hdrLines[i].search(/^content-type:/i) >= 0) {
        // Join the rest of the content type lines together.
        // See RFC 2425, section 5.8.1
        let contentTypeLine = hdrLines[i];
        i++;
        while (i < hdrLines.length) {
          // Does the line start with a space or a tab, followed by something else?
          if (hdrLines[i].search(/^[ \t]+?/) === 0) {
            contentTypeLine += hdrLines[i];
            i++;
          }
          else {
            // we got the complete content-type header
            contentTypeLine = contentTypeLine.replace(/[\r\n]/g, "");
            let h = EnigmailFuncs.getHeaderData(contentTypeLine);
            r.boundary = h.boundary || "";
            break;
          }
        }
      }
      else {
        r.headers += hdrLines[i] + "\r\n";
      }
    }

    r.boundary = r.boundary.replace(/^(['"])(.*)(['"])/, "$2");

    r.headers += 'Content-Type: multipart/encrypted;\r\n' +
      '  protocol="application/pgp-encrypted";\r\n' +
      '  boundary="' + r.boundary + '"\r\n' +
      'X-Enigmail-Info: Fixed broken PGP/MIME message\r\n';

    return r;
  },


  /**
   * Get corrected body for MS-Exchange messages
   */
  getCorrectedExchangeBodyData: function(bodyData, boundary) {
    EnigmailLog.DEBUG("fixExchangeMsg.jsm: getCorrectedExchangeBodyData: boundary='" + boundary + "'\n");
    let boundRx = new RegExp("^--" + boundary.replace(/[.*+\-?^${}()|[\]\\]/g, "\\$&"), "gm");
    let match = boundRx.exec(bodyData);

    if (match.index < 0) {
      EnigmailLog.DEBUG("fixExchangeMsg.jsm: getCorrectedExchangeBodyData: did not find index of mime type to skip\n");
      return null;
    }

    let skipStart = match.index;
    // found first instance -- that's the message part to ignore
    match = boundRx.exec(bodyData);
    if (match.index <= 0) {
      EnigmailLog.DEBUG("fixExchangeMsg.jsm: getCorrectedExchangeBodyData: did not find boundary of PGP/MIME version identification\n");
      return null;
    }

    let versionIdent = match.index;

    if (bodyData.substring(skipStart, versionIdent).search(/^content-type:[ \t]*text\/(plain|html)/mi) < 0) {
      EnigmailLog.DEBUG("fixExchangeMsg.jsm: getCorrectedExchangeBodyData: first MIME part is not content-type text/plain or text/html\n");
      return null;
    }

    match = boundRx.exec(bodyData);
    if (match.index < 0) {
      EnigmailLog.DEBUG("fixExchangeMsg.jsm: getCorrectedExchangeBodyData: did not find boundary of PGP/MIME encrypted data\n");
      return null;
    }

    let encData = match.index;
    let mimeHdr = Cc["@mozilla.org/messenger/mimeheaders;1"].createInstance(Ci.nsIMimeHeaders);
    mimeHdr.initialize(bodyData.substring(versionIdent, encData));
    let ct = mimeHdr.extractHeader("content-type", false);

    if (!ct || ct.search(/application\/pgp-encrypted/i) < 0) {
      EnigmailLog.DEBUG("fixExchangeMsg.jsm: getCorrectedExchangeBodyData: wrong content-type of version-identification\n");
      EnigmailLog.DEBUG("   ct = '" + ct + "'\n");
      return null;
    }

    mimeHdr.initialize(bodyData.substr(encData, 5000));
    ct = mimeHdr.extractHeader("content-type", false);
    if (!ct || ct.search(/application\/octet-stream/i) < 0) {
      EnigmailLog.DEBUG("fixExchangeMsg.jsm: getCorrectedExchangeBodyData: wrong content-type of PGP/MIME data\n");
      EnigmailLog.DEBUG("   ct = '" + ct + "'\n");
      return null;
    }

    return bodyData.substr(versionIdent);
  },


  /**
   * Get corrected body for iPGMail messages
   */
  getCorrectediPGMailBodyData: function(bodyData, boundary) {
    EnigmailLog.DEBUG("fixExchangeMsg.jsm: getCorrectediPGMailBodyData: boundary='" + boundary + "'\n");
    let boundRx = new RegExp("^--" + boundary.replace(/[.*+\-?^${}()|[\]\\]/g, "\\$&"), "gm");
    let match = boundRx.exec(bodyData);

    if (match.index < 0) {
      EnigmailLog.DEBUG("fixExchangeMsg.jsm: getCorrectediPGMailBodyData: did not find index of mime type to skip\n");
      return null;
    }

    let skipStart = match.index;
    // found first instance -- that's the message part to ignore
    match = boundRx.exec(bodyData);
    if (match.index <= 0) {
      EnigmailLog.DEBUG("fixExchangeMsg.jsm: getCorrectediPGMailBodyData: did not find boundary of text/plain msg part\n");
      return null;
    }

    let encData = match.index;

    match = boundRx.exec(bodyData);
    if (match.index < 0) {
      EnigmailLog.DEBUG("fixExchangeMsg.jsm: getCorrectediPGMailBodyData: did not find end boundary of PGP/MIME encrypted data\n");
      return null;
    }

    let mimeHdr = Cc["@mozilla.org/messenger/mimeheaders;1"].createInstance(Ci.nsIMimeHeaders);

    mimeHdr.initialize(bodyData.substr(encData, 5000));
    let ct = mimeHdr.extractHeader("content-type", false);
    if (!ct || ct.search(/application\/pgp-encrypted/i) < 0) {
      EnigmailLog.DEBUG("fixExchangeMsg.jsm: getCorrectediPGMailBodyData: wrong content-type of PGP/MIME data\n");
      EnigmailLog.DEBUG("   ct = '" + ct + "'\n");
      return null;
    }

    return "--" + boundary + "\r\n" +
      "Content-Type: application/pgp-encrypted\r\n" +
      "Content-Description: PGP/MIME version identification\r\n\r\n" +
      "Version: 1\r\n\r\n" +
      bodyData.substring(encData, match.index).replace(/^Content-Type: +application\/pgp-encrypted/im,
        "Content-Type: application/octet-stream") +
      "--" + boundary + "--\r\n";
  },

  checkMessageStructure: function(msgData) {
    let msgTree = EnigmailMime.getMimeTree(msgData, true);

    try {

      // check message structure
      let ok =
        msgTree.headers.get("content-type").type.toLowerCase() === "multipart/encrypted" &&
        msgTree.headers.get("content-type").get("protocol").toLowerCase() === "application/pgp-encrypted" &&
        msgTree.subParts.length === 2 &&
        msgTree.subParts[0].headers.get("content-type").type.toLowerCase() === "application/pgp-encrypted" &&
        msgTree.subParts[1].headers.get("content-type").type.toLowerCase() === "application/octet-stream";


      if (ok) {
        // check for existence of PGP Armor
        let body = msgTree.subParts[1].body;
        let p0 = body.search(/^-----BEGIN PGP MESSAGE-----$/m);
        let p1 = body.search(/^-----END PGP MESSAGE-----$/m);

        ok = (p0 >= 0 && p1 > p0 + 32);
      }
      return ok;
    }
    catch (x) {}
    return false;
  },

  copyToTargetFolder: function(msgData) {
    return EnigmailPersistentCrypto.copyMessageToFolder(this.hdr, this.destFolderUri, true, msgData, true, this.window);
  }
};
