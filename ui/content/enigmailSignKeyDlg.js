/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

"use strict";

var Cu = Components.utils;
var Cc = Components.classes;
var Ci = Components.interfaces;

var EnigmailCore = ChromeUtils.import("chrome://enigmail/content/modules/core.jsm").EnigmailCore;
var EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
var EnigmailLocale = ChromeUtils.import("chrome://enigmail/content/modules/locale.jsm").EnigmailLocale;
var EnigmailDialog = ChromeUtils.import("chrome://enigmail/content/modules/dialog.jsm").EnigmailDialog;
var EnigmailKeyRing = ChromeUtils.import("chrome://enigmail/content/modules/keyRing.jsm").EnigmailKeyRing;
var EnigmailTrust = ChromeUtils.import("chrome://enigmail/content/modules/trust.jsm").EnigmailTrust;
var EnigmailCryptoAPI = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI.jsm").EnigmailCryptoAPI;
var EnigmailKeyManagement = EnigmailCryptoAPI().getKeyManagement();

var gExportableSignatureList = null;
var gUidCount = null;
var gNumUid = 0;

function onLoad() {
  var key;
  var i;
  const cApi = EnigmailCryptoAPI();

  window.arguments[1].refresh = false;

  var enigmailSvc = EnigmailCore.getService(window);
  if (!enigmailSvc) {
    EnigmailDialog.alert(null, EnigmailLocale.getString("accessError"));
    window.close();
    return;
  }
  var keys = EnigmailKeyRing.getAllSecretKeys(true);
  if (keys.length === 0) {
    EnigmailDialog.info(null, EnigmailLocale.getString("noTrustedOwnKeys"));
    window.close();
    return;
  }
  if (!cApi.supportsFeature("smartcard")) {
    document.getElementById("ownKeyTrustLabel").setAttribute("collapsed", "true");
  }

  var menulist = document.getElementById("signWithKey");

  for (key of keys) {
    menulist.appendItem(key.userId + " - " + key.fprFormatted, key.fpr);
  }
  if (menulist.selectedIndex == -1) {
    menulist.selectedIndex = 0;
  }

  // determine keys that have already signed the key
  try {
    gExportableSignatureList = [];
    var sigType = null;
    gUidCount = [];

    var keyObj = EnigmailKeyRing.getKeyById(window.arguments[0].keyId);

    if (keyObj) {
      gUidCount[keyObj.keyId] = 1;

      for (i in keyObj.signatures) {
        gUidCount[keyObj.keyId]++;
        let s = keyObj.signatures[i];
        for (let j in s.sigList) {
          sigType = s.sigList[j].sigType.charAt(s.sigList[j].sigType.length - 1);

          let signer = s.sigList[j].signerKeyId;

          if (sigType === "x") {
            if (gExportableSignatureList[signer] === undefined) {
              gExportableSignatureList[signer] = 1;
            }
            else {
              gExportableSignatureList[signer] += 1;
            }
          }
        }
      }
    }
    enigKeySelCb();

    var keyDesc = keyObj.userId + " - 0x" + keyObj.keyId;
    document.getElementById("keyId").value = keyDesc;
    if (keyObj.fpr && keyObj.fpr.length > 0) {
      document.getElementById("fingerprint").value = keyObj.fprFormatted;
    }

    document.getElementById("checkbox-uid-0").setAttribute("label", keyObj.userId);

    if (keyObj.hasSubUserIds()) {
      let sUid = document.getElementById("uidForSigning");
      let nUid = 0;

      for (let j = 1; j < keyObj.userIds.length; j++) {
        if (keyObj.userIds[j].type === "uid" && (!EnigmailTrust.isInvalid(keyObj.userIds[j].keyTrust))) {
          ++nUid;
          sUid.appendChild(createRowElem(keyObj.userIds[j].userId, nUid));
        }
      }

      gNumUid = nUid;
    }
  }
  catch (ex) {}
}

function createRowElem(uidLabel, idNum) {
  let hbox = document.createXULElement("hbox");
  hbox.setAttribute("align", "center");
  let chk = document.createXULElement("checkbox");
  chk.id = `checkbox-uid-${idNum}`;
  chk.setAttribute("checked", "true");
  chk.setAttribute("label", uidLabel);
  hbox.appendChild(chk);
  return hbox;
}

function onAccept() {
  var signWithKey = document.getElementById("signWithKey");

  var enigmailSvc = EnigmailCore.getService(window);
  if (!enigmailSvc) {
    EnigmailDialog.alert(window, EnigmailLocale.getString("accessError"));
    return true;
  }

  let signUids = [];

  for (let i = 0; i <= gNumUid; i++) {
    if (document.getElementById(`checkbox-uid-${i}`).getAttribute("checked") === "true") {
      signUids.push(document.getElementById(`checkbox-uid-${i}`).getAttribute("label"));
    }
  }

  EnigmailKeyManagement.signKey(window,
    "0x" + signWithKey.selectedItem.value,
    window.arguments[0].keyId,
    [...new Set(signUids)], // make UIDs unique
    false,
    "0"
  ).then(resultObj => {
    if (resultObj.returnCode !== 0) {
      EnigmailDialog.alert(window, EnigmailLocale.getString("signKeyFailed") + "\n\n" + resultObj.errorMsg);
    }
    else {
      EnigmailKeyRing.updateKeys([window.arguments[0].keyId]);
    }
    window.close();
  });

  return false; // wait with closing until task terminated
}

function enigKeySelCb() {
  var keyToBeSigned = window.arguments[0].keyId;
  var signWithKey = document.getElementById("signWithKey");
  var signWithKeyId = signWithKey.selectedItem.value;
  var alreadySigned = document.getElementById("alreadySigned");
  var acceptButton = document.getElementById("enigmailSignKeyDlg").getButton("accept");
  var signatureCount = 0;

  signatureCount = gExportableSignatureList[signWithKeyId];

  if (gExportableSignatureList[signWithKeyId] > 0) {
    // User tries to locally sign a key he has already signed (at least partially) with an exportable signature
    // Here we display a hint and DISable the OK button
    alreadySigned.setAttribute("value", EnigmailLocale.getString("alreadySignedexportable.label", "0x" + keyToBeSigned));
    alreadySigned.removeAttribute("collapsed");
    acceptButton.disabled = true;
  }
  else if (signatureCount === undefined) {
    // No signature yet, Hide hint field and ENable OK button
    alreadySigned.setAttribute("collapsed", "true");
    acceptButton.disabled = false;
  }
  else if (signatureCount == gUidCount[keyToBeSigned]) {
    // Signature count == UID count, so key is already fully signed and another signing operation makes no more sense
    // Here, we display a hint and DISable the OK button
    alreadySigned.setAttribute("value", EnigmailLocale.getString("alreadySigned.label", "0x" + keyToBeSigned));
    alreadySigned.removeAttribute("collapsed");
    acceptButton.disabled = true;
  }
  else if (signatureCount > 0) {
    // Signature count != UID count, so key is partly signed and another sign operation makes sense
    // Here, we display a hint and ENable the OK button
    alreadySigned.setAttribute("value", EnigmailLocale.getString("partlySigned.label", "0x" + keyToBeSigned));
    alreadySigned.removeAttribute("collapsed");
    acceptButton.disabled = false;
  }
  else {
    // Default catch for unforeseen cases. Hide hint field and enable OK button
    alreadySigned.setAttribute("collapsed", "true");
    acceptButton.disabled = false;
  }
}

document.addEventListener("dialogaccept", function(event) {
  if (!onAccept())
    event.preventDefault(); // Prevent the dialog closing.
});
