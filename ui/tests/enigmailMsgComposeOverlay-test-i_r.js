/*global Enigmail: false, Assert: false, do_load_module: false, trustAllKeys_test: false, JSUnit: false, EnigmailConstants: false,
  EnigmailLocale: false, do_get_cwd: false, test: false */
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */


do_load_module("file://" + do_get_cwd().path + "/testHelper.js"); /*global withEnigmail: false, withTestGpgHome: false, asyncTest: false */

var window;
var document;

var EnigmailApp = {};
var getCurrentAccountKey = {};
var MailServices = {};
var CommandUpdate_MsgCompose = {};
var top = {};
var EnigmailDialog = {
  msgBox: function() {}
};
var AddAttachment;
var AddAttachments;
var EnigmailMimeEncrypt = {};
var Recipients2CompFields = {};
var GetResourceFromUri = {};
var EnigmailCore = {};

var gSMFields;

var EnigmailCompat = ChromeUtils.import("chrome://enigmail/content/modules/compat.jsm").EnigmailCompat;

var EnigmailPrefs = {
  getPref: (prop) => {
    return 1;
  },
  setPref: function() {}
};

var EnigmailTimer = {
  setTimeout: function() {}
};

var gMsgCompose = {};

function toggleEncryptMessage() {
  Assert.ok(true);
}

function toggleSignMessage() {
  Assert.ok(true);
}

var getCurrentIdentity = function() {

};

var EnigmailFuncs = {

};

function initialSendFlags_test() {

  Enigmail.msg.fireSendFlags = function() {
    Assert.ok(true);
  };

  Enigmail.msg.determineSendFlags = function() {
    Assert.ok(true);
  };

  Enigmail.msg.processFinalState = function() {
    Assert.ok(true);
  };

  Enigmail.msg.updateStatusBar = function() {
    Assert.ok(true);
  };

  EnigmailTimer.setTimeout = function() {
    Assert.ok(true);
  };

  Enigmail.msg.initialSendFlags();
}

function initRadioMenu_test() {

  EnigmailPrefs.getPref = function(prefName) {
    Assert.equal(prefName, 'prefName');
    return 1;
  };

  document.getElementById = function() {
    Assert.ok(false);
  };

  Enigmail.msg.initRadioMenu('prefName', ['option1']);

  EnigmailPrefs.getPref = function(prefName) {
    Assert.equal(prefName, 'prefName');
    return 1;
  };

  document.getElementById = function(val) {
    Assert.equal(val, 'enigmail_option2');
    return {
      setAttribute: function(prop, val) {
        Assert.equal(prop, "checked");
        Assert.equal(val, "true");
      }
    };
  };

  Enigmail.msg.initRadioMenu('prefName', ['option1', 'option2']);
}

function isEnigmailEnabled_test() {

  Enigmail.msg.identity = {
    getBoolAttribute: function() {
      Assert.ok(true);
      return true;
    }
  };
  let ret = Enigmail.msg.isEnigmailEnabled();
  Assert.equal(ret, true);

}

function isSendConfirmationRequired_test() {
  EnigmailPrefs.getPref = function() {
    return 0;
  };

  Enigmail.msg.statusPGPMime = EnigmailConstants.ENIG_FINAL_SMIME;

  let ret = Enigmail.msg.isSendConfirmationRequired(0x0002);
  Assert.equal(ret, false);

  EnigmailPrefs.getPref = function() {
    return 1;
  };

  ret = Enigmail.msg.isSendConfirmationRequired(0x0002);
  Assert.equal(ret, true);

  EnigmailPrefs.getPref = function() {
    return 2;
  };

  ret = Enigmail.msg.isSendConfirmationRequired(0x0002);
  Assert.equal(ret, true);

  EnigmailPrefs.getPref = function() {
    return 2;
  };

  ret = Enigmail.msg.isSendConfirmationRequired(0x0001);
  Assert.equal(ret, false);

  EnigmailPrefs.getPref = function() {
    return 3;
  };

  ret = Enigmail.msg.isSendConfirmationRequired(0x0001);
  Assert.equal(ret, true);

  EnigmailPrefs.getPref = function() {
    return 3;
  };

  ret = Enigmail.msg.isSendConfirmationRequired(0x0002);
  Assert.equal(ret, false);

  EnigmailPrefs.getPref = function() {
    return 4;
  };

  Enigmail.msg.sendMode = 0x0001;

  ret = Enigmail.msg.isSendConfirmationRequired(0x0002);
  Assert.equal(ret, true);

  Enigmail.msg.sendMode = 0x0002;

  ret = Enigmail.msg.isSendConfirmationRequired(0x0002);
  Assert.equal(ret, false);

  Enigmail.msg.statusPGPMime = null;
  Enigmail.msg.statusEncrypted = EnigmailConstants.ENIG_FINAL_YES;

  EnigmailDialog.confirmDlg = function() {
    return false;
  };

  ret = Enigmail.msg.isSendConfirmationRequired(0x0001);
  Assert.equal(ret, null);

  Enigmail.msg.statusPGPMime = null;
  Enigmail.msg.statusEncrypted = EnigmailConstants.ENIG_FINAL_YES;

  EnigmailDialog.confirmDlg = function() {
    return true;
  };

  ret = Enigmail.msg.isSendConfirmationRequired(0x0001);
  Assert.equal(ret, true);

  Enigmail.msg.statusEncrypted = EnigmailConstants.ENIG_FINAL_FORCEYES;

  ret = Enigmail.msg.isSendConfirmationRequired(0x0001);
  Assert.equal(ret, true);

  Enigmail.msg.statusEncrypted = null;
  Enigmail.msg.statusEncryptedInStatusBar = EnigmailConstants.ENIG_FINAL_YES;

  ret = Enigmail.msg.isSendConfirmationRequired(0x0001);
  Assert.equal(ret, true);

  Enigmail.msg.statusEncrypted = null;
  Enigmail.msg.statusEncryptedInStatusBar = EnigmailConstants.ENIG_FINAL_FORCEYES;

  ret = Enigmail.msg.isSendConfirmationRequired(0x0001);
  Assert.equal(ret, true);

}

function isSmimeEnabled_test() {

  getCurrentIdentity = function() {
    //Function Overriding
    return {
      getUnicharAttribute: function() {
        return "";
      }
    };
  };

  var ret = Enigmail.msg.isSmimeEnabled();
  Assert.equal(ret, false);

  getCurrentIdentity = function() {
    //Function Overriding
    return {
      getUnicharAttribute: function() {
        return "xyz";
      }
    };
  };

  ret = Enigmail.msg.isSmimeEnabled();
  Assert.equal(ret, true);
}

function isSmimeEncryptionPossible_test() {

  getCurrentIdentity = function() {
    return {
      getUnicharAttribute: function() {
        return "";
      }
    };
  };

  let ret = Enigmail.msg.isSmimeEncryptionPossible();
  Assert.equal(ret, false);

  getCurrentIdentity = function() {
    return {
      getUnicharAttribute: function() {
        return "string";
      }
    };
  };

  gMsgCompose.compFields = {
    hasRecipients: false
  };

  ret = Enigmail.msg.isSmimeEncryptionPossible();
  Assert.equal(ret, false);

  getCurrentIdentity = function() {
    return {
      getUnicharAttribute: function() {
        return "string";
      }
    };
  };

  gMsgCompose.compFields = {
    hasRecipients: true
  };

  ret = Enigmail.msg.isSmimeEncryptionPossible();
  Assert.equal(ret, true);

}

function modifyCompFields_test() {
  getCurrentIdentity = function() {
    Assert.ok(true);
    return true;
  };

  EnigmailApp = {
    getVersion: function() {
      Assert.ok(true);
    }
  };

  Enigmail.msg.setAdditionalHeader = function() {
    Assert.ok(true);
  };

  Enigmail.msg.isEnigmailEnabled = function() {
    Assert.ok(true);
  };

  EnigmailPrefs.getPref = function() {
    Assert.ok(true);
    return true;
  };

  Enigmail.msg.modifyCompFields();
}

function msgComposeReset_test() {
  Enigmail.msg.setIdentityDefaults = function() {
    Assert.ok(false);
  };

  Enigmail.msg.msgComposeReset(true);
  Assert.equal(Enigmail.msg.dirty, 0);
  Assert.equal(Enigmail.msg.processed, null);
  Assert.equal(Enigmail.msg.timeoutId, null);
  Assert.equal(Enigmail.msg.modifiedAttach, null);
  Assert.equal(Enigmail.msg.sendMode, 0);
  Assert.equal(Enigmail.msg.sendModeDirty, false);
  Assert.equal(Enigmail.msg.reasonEncrypted, "");
  Assert.equal(Enigmail.msg.reasonSigned, "");
  Assert.equal(Enigmail.msg.encryptByRules, EnigmailConstants.ENIG_UNDEF);
  Assert.equal(Enigmail.msg.signByRules, EnigmailConstants.ENIG_UNDEF);
  Assert.equal(Enigmail.msg.pgpmimeByRules, EnigmailConstants.ENIG_UNDEF);
  Assert.equal(Enigmail.msg.signForced, EnigmailConstants.ENIG_UNDEF);
  Assert.equal(Enigmail.msg.encryptForced, EnigmailConstants.ENIG_UNDEF);
  Assert.equal(Enigmail.msg.pgpmimeForced, EnigmailConstants.ENIG_UNDEF);
  Assert.equal(Enigmail.msg.finalSignDependsOnEncrypt, false);
  Assert.equal(Enigmail.msg.statusSigned, EnigmailConstants.ENIG_FINAL_UNDEF);
  Assert.equal(Enigmail.msg.statusEncrypted, EnigmailConstants.ENIG_FINAL_UNDEF);
  Assert.equal(Enigmail.msg.statusPGPMime, EnigmailConstants.ENIG_FINAL_UNDEF);
  Assert.equal(Enigmail.msg.statusEncryptedStr, "???");
  Assert.equal(Enigmail.msg.statusSignedStr, "???");
  Assert.equal(Enigmail.msg.statusPGPMimeStr, "???");
  Assert.equal(Enigmail.msg.statusAttachOwnKey, "???");
  Assert.equal(Enigmail.msg.enableRules, true);
  Assert.equal(Enigmail.msg.identity, null);
  Assert.equal(Enigmail.msg.sendProcess, false);
  Assert.equal(Enigmail.msg.trustAllKeys, false);
  Assert.equal(Enigmail.msg.mimePreferOpenPGP, 0);
  Assert.equal(Enigmail.msg.keyLookupDone.length, 0);

  Enigmail.msg.setIdentityDefaults = function() {
    Assert.ok(true);
  };

  Enigmail.msg.msgComposeReset(false);
}

function notifyUser_test() {
  let msgText = "Hello",
    messageId = "12",
    detailsText = "Text";

  document.getElementById = function() {
    return {
      appendNotification: function(msg_text, message_id, str, prio, button_arr) {
        Assert.equal(msgText, msgText);
        Assert.equal(message_id, messageId);
        Assert.equal(str, null);
        Assert.equal(prio, 1);
        Assert.equal(button_arr.length, 1);
      },
      PRIORITY_CRITICAL_MEDIUM: 1,
      PRIORITY_INFO_MEDIUM: 3,
      PRIORITY_WARNING_MEDIUM: 2
    };
  };
  Enigmail.msg.notifyUser(1, msgText, messageId, detailsText);

  document.getElementById = function() {
    return {
      appendNotification: function(msg_text, message_id, str, prio, button_arr) {
        Assert.equal(msgText, msgText);
        Assert.equal(message_id, messageId);
        Assert.equal(str, null);
        Assert.equal(prio, 2);
        Assert.equal(button_arr.length, 1);
      },
      PRIORITY_CRITICAL_MEDIUM: 1,
      PRIORITY_INFO_MEDIUM: 3,
      PRIORITY_WARNING_MEDIUM: 2
    };
  };
  Enigmail.msg.notifyUser(2, msgText, messageId, detailsText);

  document.getElementById = function() {
    return {
      appendNotification: function(msg_text, message_id, str, prio, button_arr) {
        Assert.equal(msgText, msgText);
        Assert.equal(message_id, messageId);
        Assert.equal(str, null);
        Assert.equal(prio, 3);
        Assert.equal(button_arr.length, 1);
      },
      PRIORITY_CRITICAL_MEDIUM: 1,
      PRIORITY_INFO_MEDIUM: 3,
      PRIORITY_WARNING_MEDIUM: 2
    };
  };
  Enigmail.msg.notifyUser(3, msgText, messageId, detailsText);
}


function preferPgpOverSmime_test() {
  let si = EnigmailCompat.getSecurityField();
  let secField;
  if (si === "securityInfo") {
    secField = Components.classes["@mozilla.org/messenger-smime/composefields;1"].createInstance(Ci.nsIMsgSMIMECompFields);
    gMsgCompose.compFields.securityInfo = secField;
  } else {
    secField = Cc["@mozilla.org/messengercompose/composesecure;1"].createInstance(Ci.nsIMsgComposeSecure);
    gMsgCompose.compFields.composeSecure = secField;
  }
  EnigmailMimeEncrypt.isEnigmailCompField = function(val) {
    return false;
  };

  let ret = Enigmail.msg.preferPgpOverSmime(0x0001);
  Assert.equal(ret, 1);

  Enigmail.msg.mimePreferOpenPGP = 2;

  ret = Enigmail.msg.preferPgpOverSmime(0x0203);
  Assert.equal(ret, 1);

  secField.requireEncryptMessage = 0;
  secField.signMessage = 1;

  ret = Enigmail.msg.preferPgpOverSmime(0x0203);
  Assert.equal(ret, 0);

  secField.signMessage = 0;

  ret = Enigmail.msg.preferPgpOverSmime(0x0203);
  Assert.equal(ret, 1);

  secField.signMessage = 1;

  ret = Enigmail.msg.preferPgpOverSmime(0x0003);
  Assert.equal(ret, 2);
}

function processAccountSpecificDefaultOptions_test() {

  Enigmail.msg.sendMode = 0;
  Enigmail.msg.sendPgpMime = "";

  Enigmail.msg.getSmimeSigningEnabled = function() {
    //Function Overriding
    return true;
  };

  Enigmail.msg.isEnigmailEnabled = function() {
    //Function Overriding
    return false;
  };

  Enigmail.msg.processAccountSpecificDefaultOptions();

  Assert.equal(Enigmail.msg.sendMode, 1);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("signReasonEnabledByDefault"));
  Assert.equal(Enigmail.msg.sendPgpMime, "");

  Enigmail.msg.isEnigmailEnabled = function() {
    //Function Overriding
    return true;
  };

  Enigmail.msg.getAccDefault = function() {
    //Function Overriding
    return true;
  };

  Enigmail.msg.setOwnKeyStatus = function() {
    //Function Overriding
  };

  Enigmail.msg.processAccountSpecificDefaultOptions();

  Assert.equal(Enigmail.msg.sendMode, 3);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("signReasonEnabledByDefault"));
  Assert.equal(Enigmail.msg.reasonEncrypted, EnigmailLocale.getString("encryptReasonEnabledByDefault"));
  Assert.equal(Enigmail.msg.sendPgpMime, true);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.appendAttachment, true);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.attachedObj, null);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.attachedKey, null);
  Assert.equal(Enigmail.msg.finalSignDependsOnEncrypt, true);

  Enigmail.msg.getAccDefault = function() {
    //Function Overriding
    return false;
  };

  Enigmail.msg.processAccountSpecificDefaultOptions();

  Assert.equal(Enigmail.msg.sendMode, 1);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("signReasonEnabledByDefault"));
  Assert.equal(Enigmail.msg.sendPgpMime, true);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.appendAttachment, false);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.attachedObj, null);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.attachedKey, null);
  Assert.equal(Enigmail.msg.finalSignDependsOnEncrypt, false);

  Enigmail.msg.getSmimeSigningEnabled = function() {
    //Function Overriding
    return false;
  };

  Enigmail.msg.processAccountSpecificDefaultOptions();

  Assert.equal(Enigmail.msg.sendMode, 0);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("signReasonEnabledByDefault"));
  Assert.equal(Enigmail.msg.sendPgpMime, true);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.appendAttachment, false);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.attachedObj, null);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.attachedKey, null);
  Assert.equal(Enigmail.msg.finalSignDependsOnEncrypt, false);

  Enigmail.msg.reasonSigned = "";

  Enigmail.msg.getAccDefault = function(str) {
    //Function Overriding
    if (str === "sign") {
      return false;
    } else {
      return true;
    }
  };

  Enigmail.msg.processAccountSpecificDefaultOptions();

  Assert.equal(Enigmail.msg.sendMode, 2);
  Assert.equal(Enigmail.msg.reasonSigned, "");
  Assert.equal(Enigmail.msg.reasonEncrypted, EnigmailLocale.getString("encryptReasonEnabledByDefault"));
  Assert.equal(Enigmail.msg.sendPgpMime, true);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.appendAttachment, true);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.attachedObj, null);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.attachedKey, null);
  Assert.equal(Enigmail.msg.finalSignDependsOnEncrypt, true);

}

function processFinalState_test() {
  // Encryption Status and Reason

  Enigmail.msg.isEnigmailEnabled = () => {
    //Function Overriding
    return false;
  };

  Enigmail.msg.isSmimeEnabled = () => {
    //Function Overriding
    return false;
  };

  Enigmail.msg.getAccDefault = (prop) => {
    //Function Overriding
    if (prop === "signIfEnc" || prop === "signIfNotEnc" || prop === "signIfNotEnc" || prop === "signIfEnc" || prop === "sign-pgp" || prop === "encrypt") {
      return true;
    } else {
      return false;
    }
  };

  // Testing Encryption Flags

  //Encryption reasonManuallyForced
  Enigmail.msg.encryptForced = EnigmailConstants.ENIG_NEVER;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusEncrypted, EnigmailConstants.ENIG_FINAL_FORCENO);
  Assert.equal(Enigmail.msg.reasonEncrypted, EnigmailLocale.getString("encryptReasonManuallyForced"));

  //Encryption reasonManuallyForced
  Enigmail.msg.encryptForced = EnigmailConstants.ENIG_ALWAYS;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusEncrypted, EnigmailConstants.ENIG_FINAL_FORCEYES);
  Assert.equal(Enigmail.msg.reasonEncrypted, EnigmailLocale.getString("encryptReasonManuallyForced"));

  //Encryption reasonByRecipientRules
  Enigmail.msg.encryptForced = null;
  Enigmail.msg.encryptByRules = EnigmailConstants.ENIG_NEVER;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusEncrypted, EnigmailConstants.ENIG_FINAL_NO);
  Assert.equal(Enigmail.msg.reasonEncrypted, EnigmailLocale.getString("encryptReasonByRecipientRules"));

  //Encryption reasonEnabledByDefault
  Enigmail.msg.encryptByRules = EnigmailConstants.ENIG_UNDEF;
  Enigmail.msg.sendMode = 0x0002;
  Enigmail.msg.isEnigmailEnabled = () => {
    //Function Overriding
    return true;
  };
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusEncrypted, EnigmailConstants.ENIG_FINAL_YES);
  Assert.equal(Enigmail.msg.reasonEncrypted, EnigmailLocale.getString("encryptReasonEnabledByDefault"));

  //Encryption reasonEmpty
  Enigmail.msg.encryptByRules = EnigmailConstants.ENIG_UNDEF;
  Enigmail.msg.sendMode = 0x0001;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusEncrypted, EnigmailConstants.ENIG_FINAL_NO);
  Assert.equal(Enigmail.msg.reasonEncrypted, "");

  //Encryption reasonByRecipientRules
  Enigmail.msg.encryptByRules = EnigmailConstants.ENIG_ALWAYS;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusEncrypted, EnigmailConstants.ENIG_FINAL_YES);
  Assert.equal(Enigmail.msg.reasonEncrypted, EnigmailLocale.getString("encryptReasonByRecipientRules"));

  //Encryption reasonByAutoEncryption
  Enigmail.msg.encryptByRules = EnigmailConstants.ENIG_AUTO_ALWAYS;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusEncrypted, EnigmailConstants.ENIG_FINAL_YES);
  Assert.equal(Enigmail.msg.reasonEncrypted, EnigmailLocale.getString("encryptReasonByAutoEncryption"));

  //Encryption reasonByConflict
  Enigmail.msg.encryptByRules = EnigmailConstants.ENIG_CONFLICT;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusEncrypted, EnigmailConstants.ENIG_FINAL_CONFLICT);
  Assert.equal(Enigmail.msg.reasonEncrypted, EnigmailLocale.getString("encryptReasonByConflict"));

  //Signing of Key

  //Signing reasonManuallyForced
  Enigmail.msg.signForced = EnigmailConstants.ENIG_NEVER;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusSigned, EnigmailConstants.ENIG_FINAL_FORCENO);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("signReasonManuallyForced"));

  //Signing reasonManuallyForced
  Enigmail.msg.signForced = EnigmailConstants.ENIG_ALWAYS;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusSigned, EnigmailConstants.ENIG_FINAL_FORCEYES);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("signReasonManuallyForced"));

  //Signing reasonByRecipientRules
  Enigmail.msg.signForced = null;
  Enigmail.msg.signByRules = EnigmailConstants.ENIG_NEVER;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusSigned, EnigmailConstants.ENIG_FINAL_NO);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("signReasonByRecipientRules"));

  //Signing reasonEnabledByDefault
  Enigmail.msg.signByRules = EnigmailConstants.ENIG_UNDEF;
  Enigmail.msg.sendMode = 0x0001;
  Enigmail.msg.finalSignDependsOnEncrypt = false;
  Enigmail.msg.isEnigmailEnabled = () => {
    //Function Overriding
    return true;
  };
  Enigmail.msg.getAccDefault = () => {
    //Function Overriding
    return true;
  };
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusSigned, EnigmailConstants.ENIG_FINAL_YES);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("signReasonEnabledByDefault"));

  //Signing reasonEmpty
  Enigmail.msg.signByRules = EnigmailConstants.ENIG_UNDEF;
  Enigmail.msg.sendMode = 0x0002;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusSigned, EnigmailConstants.ENIG_FINAL_NO);
  Assert.equal(Enigmail.msg.reasonSigned, "");

  //Signing reasonByRecipientRules
  Enigmail.msg.signByRules = EnigmailConstants.ENIG_ALWAYS;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusSigned, EnigmailConstants.ENIG_FINAL_YES);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("signReasonByRecipientRules"));

  //Signing reasonByConflict
  Enigmail.msg.signByRules = EnigmailConstants.ENIG_CONFLICT;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusSigned, EnigmailConstants.ENIG_FINAL_CONFLICT);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("signReasonByConflict"));

  //finalSignDependsOnEncrypt Cases

  //Encryption ENIG_ALWAYS
  Enigmail.msg.isEnigmailEnabled = () => {
    return true;
  };
  Enigmail.msg.signByRules = EnigmailConstants.ENIG_UNDEF;
  Enigmail.msg.encryptForced = EnigmailConstants.ENIG_ALWAYS;
  Enigmail.msg.finalSignDependsOnEncrypt = true;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusSigned, EnigmailConstants.ENIG_FINAL_YES);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("signReasonByEncryptionMode"));

  //Encryption ENIG_NEVER
  Enigmail.msg.encryptForced = EnigmailConstants.ENIG_NEVER;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusSigned, EnigmailConstants.ENIG_FINAL_YES);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("signReasonByEncryptionMode"));

  //Encryption encFinally = EnigmailConstants;
  Enigmail.msg.encryptForced = null;
  Enigmail.msg.encryptByRules = EnigmailConstants.ENIG_CONFLICT;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusSigned, EnigmailConstants.ENIG_FINAL_YES);
  Assert.equal(Enigmail.msg.reasonSigned, EnigmailLocale.getString("signReasonByEncryptionMode"));

  //Encryption ENIG_CONFLICT
  Enigmail.msg.getAccDefault = (prop) => {
    //Function Overriding
    return false;
  };
  Enigmail.msg.sendMode = 0x0001;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusSigned, EnigmailConstants.ENIG_FINAL_CONFLICT);
  Assert.equal(Enigmail.msg.reasonSigned, "");

  //statusPGPMime Flags

  Enigmail.msg.pgpmimeForced = EnigmailConstants.ENIG_NEVER;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusPGPMime, EnigmailConstants.ENIG_FINAL_FORCENO);

  Enigmail.msg.pgpmimeForced = EnigmailConstants.ENIG_ALWAYS;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusPGPMime, EnigmailConstants.ENIG_FINAL_FORCEYES);

  Enigmail.msg.pgpmimeForced = "";
  Enigmail.msg.pgpmimeByRules = EnigmailConstants.ENIG_NEVER;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusPGPMime, EnigmailConstants.ENIG_FINAL_NO);

  Enigmail.msg.pgpmimeByRules = EnigmailConstants.ENIG_ALWAYS;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusPGPMime, EnigmailConstants.ENIG_FINAL_YES);

  Enigmail.msg.pgpmimeByRules = EnigmailConstants.ENIG_CONFLICT;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusPGPMime, EnigmailConstants.ENIG_FINAL_CONFLICT);

  Enigmail.msg.pgpmimeByRules = EnigmailConstants.ENIG_UNDEF;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusPGPMime, EnigmailConstants.ENIG_FINAL_NO);

  Enigmail.msg.pgpmimeByRules = EnigmailConstants.ENIG_UNDEF;
  Enigmail.msg.sendMode = EnigmailConstants.SEND_PGP_MIME;
  Enigmail.msg.processFinalState();
  Assert.equal(Enigmail.msg.statusPGPMime, EnigmailConstants.ENIG_FINAL_YES);

}

function replaceEditorText_test() {
  Enigmail.msg.editorSelectAll = function() {
    Assert.ok(true);
  };

  Enigmail.msg.editorInsertText = function(val) {
    Assert.ok(true);
    if (val === "Enigmail" || val === "text") {
      Assert.ok(true);
    } else {
      Assert.ok(false);
    }
  };

  Enigmail.msg.editor = {};

  Enigmail.msg.editor.textLength = 4;

  Enigmail.msg.replaceEditorText("text");

  Enigmail.msg.editor.textLength = 0;
  Enigmail.msg.editorInsertText = function(val) {
    Assert.ok(true);
    if (val === " " || val === "text") {
      Assert.ok(true);
    } else {
      Assert.ok(false);
    }
  };
}

function resetUpdatedFields_test() {

  let si = EnigmailCompat.getSecurityField();
  gMsgCompose = {
    compFields: {
      subject: 'subject'
    }
  };

  gMsgCompose.compFields[si] = {
    signMessage: false,
    wrappedJSObject: this
  };


  Enigmail.msg.removeAttachedKey = function() {
    Assert.ok(true);
  };

  EnigmailMimeEncrypt.isEnigmailCompField = function(val) {
    Assert.equal(val.signMessage, false);
    return true;
  };

  Enigmail.msg.resetUpdatedFields();
  Assert.equal(gMsgCompose.compFields.subject, 'subject');

}


test(function run_test() {
  window = JSUnit.createStubWindow();
  window.document = {};
  document = window.document;

  do_load_module("chrome://enigmail/content/ui/enigmailMsgComposeOverlay.js");

  //Overriding Problem
  //TODO Use testHelper
  isEnigmailEnabled_test();
  isSmimeEnabled_test();
  processFinalState_test();

  initialSendFlags_test();
  initRadioMenu_test();
  isSendConfirmationRequired_test();
  isSmimeEncryptionPossible_test();
  modifyCompFields_test();
  msgComposeReset_test();
  notifyUser_test();
  preferPgpOverSmime_test();
  processAccountSpecificDefaultOptions_test();
  replaceEditorText_test();
  resetUpdatedFields_test();

});
