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

var EnigmailPrefs = {
  getPref: (prop) => {
    return 1;
  },
  setPref: function() {},
  getPrefRoot: function() {
    return {
      getPrefType: function() {
        return true;
      },
      getBoolPref: function(str) {
        return true;
      },
      getCharPref: function(str) {
        return "";
      },
      PREF_BOOL: true
    };
  }
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

function fireSearchKeys_test() {
  return new Promise((resolve, reject) => {
    Enigmail.msg.isEnigmailEnabled = function() {
      return true;
    };

    Enigmail.msg.searchKeysTimeout = true;

    Enigmail.msg.findMissingKeys = function() {
      Assert.ok(false, "Should not be called now");
    };

    Enigmail.msg.fireSearchKeys();
    Assert.equal(Enigmail.msg.searchKeysTimeout, true);

    Enigmail.msg.searchKeysTimeout = false;

    Enigmail.msg.findMissingKeys = function() {
      Assert.ok(true);
    };

    EnigmailTimer.setTimeout = function(callback, time) {
      Assert.equal(time, 5000);
      callback();
      resolve(true);
      return false;
    };

    Enigmail.msg.fireSearchKeys();
    Assert.equal(Enigmail.msg.searchKeysTimeout, false);
  });
}

function fireSendFlags_test() {
  return new Promise((resolve, reject) => {
    Enigmail.msg.determineSendFlags = function() {
      Assert.ok(true);
    };

    Enigmail.msg.fireSearchKeys = function() {
      Assert.ok(true);
    };

    EnigmailTimer.setTimeout = function(callback, time) {
      callback();
      Assert.ok(true);
      resolve(true);
      return null;
    };

    Enigmail.msg.determineSendFlagId = false;

    Enigmail.msg.fireSendFlags();

    Assert.equal(Enigmail.msg.determineSendFlagId, null);
  });
}

function fixMessageSubject_test() {
  let check = "";
  document.getElementById = function() {
    return {
      value: "Re: Re: Hello",
      oninput: function() {
        Assert.ok(true);
      }
    };
  };

  let h = Enigmail.msg.getMsgHdr;
  Enigmail.msg.getMsgHdr = function() {
    return {
      flags: Ci.nsMsgMessageFlags.HasRe
    };
  };
  Enigmail.msg.fixMessageSubject();
  Enigmail.msg.getMsgHdr = h;
}

function focusChange_test() {
  CommandUpdate_MsgCompose = function() {
    Assert.ok(true);
  };

  Enigmail.msg.lastFocusedWindow = true;

  top = {
    document: {
      commandDispatcher: {
        focusedWindow: true
      }
    }
  };

  Enigmail.msg.focusChange();
  Assert.equal(Enigmail.msg.lastFocusedWindow, true);

  Enigmail.msg.lastFocusedWindow = false;

  Enigmail.msg.fireSendFlags = function() {
    Assert.ok(true);
  };

  Enigmail.msg.focusChange();
  Assert.equal(Enigmail.msg.lastFocusedWindow, true);

}

function getAccDefault_test() {

  Enigmail.msg.identity = {};

  Enigmail.msg.isSmimeEnabled = () => {
    //Function Overriding
    return true;
  };

  Enigmail.msg.isEnigmailEnabled = () => {
    //Function Overriding
    return true;
  };

  Enigmail.msg.identity.getBoolAttribute = (key) => {
    //Function Overriding
    return false;
  };

  Enigmail.msg.identity.getIntAttribute = (key) => {
    //Function Overriding
    return 0;
  };

  let ret = Enigmail.msg.getAccDefault('sign');
  Assert.equal(ret, false);

  Enigmail.msg.identity.getIntAttribute = (key) => {
    //Function Overriding
    return 1;
  };

  ret = Enigmail.msg.getAccDefault('sign');
  Assert.equal(ret, true);

  Enigmail.msg.identity.getBoolAttribute = (key) => {
    //Function Overriding
    return true;
  };

  Enigmail.msg.identity.getIntAttribute = (key) => {
    //Function Overriding
    return 1;
  };

  Enigmail.msg.pgpmimeForced = EnigmailConstants.ENIG_FORCE_SMIME;

  ret = Enigmail.msg.getAccDefault('sign');
  Assert.equal(ret, true);

  Enigmail.msg.pgpmimeForced = EnigmailConstants.ENIG_FORCE_ALWAYS;

  ret = Enigmail.msg.getAccDefault('sign');
  Assert.equal(ret, true);

  ret = Enigmail.msg.getAccDefault('encrypt');
  Assert.equal(ret, true);

  Enigmail.msg.pgpmimeForced = null;
  ret = Enigmail.msg.getAccDefault('encrypt');
  Assert.equal(ret, true);

  ret = Enigmail.msg.getAccDefault('sign-pgp');
  Assert.equal(ret, true);

  Enigmail.msg.identity.getBoolAttribute = (key) => {
    return false;
  };

  ret = Enigmail.msg.getAccDefault("signIfNotEnc");
  Assert.equal(ret, false);

  Enigmail.msg.identity.getBoolAttribute = (key) => {
    return true;
  };

  ret = Enigmail.msg.getAccDefault("signIfEnc");
  Assert.equal(ret, true);

  ret = Enigmail.msg.getAccDefault('attachPgpKey');
  Assert.equal(ret, true);

  Enigmail.msg.isEnigmailEnabled = () => {
    //Function Overriding
    return false;
  };

  ret = Enigmail.msg.getAccDefault('sign');
  Assert.equal(ret, true);

  Enigmail.msg.identity.getBoolAttribute = (key) => {
    return false;
  };

  ret = Enigmail.msg.getAccDefault('sign');
  Assert.equal(ret, false);

  Enigmail.msg.identity.getIntAttribute = (key) => {
    //Function Overriding
    return 0;
  };

  ret = Enigmail.msg.getAccDefault('encrypt');
  Assert.equal(ret, false);

  ret = Enigmail.msg.getAccDefault('random');
  Assert.equal(ret, false);

  Enigmail.msg.isSmimeEnabled = () => {
    //Function Overriding
    return false;
  };

  ret = Enigmail.msg.getAccDefault('sign');
  Assert.equal(ret, false);

  ret = Enigmail.msg.getAccDefault('encrypt');
  Assert.equal(ret, false);

  ret = Enigmail.msg.getAccDefault('signIfNotEnc');
  Assert.equal(ret, false);

  ret = Enigmail.msg.getAccDefault('signIfEnc');
  Assert.equal(ret, false);

  ret = Enigmail.msg.getAccDefault('attachPgpKey');
  Assert.equal(ret, false);

  ret = Enigmail.msg.getAccDefault('sign-pgp');
  Assert.equal(ret, false);

  ret = Enigmail.msg.getAccDefault('random');
  Assert.equal(ret, null);
}

function getCurrentIncomingServer_test() {
  getCurrentAccountKey = function() {
    return true;
  };

  MailServices = {
    accounts: {
      getAccount: function(currentAccountKey) {
        Assert.equal(currentAccountKey, true);
        return {
          incomingServer: true
        };
      }
    }
  };

  let ret = Enigmail.msg.getCurrentIncomingServer();
  Assert.equal(ret, true);
}

function getEncryptionEnabled_test() {
  getCurrentIdentity = function() {
    return {
      getUnicharAttribute: function() {
        return "xyz";
      }
    };
  };
  let ret = Enigmail.msg.getEncryptionEnabled();
  Assert.equal(ret, true);

  getCurrentIdentity = function() {
    return {
      getUnicharAttribute: function() {
        return "";
      }
    };
  };

  Enigmail.msg.isEnigmailEnabled = function() {
    return true;
  };
  ret = Enigmail.msg.getEncryptionEnabled();
  Assert.equal(ret, true);

  Enigmail.msg.isEnigmailEnabled = function() {
    return false;
  };
  ret = Enigmail.msg.getEncryptionEnabled();
  Assert.equal(ret, false);
}

function getForceRecipientDlg_test() {
  EnigmailPrefs.getPref = function(prop) {
    if (prop === "assignKeysByRules") {
      return true;
    }
    else if (prop === "assignKeysByEmailAddr") {
      return false;
    }
    else if (prop === "assignKeysManuallyIfMissing") {
      return false;
    }

    return false;
  };

  let ret = Enigmail.msg.getForceRecipientDlg();
  Assert.equal(ret, true);

  EnigmailPrefs.getPref = function(prop) {
    if (prop === "assignKeysByRules") {
      return true;
    }
    else if (prop === "assignKeysByEmailAddr") {
      return true;
    }
    else if (prop === "assignKeysManuallyIfMissing") {
      return false;
    }

    return false;
  };

  ret = Enigmail.msg.getForceRecipientDlg();
  Assert.equal(ret, false);
}

function getMailPref_test() {
  let h = EnigmailPrefs.getPrefRoot;
  EnigmailPrefs.getPrefRoot = function() {
    return {
      getPrefType: function() {
        return true;
      },
      getBoolPref: function(str) {
        Assert.ok(true);
        Assert.equal(str, 'xyz');
      },
      PREF_BOOL: true
    };
  };

  Enigmail.msg.getMailPref('xyz');

  EnigmailPrefs.getPrefRoot = function() {
    return {
      getPrefType: function() {
        return true;
      },
      getIntPref: function(str) {
        Assert.ok(true);
        Assert.equal(str, 'xyz');
      },
      PREF_INT: 1
    };
  };

  Enigmail.msg.getMailPref('xyz');

  EnigmailPrefs.getPrefRoot = function() {
    return {
      getPrefType: function() {
        return true;
      },
      getCharPref: function(str) {
        Assert.equal(str, 'xyz');
      },
      PREF_STRING: 'str'
    };
  };

  Enigmail.msg.getMailPref('xyz');
  EnigmailPrefs.getPrefRoot = h;
}

function getMsgHdr_test() {
  //Check for Only Null
  Enigmail.msg.getOriginalMsgUri = function() {
    return null;
  };

  let ret = Enigmail.msg.getMsgHdr(null);
  Assert.equal(ret, null);

}

function getOriginalMsgUri_test() {
  gMsgCompose = {
    compFields: {
      draftId: 'HelloWorld\s'
    }
  };

  let ret = Enigmail.msg.getOriginalMsgUri();
  Assert.equal(ret, "HelloWorlds");

  gMsgCompose = {
    compFields: {
      draftId: ''
    },
    originalMsgURI: "xyz"
  };

  ret = Enigmail.msg.getOriginalMsgUri();
  Assert.equal(ret, "xyz");

}


function getSigningEnabled_test() {
  getCurrentIdentity = function() {
    //Function Overriding
    return {
      getUnicharAttribute: function() {
        return "xyz";
      }
    };
  };

  let ret = Enigmail.msg.getSigningEnabled();
  Assert.equal(ret, true);

  getCurrentIdentity = function() {
    //Function Overriding
    return {
      getUnicharAttribute: function() {
        return "";
      }
    };
  };

  Enigmail.msg.isEnigmailEnabled = function() {
    //Function Overriding
    return true;
  };
  ret = Enigmail.msg.getSigningEnabled();
  Assert.equal(ret, true);

  Enigmail.msg.isEnigmailEnabled = function() {
    return false;
  };
  ret = Enigmail.msg.getSigningEnabled();
  Assert.equal(ret, false);

}

function getSmimeSigningEnabled_test() {
  let ret = Enigmail.msg.getSmimeSigningEnabled();
  Assert.equal(ret, false);

  getCurrentIdentity = function() {
    //Function Overriding
    return {
      getUnicharAttribute: function() {
        return false;
      }
    };
  };

  ret = Enigmail.msg.getSmimeSigningEnabled();
  Assert.equal(ret, false);

  getCurrentIdentity = function() {
    //Function Overriding
    return {
      getUnicharAttribute: function() {
        return true;
      },
      getBoolAttribute: function() {
        return false;
      }
    };
  };

  ret = Enigmail.msg.getSmimeSigningEnabled();
  Assert.equal(ret, false);

}

function goAccountManager_test() {

  EnigmailCore.getService = function() {
    Assert.ok(true);
  };

  getCurrentIdentity = function() {
    return 'id';
  };

  EnigmailFuncs.getAccountForIdentity = function() {
    return 'account';
  };

  window.openDialog = function(xulPath, str1, prop, param) {
    Assert.equal(param.identity, 'id');
    Assert.equal(param.account, 'account');
  };

  Enigmail.msg.setIdentityDefaults = function() {
    Assert.ok(true);
  };

  Enigmail.msg.goAccountManager();
}

function handleClick_test() {

  let event = {
    button: 2,
    preventDefault: function() {
      Assert.ok(true);
    }
  };

  Enigmail.msg.doPgpButton = function(str) {
    //Function Overriding
    Assert.ok(true);
  };

  let modifyType = "xyz";

  Enigmail.msg.handleClick(event, modifyType);

  event = {
    button: 0,
    preventDefault: function() {
      Assert.ok(true);
    }
  };

  Enigmail.msg.doPgpButton = function(str) {
    //Function Overriding
    Assert.equal(str, "xyz");
    Assert.ok(true);
  };

  Enigmail.msg.handleClick(event, modifyType);
}

function preferPgpOverSmime_test() {
  gMsgCompose.compFields.securityInfo = Components.classes["@mozilla.org/messenger-smime/composefields;1"].createInstance();

  let ret = Enigmail.msg.preferPgpOverSmime(0x0001);
  Assert.equal(ret, 1);

  gMsgCompose.compFields.securityInfo.requireEncryptMessage = 1;

  Enigmail.msg.mimePreferOpenPGP = 2;

  ret = Enigmail.msg.preferPgpOverSmime(0x0203);
  Assert.equal(ret, 0);

  gMsgCompose.compFields.securityInfo.requireEncryptMessage = 0;
  gMsgCompose.compFields.securityInfo.signMessage = 1;

  ret = Enigmail.msg.preferPgpOverSmime(0x0203);
  Assert.equal(ret, 0);

  gMsgCompose.compFields.securityInfo.signMessage = 0;

  ret = Enigmail.msg.preferPgpOverSmime(0x0203);
  Assert.equal(ret, 1);

  gMsgCompose.compFields.securityInfo.signMessage = 1;

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
  Assert.equal(Enigmail.msg.sendPgpMime, false);
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
  Assert.equal(Enigmail.msg.sendPgpMime, false);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.appendAttachment, false);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.attachedObj, null);
  Assert.equal(Enigmail.msg.attachOwnKeyObj.attachedKey, null);
  Assert.equal(Enigmail.msg.finalSignDependsOnEncrypt, false);

  Enigmail.msg.reasonSigned = "";

  Enigmail.msg.getAccDefault = function(str) {
    //Function Overriding
    if (str === "sign") {
      return false;
    }
    else {
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
    }
    else {
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
    }
    else {
      Assert.ok(false);
    }
  };

  Enigmail.msg.editor.textLength = 4;

  Enigmail.msg.replaceEditorText("text");

  Enigmail.msg.editor.textLength = 0;
  Enigmail.msg.editorInsertText = function(val) {
    Assert.ok(true);
    if (val === " " || val === "text") {
      Assert.ok(true);
    }
    else {
      Assert.ok(false);
    }
  };
}

function resetUpdatedFields_test() {

  gMsgCompose = {
    compFields: {
      securityInfo: 'xyz'
    }
  };

  Enigmail.msg.removeAttachedKey = function() {
    Assert.ok(true);
  };

  EnigmailMimeEncrypt.isEnigmailCompField = function(val) {
    Assert.equal(val, 'xyz');
    return true;
  };

  // EnigmailMsgCompFields.getValue = function(si, subject) {
  //   Assert.equal(si, 'xyz');
  //   Assert.equal(subject, 'originalSubject');
  //   return 'subject';
  // };

  Enigmail.msg.resetUpdatedFields();
  Assert.equal(gMsgCompose.compFields.subject, 'subject');

}

test(asyncTest(async function run_test() {
  window = JSUnit.createStubWindow();
  window.document = JSUnit.createDOMDocument();
  document = window.document;

  do_load_module("chrome://enigmail/content/ui/enigmailMsgComposeOverlay.js");

  getOriginalMsgUri_test();

  await fireSearchKeys_test();
  await fireSendFlags_test();
  fixMessageSubject_test();
  focusChange_test();
  getAccDefault_test();
  getCurrentIncomingServer_test();
  getEncryptionEnabled_test();
  getForceRecipientDlg_test();
  getMailPref_test();
  getMsgHdr_test();
  getSigningEnabled_test();
  getSmimeSigningEnabled_test();
  goAccountManager_test();
  handleClick_test();
}));
