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
  msgBox: function() {},
  alertPref: function() {}
};
var AddAttachment;
var AddAttachments;
var Recipients2CompFields = {};
var GetResourceFromUri = {};
var EnigmailCore = {};

var gSMFields;

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

function unsetAdditionalHeader_test() {
  gMsgCompose = {
    compFields: {
      deleteHeader: function() {
        Assert.ok(true);
      }
    }
  };

  Enigmail.msg.unsetAdditionalHeader('hdr');
}



test(function run_test() {
  window = JSUnit.createStubWindow();
  window.document = JSUnit.createDOMDocument();
  document = window.document;

  do_load_module("chrome://enigmail/content/ui/enigmailMsgComposeOverlay.js");

  unsetAdditionalHeader_test();

});
