/*global do_load_module: false, do_get_file: false, do_get_cwd: false, testing: false, test: false, Assert: false, resetting: false, JSUnit: false, withTestGpgHome:false */
/*global Ec: false, asyncTest: false, do_print: false, EnigmailCore: false, EnigmailKeyEditor: false, component: false, EnigmailPrefs: false, EnigmailExecution: false */
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

"use strict";

do_load_module("file://" + do_get_cwd().path + "/testHelper.js"); /*global withEnigmail: false */

testing("cryptoAPI/gnupg-keyEditor.jsm"); /*global editKey: false, EnigmailKeyRing: false */
var EnigmailTime = component("enigmail/time.jsm").EnigmailTime;
var getGpgMEApi = component("enigmail/cryptoAPI/gpgme.js").getGpgMEApi;
var gGnuPGPath = null;


test(withTestGpgHome(withEnigmail(asyncTest(function shouldEditKey(esvc, window) {
  if (!gGnuPGPath) {
    const gpgmeApi = getGpgMEApi();
    gpgmeApi.initialize(esvc);
    gGnuPGPath = gpgmeApi._gpgPath;
  }

  EnigmailKeyEditor.gpgPath = gGnuPGPath;

  return new Promise((resolve, reject) => {
    importKeys();
    var window = JSUnit.createStubWindow();
    editKey(
      window,
      false,
      null,
      "781617319CE311C4",
      "trust", {
        trustLevel: 5
      },
      function(inputData, keyEdit, ret) {
        ret.writeTxt = "";
        ret.errorMsg = "";
        ret.quitNow = true;
        ret.exitCode = 0;
      },
      null,
      function(exitCode, errorMsg) {
        Assert.equal(exitCode, 0);
        Assert.equal("", errorMsg);
        resolve(1);
      }
    );
  });
}))));

test(withTestGpgHome(withEnigmail(asyncTest(function shouldSetTrust() {
  return new Promise((resolve, reject) => {
    importKeys();
    var window = JSUnit.createStubWindow();
    EnigmailKeyEditor.setKeyTrust(window, "781617319CE311C4", 5).then(
      resultObj => {
        Assert.equal(resultObj.returnCode, 0);
        Assert.equal("", resultObj.errorMsg);
        resolve(true);
      });
  });
}))));

test(withTestGpgHome(withEnigmail(asyncTest(function shouldSignKey() {
  return new Promise((resolve, reject) => {
    importKeys();
    var window = JSUnit.createStubWindow();
    EnigmailKeyEditor.signKey(window,
      "0x65537E212DC19025AD38EDB2781617319CE311C4",
      "781617319CE311C4",
      ["anonymous strike <strike.devtest@gmail.com>"],
      false,
      5
    ).then(resultObj => {
      Assert.equal(resultObj.returnCode, -1);
      Assert.equal("The key is already signed, you cannot sign it twice.", resultObj.errorMsg);
      resolve(true);
    }).catch(err => {
      Assert.ok(false, `Error: ${err}`);
      resolve(true);
    });
  });
}))));

test(withTestGpgHome(withEnigmail(function importKeyForEdit() {
  const result = importKeys();
  Assert.equal(result[0], 0);
  Assert.equal(result[1], 0);
})));


test(withTestGpgHome(withEnigmail(asyncTest(function shouldGetSecretKeys() {
  return new Promise((resolve, reject) => {
    const secretKey = do_get_file("resources/dev-strike.sec", false);
    const errorMsgObj = {};
    const importedKeysObj = {};
    const window = JSUnit.createStubWindow();
    const importResult = EnigmailKeyRing.importKeyFromFile(secretKey, errorMsgObj, importedKeysObj);

    const createDate = EnigmailTime.getDateTime(1430756251, true, false);

    const expectedKey = [{
      userId: "anonymous strike <strike.devtest@gmail.com>",
      keyId: "781617319CE311C4",
      created: createDate,
      keyTrust: "u"
    }];
    EnigmailKeyEditor.setKeyTrust(window, "781617319CE311C4", 5).then(
      resultObj => {
        let result = EnigmailKeyRing.getAllSecretKeys();
        Assert.equal(result.length, 1);
        Assert.equal(result[0].userId, expectedKey[0].userId);
        Assert.equal(result[0].keyId, expectedKey[0].keyId);
        Assert.equal(result[0].created, expectedKey[0].created);
        Assert.equal(result[0].keyTrust, expectedKey[0].keyTrust);
        resolve(1);
      }).catch(err => {
        resolve(0);
      });
  });
}))));

test(function shouldDoErrorHandling() {
  let nextCmd = "";

  /* global GpgEditorInterface: false */
  let editor = new GpgEditorInterface(null, null, "");
  editor._stdin = {
    write: function processStdin(data) {
      nextCmd = data;
    }
  };

  editor.gotData("[GNUPG:] FAILURE sign 85\n");
  Assert.ok(editor.errorMsg.length > 0);
  Assert.equal("save\n", nextCmd);
});

function importKeys() {
  var publicKey = do_get_file("resources/dev-strike.asc", false);
  var secretKey = do_get_file("resources/dev-strike.sec", false);
  var errorMsgObj = {};
  var importedKeysObj = {};
  var publicImportResult = EnigmailKeyRing.importKeyFromFile(publicKey, errorMsgObj, importedKeysObj);
  var secretImportResult = EnigmailKeyRing.importKeyFromFile(secretKey, errorMsgObj, importedKeysObj);
  return [publicImportResult, secretImportResult];
}
