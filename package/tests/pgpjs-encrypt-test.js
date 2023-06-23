/*global do_load_module: false, do_get_file: false, do_get_cwd: false, testing: false, test: false, Assert: false, resetting: false */
/*global do_test_pending: false, do_test_finished: false, withTestGpgHome: false, asyncTest: false */

/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

"use strict";

do_load_module("file://" + do_get_cwd().path + "/testHelper.js");

testing("cryptoAPI/pgpjs-encrypt.jsm");
/*global pgpjs_encrypt: false, getOpenPGPLibrary: false, pgpjs_keyStore: false, EnigmailConstants: false */

const EnigmailFiles = ChromeUtils.import("chrome://enigmail/content/modules/files.jsm").EnigmailFiles;

test(withTestGpgHome(asyncTest(async function testEncrypt() {
  try {
    await pgpjs_keyStore.init();

    // set password to decrypt key
    const pm = Cc["@mozilla.org/login-manager;1"].getService(Ci.nsILoginManager);
    const queryString = 'enigmail://65537E212DC19025AD38EDB2781617319CE311C4';
    const passwd = "STRIKEfreedom@Qu1to";

    const nsLoginInfo = new Components.Constructor(
      "@mozilla.org/login-manager/loginInfo;1",
      Ci.nsILoginInfo,
      "init"
    );

    let loginInfo = new nsLoginInfo(queryString, null, "OpenPGPKey", "", passwd, "", "");
    try {
      pm.addLogin(loginInfo);
    }
    catch (ex) {}


    const pubKeyFile = do_get_file("resources/dev-strike.sec", false);
    let fileData = EnigmailFiles.readBinaryFile(pubKeyFile);

    let r = await pgpjs_keyStore.writeKey(fileData);
    Assert.equal(r.length, 1);

    let encryptFlags = (EnigmailConstants.SEND_ENCRYPTED | EnigmailConstants.SEND_SIGNED | EnigmailConstants.SEND_ENCRYPT_TO_SELF);

    let result = await pgpjs_encrypt.encryptMessage("0x65537E212DC19025AD38EDB2781617319CE311C4", "", "", encryptFlags, "Hello World");
    Assert.equal(result.exitCode, 0);
    Assert.ok(result.data.search(/^-----BEGIN PGP MESSAGE-----$/m) >= 0, "contains PGP start header");

    encryptFlags = EnigmailConstants.SEND_SIGNED | EnigmailConstants.SEND_TEST;
    result = await pgpjs_encrypt.encryptMessage("0x65537E212DC19025AD38EDB2781617319CE311C4", null, null, encryptFlags, "Hello World");
    Assert.equal(result.exitCode, 0);
    Assert.ok(result.data.search(/-----BEGIN PGP SIGNED MESSAGE-----\r?\nHash: SHA(256|512)/) >= 0, "contains Hash header");

    encryptFlags = EnigmailConstants.SEND_SIGNED | EnigmailConstants.SEND_PGP_MIME;
    result = await pgpjs_encrypt.encryptMessage("0x65537E212DC19025AD38EDB2781617319CE311C4", null, null, encryptFlags, "Hello World");
    Assert.equal(result.exitCode, 0);
    Assert.ok(result.data.search(/^-----BEGIN PGP SIGNATURE-----$/m) >= 0, "contains Hash header");

  }
  catch (ex) {
    Assert.ok(false, "exception: " + ex.toString());
  }
})));
