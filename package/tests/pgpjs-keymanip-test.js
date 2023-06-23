/*global do_load_module: false, do_get_file: false, do_get_cwd: false, testing: false, test: false, Assert: false, resetting: false */
/*global do_test_pending: false, do_test_finished: false, withTestGpgHome: false, asyncTest: false */

/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

"use strict";

do_load_module("file://" + do_get_cwd().path + "/testHelper.js");

testing("cryptoAPI/pgpjs-keymanipulation.jsm");
/*global pgpjs_keymanipulation: false, getOpenPGPLibrary: false, pgpjs_keyStore: false, EnigmailConstants: false,
    pgpjs_keys: false, EnigmailFiles: false
 */

test(withTestGpgHome(asyncTest(async function testGenRevokeCert() {
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

    let keys = await pgpjs_keyStore.readKeys(["0x65537E212DC19025AD38EDB2781617319CE311C4"]);
    Assert.ok(!(await keys[0].key.isRevoked()), "Key is not revoked");

    const revFile = EnigmailFiles.getTempDirObj();
    revFile.append("key.rev");
    revFile.createUnique(Ci.nsIFile.NORMAL_FILE_TYPE, 0o600);

    r = await pgpjs_keymanipulation.genRevokeCert(null, "0x65537E212DC19025AD38EDB2781617319CE311C4", revFile, "0", "");
    Assert.equal(r.returnCode, 0);

    let revCert = EnigmailFiles.readFile(revFile);
    Assert.ok(revCert.search(/^-----BEGIN PGP PUBLIC KEY BLOCK-----$/m) >= 0);
    r = await pgpjs_keyStore.writeKey(revCert);

    Assert.equal(r.length, 1);

    keys = await pgpjs_keyStore.readKeys(["0x65537E212DC19025AD38EDB2781617319CE311C4"]);
    Assert.ok(await keys[0].key.isRevoked(), "Key is revoked");
  }
  catch (ex) {
    Assert.ok(false, "exception: " + ex.toString());
  }
})));

test(withTestGpgHome(asyncTest(async function testChangeExpiry() {
  try {
    await pgpjs_keyStore.init();

    const pubKeyFile = do_get_file("resources/multi-uid.sec", false);
    let fileData = EnigmailFiles.readBinaryFile(pubKeyFile);

    let r = await pgpjs_keyStore.writeKey(fileData);
    Assert.equal(r.length, 1);

    let keys = await pgpjs_keyStore.readKeys(["0xADC49530CB6B132412D856107F1568CB8997F7BA"]);
    let key = keys[0].key;
    Assert.ok(!(await key.isRevoked()), "Key is not revoked");

    Assert.equal(await key.getExpirationTime(), Infinity);

    const now = Math.floor(Date.now() / 1000);
    r = await pgpjs_keymanipulation.setKeyExpiration(null, "0xADC49530CB6B132412D856107F1568CB8997F7BA", [0, 1, 3], 1, 365, false);
    Assert.equal(r.returnCode, 0, "setKeyExpiration Succeeded");

    // Re-read the key to test it
    keys = await pgpjs_keyStore.readKeys(["0xADC49530CB6B132412D856107F1568CB8997F7BA"]);
    key = keys[0].key;

    Assert.ok(!(await key.isRevoked()), "Key is not revoked");
    let expiryTime = Math.floor((await key.getExpirationTime()).getTime() / 1000);
    Assert.ok(expiryTime >= now + 365 * 86000);
    Assert.ok(expiryTime < now + 367 * 86000);

    r = await pgpjs_keymanipulation.setKeyExpiration(null, "0xADC49530CB6B132412D856107F1568CB8997F7BA", [0], 1, 1, true);
    Assert.equal(r.returnCode, 0, "setKeyExpiration Succeeded");
  }
  catch (ex) {
    Assert.ok(false, "exception: " + ex.toString());
  }
})));


test(withTestGpgHome(asyncTest(async function testChangePassword() {
  try {
    await pgpjs_keyStore.init();
    const PgpJS = getOpenPGPLibrary();

    const pubKeyFile = do_get_file("resources/dev-strike.sec", false);
    let fileData = EnigmailFiles.readBinaryFile(pubKeyFile);

    const origPasswd = "STRIKEfreedom@Qu1to";
    const newPasswd = "SomePasswd";

    let r = await pgpjs_keyStore.writeKey(fileData);
    Assert.equal(r.length, 1);

    // test changing password on key that is password-protected
    await new Promise((resolve, reject) => {
      const pseudoWin = {
        openDialog: function() {
          resolve(pgpjs_keymanipulation.performChangePassphrase("0x65537E212DC19025AD38EDB2781617319CE311C4", origPasswd, newPasswd));
        }
      };

      pgpjs_keymanipulation.initiateChangePassphrase(pseudoWin, "0x65537E212DC19025AD38EDB2781617319CE311C4");
    });

    let keys = await pgpjs_keyStore.readKeys(["0x65537E212DC19025AD38EDB2781617319CE311C4"]);
    let key = keys[0].key;
    Assert.ok(!key.isDecrypted(), "key is encrypted");

    try {
      key = await PgpJS.decryptKey({
        privateKey: key,
        passphrase: newPasswd
      });
      Assert.ok(key !== null, "key decryption successful");
    }
    catch (ex) {
      Assert.ok(false, "key decryption failed");
    }

    Assert.ok(key.isDecrypted(), "key is decrypted");

    // test removing the password from key
    await new Promise((resolve, reject) => {
      const pseudoWin = {
        openDialog: function() {
          resolve(pgpjs_keymanipulation.performChangePassphrase("0x65537E212DC19025AD38EDB2781617319CE311C4", newPasswd, ""));
        }
      };

      pgpjs_keymanipulation.initiateChangePassphrase(pseudoWin, "0x65537E212DC19025AD38EDB2781617319CE311C4");
    });

    keys = await pgpjs_keyStore.readKeys(["0x65537E212DC19025AD38EDB2781617319CE311C4"]);
    key = keys[0].key;
    Assert.ok(key.isDecrypted(), "key is decrypted");

    // test setting a password for an unencrypted key
    await new Promise((resolve, reject) => {
      const pseudoWin = {
        openDialog: function() {
          resolve(pgpjs_keymanipulation.performChangePassphrase("0x65537E212DC19025AD38EDB2781617319CE311C4", "", origPasswd));
        }
      };

      pgpjs_keymanipulation.initiateChangePassphrase(pseudoWin, "0x65537E212DC19025AD38EDB2781617319CE311C4");
    });

    keys = await pgpjs_keyStore.readKeys(["0x65537E212DC19025AD38EDB2781617319CE311C4"]);
    key = keys[0].key;
    Assert.ok(!key.isDecrypted(), "key is encrypted");
  }
  catch (ex) {
    Assert.ok(false, "exception: " + ex.toString());
  }
})));


test(withTestGpgHome(asyncTest(async function testWrongPassword() {
  try {
    await pgpjs_keyStore.init();
    const PgpJS = getOpenPGPLibrary();

    const pubKeyFile = do_get_file("resources/dev-strike.sec", false);
    let fileData = EnigmailFiles.readBinaryFile(pubKeyFile);

    const origPasswd = "STRIKEfreedom@Qu1to";
    const newPasswd = "SomePasswd";

    let r = await pgpjs_keyStore.writeKey(fileData);
    Assert.equal(r.length, 1);

    let keys = await pgpjs_keyStore.readKeys(["0x65537E212DC19025AD38EDB2781617319CE311C4"]);
    let key = keys[0].key;

    Assert.ok(!key.isDecrypted(), "key is encrypted");
    try {
      r = await PgpJS.decryptKey({
        privateKey: key,
        passphrase: "wrong password"
      });
      Assert.ok(false, "key decryption must not succeed");
    }
    catch (ex) {
      Assert.ok(pgpjs_keys.isWrongPassword(ex), "wrong password detected");
    }
  }
  catch (ex) {
    Assert.ok(false, "exception: " + ex.toString());
  }
})));


test(withTestGpgHome(asyncTest(async function testPartialKeyDecryption() {
  try {
    await pgpjs_keyStore.init();
    const PgpJS = getOpenPGPLibrary();

    const passwd = "STRIKEfreedom@Qu1to";

    const pubKeyFile = do_get_file("resources/mixed-encrypted-key.sec", false);
    let fileData = EnigmailFiles.readBinaryFile(pubKeyFile);

    let r = await pgpjs_keyStore.writeKey(fileData);
    Assert.equal(r.length, 1);

    let keys = await pgpjs_keyStore.readKeys(["0x8A11371431B0941F815967C373665408D8D8AC8E"]);
    let key = keys[0].key;
    Assert.ok(key.isDecrypted(), "key is encrypted");
    try {
      key = await PgpJS.decryptKey({
        privateKey: key,
        passphrase: passwd
      });
      Assert.ok(false, "key decryption must not succeed");
    }
    catch (ex) {
      Assert.ok(pgpjs_keys.isKeyFullyDecrypted(ex, key), "key is fully decrypted");
    }
  }
  catch (ex) {
    Assert.ok(false, "exception: " + ex.toString());
  }
})));


test(withTestGpgHome(asyncTest(async function testWrongPassword() {
  try {
    await pgpjs_keyStore.init();
    const PgpJS = getOpenPGPLibrary();

    const pubKeyFile = do_get_file("resources/dev-strike.sec", false);
    let fileData = EnigmailFiles.readBinaryFile(pubKeyFile);

    const origPasswd = "STRIKEfreedom@Qu1to";
    const newPasswd = "SomePasswd";

    let r = await pgpjs_keyStore.writeKey(fileData);
    Assert.equal(r.length, 1);

    let keys = await pgpjs_keyStore.readKeys(["0x65537E212DC19025AD38EDB2781617319CE311C4"]);
    let key = keys[0].key;

    Assert.ok(!key.isDecrypted(), "key is encrypted");
    try {
      r = await PgpJS.decryptKey({
        privateKey: key,
        passphrase: "wrong password"
      });
      Assert.ok(false, "key decryption must not succeed");
    }
    catch (ex) {
      Assert.ok(pgpjs_keys.isWrongPassword(ex), "wrong password detected");
    }
  }
  catch (ex) {
    Assert.ok(false, "exception: " + ex.toString());
  }
})));


test(withTestGpgHome(asyncTest(async function testSignKey() {
  try {
    await pgpjs_keyStore.init();

    const passwd = "STRIKEfreedom@Qu1to";

    const pubKeyFile = do_get_file("resources/multi-uid.asc", false);
    let fileData = EnigmailFiles.readBinaryFile(pubKeyFile);
    let r = await pgpjs_keyStore.writeKey(fileData);
    Assert.equal(r.length, 1);

    const secKeyFile = do_get_file("resources/dev-strike.sec", false);
    fileData = EnigmailFiles.readBinaryFile(secKeyFile);
    r = await pgpjs_keyStore.writeKey(fileData);
    Assert.equal(r.length, 1);

    // signing Key ID 0x65537E212DC19025AD38EDB2781617319CE311C4
    // key to sign: 0xADC49530CB6B132412D856107F1568CB8997F7BA
    r = await pgpjs_keymanipulation.signKey(null,
      "0x65537E212DC19025AD38EDB2781617319CE311C4",
      "0xADC49530CB6B132412D856107F1568CB8997F7BA",
      ["Unit Test <alice@example.invalid>", "Unit Test <bob@somewhere.invalid>"],
      false, "1");
    Assert.equal(r.returnCode, 0, "signing suceeded");
    let keys = await pgpjs_keyStore.readKeys(["0xADC49530CB6B132412D856107F1568CB8997F7BA"]);
    let signedKey = keys[0].key;

    for (let uid of signedKey.users) {
      if (uid.revocationSignatures.length > 0) {
        Assert.equal(uid.otherCertifications.length, 0);
      }
      else {
        if (uid.userID) {
          // User IDs
          if (uid.userID.userID === "test.bob@somewhere.invalid") {
            Assert.equal(uid.otherCertifications.length, 1);
          }
          else {
            Assert.equal(uid.otherCertifications.length, 2, "user ID: " + uid.userID.userID);
          }
        }
        else {
          // User attributes
          Assert.equal(uid.otherCertifications.length, 1);
        }
      }
    }
  }
  catch (ex) {
    Assert.ok(false, "exception: " + ex.toString());
  }
})));
