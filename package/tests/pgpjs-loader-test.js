/*global do_load_module: false, do_get_file: false, do_get_cwd: false, testing: false, test: false, Assert: false, resetting: false */
/*global do_test_pending: false, do_test_finished: false, withTestGpgHome: false, asyncTest: false, withEnigmail: false */

/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

"use strict";

do_load_module("file://" + do_get_cwd().path + "/testHelper.js");

testing("cryptoAPI/openpgp-js.js"); /*global getOpenPGPjsAPI: false */
const EnigmailOS = ChromeUtils.import("chrome://enigmail/content/modules/os.jsm").EnigmailOS;
const getOpenPGPLibrary = ChromeUtils.import("chrome://enigmail/content/modules/stdlib/openpgp-loader.jsm").getOpenPGPLibrary;
const EnigmailOpenPGP = ChromeUtils.import("chrome://enigmail/content/modules/openpgp.jsm").EnigmailOpenPGP;

// make sure isWin32 is set correctly
EnigmailOS.isWin32 = EnigmailOS.getOS() === "WINNT";

test(function testGetStrippedKey() {
  const cApi = getOpenPGPjsAPI();

  const pubKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----" +
    "\n" +
    "\n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" +
    "\nsnHSt1DRJA==" +
    "\n=I9l9" +
    "\n-----END PGP PUBLIC KEY BLOCK-----";

  let minKey = cApi.sync(cApi.getStrippedKey(pubKey));
  let got = btoa(String.fromCharCode.apply(null, minKey));
  Assert.equal(got.substr(0, 127), "xsFNBFVHm5sBEACs94Ln+RMdeyBpWQtTZ/NZnwntsB10Wd3HTgo5sdA/OOFOJrWetJfAZ/HRxiSu1bwRaFVC8p061ftTbxf8bsdfsykYJQQqPODfcO0/oY2n/Z93ya8");
  Assert.equal(got.substr(-127), "QriSRXV4ZhMhGtnhHEYqHP982gBxk4RPvEp7APCLrqgC0+N8N29eC4s3JkVkHAZx+fj5YV2H9/5wJRJ1w+kwmazhpTQsy01kEwS4NZMPe8Uvz0MgoNuF7Jx0rdQ0SQ=");
  Assert.equal(got.length, 3080);
});

test(withTestGpgHome(withEnigmail(asyncTest(async function testImportAndDeleteKey() {
  try {
    const cApi = getOpenPGPjsAPI();

    cApi.initialize();
    const pubKeyFile = do_get_file("resources/dev-strike.asc", false);

    let r = await cApi.importKeyFromFile(pubKeyFile);

    Assert.equal(r.exitCode, 0);
    Assert.equal(r.importSum, 1);
    Assert.equal(r.importedKeys[0], "65537E212DC19025AD38EDB2781617319CE311C4");

    let armor = await cApi.extractPublicKey("0x65537E212DC19025AD38EDB2781617319CE311C4");
    Assert.equal(armor.exitCode, 0);
    Assert.ok(armor.keyData.search(/-----BEGIN PGP PUBLIC KEY BLOCK-----/) === 0);
    Assert.ok(armor.keyData.length > 2800);

    const PgpJS = getOpenPGPLibrary();
    r = await PgpJS.readKeys({
      armoredKeys: armor.keyData
    });
    Assert.ok(r.length === 1);
    Assert.equal(r[0].getFingerprint().toUpperCase(), "65537E212DC19025AD38EDB2781617319CE311C4");

    r = await cApi.deleteKeys(["0x65537E212DC19025AD38EDB2781617319CE311C4"]);
    Assert.equal(r.exitCode, 0);

    r = await cApi.getKeys(["0x65537E212DC19025AD38EDB2781617319CE311C4"]);
    Assert.equal(r.length, 0);
  }
  catch (ex) {
    Assert.ok(false, "exception: " + ex.toString() + "\n" + ex.stack);
  }
}))));

test(withTestGpgHome(withEnigmail(asyncTest(async function testImportExport() {
  try {
    const cApi = getOpenPGPjsAPI();
    const PgpJS = getOpenPGPLibrary();

    cApi.initialize();
    let keyFile = do_get_file("resources/multi-uid.asc", false);
    let r = await cApi.importKeyFromFile(keyFile);

    Assert.equal(r.exitCode, 0);
    Assert.equal(r.importSum, 1);
    Assert.equal(r.importedKeys[0], "ADC49530CB6B132412D856107F1568CB8997F7BA");

    keyFile = do_get_file("resources/multi-uid.sec", false);
    r = await cApi.importKeyFromFile(keyFile);
    Assert.equal(r.exitCode, 0);
    Assert.equal(r.importSum, 1);


    let armor = await cApi.extractPublicKey("0xADC49530CB6B132412D856107F1568CB8997F7BA");
    Assert.equal(armor.exitCode, 0);
    Assert.ok(armor.keyData.search(/-----BEGIN PGP PUBLIC KEY BLOCK-----/) === 0);
    Assert.ok(armor.keyData.length > 2800);
    r = await PgpJS.readKeys({
      armoredKeys: armor.keyData
    });
    Assert.ok(r.length === 1);
    Assert.equal(r[0].users.length, 5);

    armor = await cApi.extractSecretKey("0xADC49530CB6B132412D856107F1568CB8997F7BA", true);
    Assert.equal(armor.exitCode, 0);
    Assert.ok(armor.keyData.search(/-----BEGIN PGP PRIVATE KEY BLOCK-----/) === 0);
    Assert.ok(armor.keyData.length > 2800);

    r = await PgpJS.readPrivateKeys({
      armoredKeys: armor.keyData
    });
    Assert.ok(r.length === 1);
    Assert.equal(r[0].getFingerprint().toUpperCase(), "ADC49530CB6B132412D856107F1568CB8997F7BA");
    Assert.ok(r[0].isPrivate());
    Assert.equal(r[0].users.length, 1);

    r = await cApi.getMinimalPubKey("0xADC49530CB6B132412D856107F1568CB8997F7BA");
    Assert.ok(r.keyData.length > 2800);

    r = await PgpJS.readKeys({
      armoredKeys: EnigmailOpenPGP.bytesToArmor(PgpJS.enums.armor.publicKey, atob(r.keyData))
    });
    Assert.ok(r.length === 1);
    Assert.equal(r[0].getFingerprint().toUpperCase(), "ADC49530CB6B132412D856107F1568CB8997F7BA");
    Assert.ok(!r[0].isPrivate());
    Assert.equal(r[0].users.length, 1);
    Assert.equal(r[0].users[0].userID.userID, "Unit Test <alice@example.invalid>");
  }
  catch (ex) {
    Assert.ok(false, "exception: " + ex.toString() + "\n" + ex.stack);
  }
}))));

test(withTestGpgHome(withEnigmail(asyncTest(async function testSignatures() {
  try {
    const cApi = getOpenPGPjsAPI();
    const PgpJS = getOpenPGPLibrary();

    cApi.initialize();
    let keyFile = do_get_file("resources/multi-uid.asc", false);
    let r = await cApi.importKeyFromFile(keyFile);

    Assert.equal(r.exitCode, 0);
    Assert.equal(r.importSum, 1);
    Assert.equal(r.importedKeys[0], "ADC49530CB6B132412D856107F1568CB8997F7BA");

    let signedUids = await cApi.getKeySignatures("ADC49530CB6B132412D856107F1568CB8997F7BA", true);

    Assert.equal(signedUids.length, 4);
    Assert.equal(signedUids[0].userId, "Unit Test <alice@example.invalid>");
    Assert.equal(signedUids[0].sigList.length, 2);
    Assert.equal(signedUids[0].sigList[0].signerKeyId, "ADC49530CB6B132412D856107F1568CB8997F7BA");
    Assert.equal(signedUids[0].sigList[0].sigType, "13x");
    Assert.equal(signedUids[0].sigList[0].createdTime, 1536940615);
    Assert.ok(signedUids[0].sigList[0].sigKnown);
    Assert.equal(signedUids[0].sigList[0].fpr, "ADC49530CB6B132412D856107F1568CB8997F7BA");

    Assert.equal(signedUids[0].sigList[1].signerKeyId, "65537E212DC19025AD38EDB2781617319CE311C4");
    Assert.equal(signedUids[0].sigList[1].sigKnown, false);
    Assert.equal(signedUids[0].sigList[1].createdTime, 1536940295);
  }
  catch (ex) {
    Assert.ok(false, "exception: " + ex.toString());
  }
}))));


test(withTestGpgHome(withEnigmail(asyncTest(async function testKeyGen() {
  const DAY = 86400000;

  try {
    const cApi = getOpenPGPjsAPI();
    cApi.initialize();

    // Test ECC Key
    let handle = cApi.generateKey("Test User", "", "testuser@invalid.domain", 5, 0, "ECC", "");
    let retObj = await handle.promise;
    Assert.equal(retObj.exitCode, 0);
    let fpr = retObj.generatedKeyId;
    Assert.equal(fpr.search(/^0x[0-9A-F]+$/), 0);

    let keyList = await cApi.getKeys([fpr]);
    Assert.equal(keyList.length, 1);

    let keyObj = keyList[0];
    Assert.equal(keyObj.keyTrust, "u");
    Assert.equal(keyObj.userId, "Test User <testuser@invalid.domain>");
    Assert.equal(keyObj.algoSym, "EDDSA");
    Assert.equal(keyObj.subKeys.length, 1);
    Assert.ok(keyObj.expiryTime > 0);

    // Test RSA Key
    handle = cApi.generateKey("Test User 2", "", "testuser2@invalid.domain", 0, 4096, "RSA", "");
    retObj = await handle.promise;
    Assert.equal(retObj.exitCode, 0);
    fpr = retObj.generatedKeyId;
    Assert.equal(fpr.search(/^0x[0-9A-F]+$/), 0);

    keyList = await cApi.getKeys([fpr]);
    Assert.equal(keyList.length, 1);

    keyObj = keyList[0];
    Assert.equal(keyObj.keyTrust, "e");
    Assert.equal(keyObj.userId, "Test User 2 <testuser2@invalid.domain>");
    Assert.equal(keyObj.algoSym, "RSA");
    Assert.equal(keyObj.subKeys.length, 1);
    Assert.equal(keyObj.expiryTime, 0);

  }
  catch (ex) {
    Assert.ok(false, "exception: " + ex.toString());
  }
}))));
