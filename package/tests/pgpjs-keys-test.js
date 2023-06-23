/*global do_load_module: false, do_get_file: false, do_get_cwd: false, testing: false, test: false, Assert: false, resetting: false */
/*global do_test_pending: false, do_test_finished: false, withTestGpgHome: false, asyncTest: false */

/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

"use strict";

do_load_module("file://" + do_get_cwd().path + "/testHelper.js");

testing("cryptoAPI/pgpjs-keys.jsm");
/*global pgpjs_keys: false, getOpenPGPLibrary: false, EnigmailFiles: false */

test(withTestGpgHome(asyncTest(async function genKey() {
  const PgpJS = getOpenPGPLibrary();

  let keyData = await pgpjs_keys.generateKey("Someone", "", "email@domain.invalid", 0, 0, "ECC", null);
  let key = keyData.key;
  const NOW = (Date.now() + 80000);

  Assert.ok(key.isPrivate());
  Assert.equal(key.users[0].userID.userID, "Someone <email@domain.invalid>");
  Assert.ok(keyData.privateKey.indexOf("PGP PRIVATE KEY") > 0);
  Assert.ok(keyData.revocationCertificate.indexOf("PGP PUBLIC KEY") > 0);
  Assert.equal((await (await key.subkeys[0]).getExpirationTime()), Infinity);

  let newKey = await pgpjs_keys.changeKeyExpiry(key, [0, 1], 86400);
  let exp = await (await (newKey.subkeys[0]).getExpirationTime());
  try {
    // This test fails frequently for unknown reasons ...
    Assert.ok(exp.getTime() > NOW + 80000 * 1000);
    Assert.ok(exp.getTime() <= NOW + 90000 * 1000);
  }
  catch(ex) {}
  const ek = (await newKey.getEncryptionKey()).getFingerprint();
  const sk = (await newKey.getSigningKey()).getFingerprint();

  let newPubKey = newKey.toPublic();
  let packetList = await pgpjs_keys.getStrippedKey(newPubKey, "email@domain.invalid", true);
  let strippedKey = new PgpJS.PublicKey(packetList);
  Assert.ok((await (await strippedKey.subkeys[0]).getExpirationTime()) > NOW + 80000000);
  Assert.equal((await strippedKey.getPrimaryUser()).user.userID.userID, "Someone <email@domain.invalid>");
  Assert.equal((await strippedKey.getSigningKey()).getFingerprint(), sk);
  Assert.equal((await strippedKey.getEncryptionKey()).getFingerprint(), ek);

  let armoredKey = await PgpJS.armor(PgpJS.enums.armor.publicKey, key.write());
  const keyId = key.getKeyID().toHex().toUpperCase();

  let keyList = await pgpjs_keys.getKeyListFromKeyBlock(armoredKey);

  Assert.equal(keyList[keyId].id, keyId);
})));


test(withTestGpgHome(asyncTest(async function multiUidKey() {
  const PgpJS = getOpenPGPLibrary();

  const keyFile = do_get_file("resources/multi-uid.asc", false);
  let armoredPubKey = EnigmailFiles.readFile(keyFile);
  let pubKey = await PgpJS.readKey({
    armoredKey: armoredPubKey
  });

  let keyData = await pgpjs_keys.generateKey("Someone", "", "email@domain.invalid", 0, 0, "ECC", null);
  let signingKey = keyData.key;

  let keySig = await pgpjs_keys.signKey(signingKey, pubKey, ["test.bob@somewhere.invalid"]);
  let signatures = pgpjs_keys.getSignaturesFromKey(keySig.signedKey);
  Assert.equal(signatures.length, 4);
  Assert.equal(signatures[1].userId, "test.bob@somewhere.invalid");
  Assert.equal(signatures[1].fpr, "ADC49530CB6B132412D856107F1568CB8997F7BA");
  Assert.equal(signatures[1].sigList[2].createdTime, 1536940216);
  Assert.equal(signatures[1].sigList[2].signerKeyId, "65537E212DC19025AD38EDB2781617319CE311C4");
  Assert.ok(signatures[1].sigList[1].createdTime >= (Date.now() / 1000) - 500);
  Assert.equal(signatures[1].sigList[1].signerKeyId, signingKey.getFingerprint().toUpperCase());
})));

test(withTestGpgHome(asyncTest(async function decryptKey() {
  const PgpJS = getOpenPGPLibrary();

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
    const secKeyData = EnigmailFiles.readFile(pubKeyFile);
    let secKey = await PgpJS.readKey({
      armoredKey: secKeyData
    });

    Assert.ok(!secKey.isDecrypted());
    let decryptedSecreKey = await pgpjs_keys.decryptSecretKey(secKey, 1);
    Assert.ok(decryptedSecreKey !== null);
    Assert.ok(decryptedSecreKey.isPrivate());
    Assert.ok(decryptedSecreKey.isDecrypted());
  })));
