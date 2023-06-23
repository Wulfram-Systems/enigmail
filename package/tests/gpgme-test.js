/*global do_load_module: false, do_get_file: false, do_get_cwd: false, testing: false, test: false, Assert: false, do_get_tmp_dir: false */
/*global do_test_pending: false, do_test_finished: false, withTestGpgHome: false, asyncTest: false, withEnigmail: false, withOverwriteFuncs: false */

/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

"use strict";

do_load_module("file://" + do_get_cwd().path + "/testHelper.js");
/* global TestHelper: false */

testing("cryptoAPI/gpgme.js"); /*global getGpgMEApi: false, EnigmailFiles: false, EnigmailConstants: false, EnigmailExecution: false */
const EnigmailArmor = ChromeUtils.import("chrome://enigmail/content/modules/armor.jsm").EnigmailArmor;

test(function testGroups() {
  const gpgmeApi = getGpgMEApi();

  gpgmeApi.execJsonCmd = async function(input) {
    Assert.equal(input.op, "config_opt");
    Assert.equal(input.component, "gpg");
    Assert.equal(input.option, "group");

    return {
      "option": {
        "name": "group",
        "description": "set up email aliases",
        "argname": "SPEC",
        "flags": 4,
        "level": 1,
        "type": 37,
        "alt_type": 1,
        "value": [{
          "string": "Testgroup1=someone@domain1.invalid next@domain.invalid",
          "is_none": false
        }, {
          "string": "testGroup2=strike@enigmail.net",
          "is_none": false
        }, {
          "string": "testgroup1=onemore@enigmail.net",
          "is_none": false
        }]
      }
    };
  };

  let res = gpgmeApi.getGroups();
  Assert.equal(res.length, 2);
});

test(withTestGpgHome(withEnigmail(asyncTest(async (esvc, window) => {
  // Test key importing and key listing
  const gpgmeApi = getGpgMEApi();
  gpgmeApi.initialize(null, esvc, null);

  const pubKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----" +
    "\n" +
    "\n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" +
    "\nsnHSt1DRJA==" +
    "\n=I9l9" +
    "\n-----END PGP PUBLIC KEY BLOCK-----";

  let impKeys = await gpgmeApi.importKeyData(pubKey, false, null);
  Assert.equal(impKeys.importSum, 1);
  Assert.equal(impKeys.importedKeys.length, 1);
  Assert.equal(impKeys.importedKeys[0], "65537E212DC19025AD38EDB2781617319CE311C4");
  Assert.equal(impKeys.importUnchanged, 0);

  let keyList = await gpgmeApi.getKeys();

  Assert.equal(keyList.length, 1);
  Assert.equal(keyList[0].fpr, "65537E212DC19025AD38EDB2781617319CE311C4");
  Assert.equal(keyList[0].userId, "anonymous strike <strike.devtest@gmail.com>");
  Assert.equal(keyList[0].expiryTime, 0);
  Assert.equal(keyList[0].keyTrust, "-");
  Assert.equal(keyList[0].ownerTrust, "-");
  Assert.equal(keyList[0].keyUseFor, "sec");
  Assert.equal(keyList[0].keySize, 4096);
  Assert.equal(keyList[0].algoSym, "RSA");
  Assert.equal(keyList[0].keyCreated, 1430756251);
  Assert.equal(keyList[0].type, "pub");
  Assert.equal(keyList[0].userIds.length, 1);
  Assert.equal(keyList[0].subKeys.length, 1);
  Assert.equal(keyList[0].subKeys[0].keyId, "D535623BB60E9E71");
  Assert.equal(keyList[0].subKeys[0].expiryTime, 0);
  Assert.equal(keyList[0].subKeys[0].keyUseFor, "e");
  Assert.equal(keyList[0].subKeys[0].keySize, 4096);
  Assert.equal(keyList[0].subKeys[0].algoSym, "RSA");
  Assert.equal(keyList[0].subKeys[0].keyCreated, 1430756251);
  Assert.equal(keyList[0].subKeys[0].type, "sub");
  Assert.equal(keyList[0].userIds[0].userId, "anonymous strike <strike.devtest@gmail.com>");
  Assert.equal(keyList[0].userIds[0].keyTrust, "-");
  Assert.equal(keyList[0].userIds[0].uidFpr, "0");
  Assert.equal(keyList[0].userIds[0].type, "uid");
}))));


test(withTestGpgHome(withEnigmail(asyncTest(async function testDecrypt(esvc, window) {
  const gpgmeApi = getGpgMEApi();
  gpgmeApi.initialize(null, esvc, null);

  Assert.ok(gpgmeApi.supportsFeature("supports-gpg-agent"));
  const encFile = do_get_file("resources/pgpMime-msg.eml", false);
  let fileData = EnigmailFiles.readFile(encFile);
  let pgpMsg = EnigmailArmor.splitArmoredBlocks(fileData)[0];

  let result = await gpgmeApi.decrypt(pgpMsg, {});
  Assert.equal(result.statusFlags, EnigmailConstants.DECRYPTION_FAILED);

  const secKeyFile = do_get_file("resources/dev-strike.sec", false);
  let r = await gpgmeApi.importKeyFromFile(secKeyFile, false, null);
  Assert.equal(r.importSum, 1);

  let keyList = await gpgmeApi.getKeys();
  Assert.equal(keyList.length, 1);
  Assert.equal(keyList[0].keyId, "781617319CE311C4");

  result = await gpgmeApi.decrypt(pgpMsg, {});
  Assert.ok(result.statusFlags & EnigmailConstants.DECRYPTION_OKAY);

  Assert.equal(result.exitCode, 0);
  Assert.equal(result.sigDetails, "65537E212DC19025AD38EDB2781617319CE311C4 2020-03-21 1584808355 0 4 0 RSA SHA256 00 65537E212DC19025AD38EDB2781617319CE311C4");
  Assert.equal(result.decryptedData, "This is a test\n");
  Assert.equal(result.keyId, "65537E212DC19025AD38EDB2781617319CE311C4");
  Assert.equal(result.userId, "anonymous strike <strike.devtest@gmail.com>");
  Assert.equal(result.encryptedFileName, "message.txt");

  // this is a simple plain text wrapped such that it looks like a OpenPGP message
  const storedMsg = `-----BEGIN PGP MESSAGE-----

owE7rZbEEOfZI+yRmpOTr1CeX5SToscVkpFZrABEiQolqcUlCla6mlwA
=aAp2
-----END PGP MESSAGE-----`;

  result = await gpgmeApi.decrypt(storedMsg, {});
  Assert.equal(result.statusFlags, EnigmailConstants.DECRYPTION_FAILED | EnigmailConstants.NODATA);
  Assert.equal(result.exitCode, 1);
  Assert.equal(result.sigDetails, "");
  Assert.equal(result.decryptedData, "");

  // this is a signed-only message
  const signedMsg = `-----BEGIN PGP MESSAGE-----

owEBbQKS/ZANAwAIAXgWFzGc4xHEAcsmYgBeSY3kSGVsbG8gd29ybGQuClRoaXMg
aXMgYSB0ZXN0IDotKQqJAjMEAAEIAB0WIQRlU34hLcGQJa047bJ4FhcxnOMRxAUC
XkmN5AAKCRB4FhcxnOMRxAicD/4jPSNH27H+G83beIyZW5UU0vzr51fHQgz+keXH
XYDpS0j7upZ2c4m5GAkc1hpdU2FMgUeksjCYhEXsIgh5RkCcacW01dr7Jw4ZgVCl
eCzuMXNWYANVE2dVt3EZb/E6G6by+T1gYn2SBfZSLnBrN6r552J9Ae65MgOKWOAV
nZ9679ys3N5BLX6cctfTc0+nE3sOmuNK3/C6cn5+FVvnTZXKBXU37Zxrs/BL46Jy
JKoxpx3yVobKw7Esef4GeAYxIEDn02mNIVXJsnr+g6YtP+gWdcuuHLyGjd/Oakuj
gbx4JmlUjUTZvoH/c40LEMtWCJ0qUUIeqEQLGYGWrfdpimc48Eli/nxxgTNrPbB3
KADtiAito4JNWoovqJA+F4MkV3qB5A6xLk5cCmZhw92PfwABoIEJY7WeoRSU8aws
2G/2QTFtOgKqwYdc15OhMP/+E4EB8sIHheaRAfhsyFq1mCMEMFFTqutu3XwaFFpp
ifNuTRIruL7nup/f5pmDD8afC2xNUe9as7L26IqRDBHuU8hwAq2t0hoo3eSLN1Ow
Av8j88klWOEH6vUiOi5gIlCNQH5CNsgBynMfz9IC8p35ExQLVnA3KxTGL3Uxmgvh
YjlIbvu0YmTlsQvYFW4JBIPNeNy+1r+7PCsSbnOtsSU32/4SnnQVN4khCM+gKTHD
j8bbyQ==
=fwVK
-----END PGP MESSAGE-----`;

  result = await gpgmeApi.decrypt(signedMsg, {
    verifyOnly: true
  });
  Assert.equal(result.statusFlags, EnigmailConstants.GOOD_SIGNATURE);
  Assert.equal(result.exitCode, 0);
  Assert.equal(result.sigDetails, "65537E212DC19025AD38EDB2781617319CE311C4 2020-02-16 1581878756 0 4 0 RSA SHA256 00 65537E212DC19025AD38EDB2781617319CE311C4");
  Assert.equal(result.keyId, "65537E212DC19025AD38EDB2781617319CE311C4");
  Assert.equal(result.userId, "anonymous strike <strike.devtest@gmail.com>");
  Assert.equal(result.decryptedData, "Hello world.\nThis is a test :-)\n");

  const clearSigned = `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Hello world.
This is a test :-)
-----BEGIN PGP SIGNATURE-----

iQIzBAEBCAAdFiEEZVN+IS3BkCWtOO2yeBYXMZzjEcQFAl5JkHwACgkQeBYXMZzj
EcQbbA/9Eu9DhB+3rkRIswp+tOmyjyytlL3V++Lfla1hUpfeC3VNC9iY3Y8TwuBW
yvPzloXD1YvVoG8QZZEqGxWEli9PcLtGLUZecSmMSD5+sKm9Muj2ahxnDSM1qN0V
yOQ+IXBtfhjDM7Zz7Xxvtv8mcRkBgQ4DAkxHTXhnBjYxo0TpffDwpmqQ0YkZCjt2
PzzYy050uL7cJZU94P5ENHtKNUkjnKgfTWqefjCG15WSj19tfxG6EHOpEnPy8fwF
gW+RnnGFRP41GctKDJh3tJ2ydiGr+1XaGmOx/M5PM0RT69mmlSnjSVQC7+xnZdX4
9AL/jOyDwRK2AFOo+mCoMFTM9WhScQC5zcoDKn1uKb1WPsjH8nrWro43yJPq2w4I
Nlqhia3bNPadPzfK3/ec++pea8byjjAuLYVe7QskNUIsfdew+m8rlhy2zDzTPSlr
uB+5+AtxV8yXxh5ATmjXlU/RiK1YIKu7QzueGKNjKrAqLTX+YwVX0HH0v2SAQZoL
JGWYnspuCiOYm19OkQoZ6NQYbqadqqakvHzrbjODHrnmlq9XJzEZ5cbhf6oeO4FT
wJEP0gfdDZA1bEV78SRcjJDlfo5vuWX4W/ZlAlA9hy5OVq69DOdlcVdgj18+gy94
+SPb1y4WzJ3KARDpgsruHZ6FnAEU1clxc5pEjll/MIeYP5NW0JM=
=WyPS
-----END PGP SIGNATURE-----`;

  result = await gpgmeApi.decrypt(clearSigned, {
    verifyOnly: true
  });
  Assert.equal(result.statusFlags, EnigmailConstants.GOOD_SIGNATURE);
  Assert.equal(result.exitCode, 0);
  Assert.equal(result.sigDetails, "65537E212DC19025AD38EDB2781617319CE311C4 2020-02-16 1581879420 0 4 0 RSA SHA256 00 65537E212DC19025AD38EDB2781617319CE311C4");
  Assert.equal(result.keyId, "65537E212DC19025AD38EDB2781617319CE311C4");
  Assert.equal(result.userId, "anonymous strike <strike.devtest@gmail.com>");
  Assert.equal(result.decryptedData, "Hello world.\nThis is a test :-)\n");

  const noMdcProtection = `-----BEGIN PGP MESSAGE-----

hQIMA9U1Yju2Dp5xARAAtAZjLVld1nOStJXw18BBbvLXZU5GydCKXKn7XvY8oT6O
tWAqrEu+rLfx0IhNKLwo5lQE5kTBoydoXBCh0wRX9P6ZCmlZKmGo0AijzhDfQ6sy
G7hQZbf0D0nxTGbSfuGwna7h/zhluYu8Zf9mqkITkbvPNRKIcouDedcZfmc1JELu
jK5+sNt1eDqL/Sic1SOwAxhFyVr2s397z74ZQbH/Xs0bhnQaYPOnHAh8SB4WJCjb
boDJbisJa87VEr9xgw/25YdqGkRFACZ47QIUKJ9jQywqaDwxfcJy8t3sNkE+SBZB
dbJLRH78923eP/0djDPsfKq3/egUf4sfumv4Rx4hhrM+ZZRMio/2NPjVA3NKmM9z
Tl/hp/825mL4mNheH/nHW1rBb58DI0VFJ9WeMq5X3mKc7Nqllv2P5KP+JfotifTG
A89ZArE26tuPLSDtmb7yOWAkIIM7hJnIenWT8Vf/mD76FxBwd/lz0iAjwRtGhlkr
7ARbWRqdaOwlExllfFJ3DmmBTDdKp3gbRmGTZMA3/zEjxuy/PU7OqSn4KX44MNVb
I881kAj7rbAprjDC5lNAsCrXibS/yoQd5z2cDOM6WOFpq+65a7Mfp9ByvxdVJ8n1
lWv9BzKlk2Lo3vhG3zSobOPZ0b4/kgXFuuoRY85sW7S94YahAPfyNFdKDvStF4jJ
MBv+amSxwYvdlpRMJcBa48saFHionNWfjGlulsbLAnBGQNi4qYye5ZzNi+A/ERnz
TA==
=6sUw
-----END PGP MESSAGE-----`;

  result = await gpgmeApi.decrypt(noMdcProtection, {});
  Assert.equal(result.statusFlags, EnigmailConstants.DECRYPTION_FAILED);
  Assert.equal(result.exitCode, 1);
  Assert.equal(result.decryptedData, "");

  const badMdc = `-----BEGIN PGP MESSAGE-----

hQIMA9U1Yju2Dp5xARAAnIdEzfwCFOHmBpd5FLoldI0sh6b1J5z6h3SlWyb6D07T
ObvOt3REynBpF1bEb6XfAhqUx5FpKwcoeTlGuxUSMlurwRmDpUOr913+1wxnY0q5
J1fclLIsFiDCcWYdwYsDTZoAmHbaoGXT+v+/we+hPpm81z9YxsxuwdcXesRxqImq
Da3IKG+fW8HvD7BmcOZPYoyfZnMUSld9lQ5cZ7DD/BQblEDZQX2rVYSNIoi9YPIa
puGr8PU1+CJeyJgk+RnMD7vItk3+BqyS7ybbzOFfhyQcBTlVgURMA88Pk42EUleP
oT3TwXvvB410l/FQAb21QQmmXjc+RObuEaAZoJmXmv+2e+LBZTniTYBK16WaHYNU
/N+5Hknf2193WAVbxea3Tw8tCpHj8IjbTde+zgMwmoRoLvB3RSpyL6NyBPYTxCXW
b0aLsu5J74v5UD3SjzEu5kXaQJCvaBy7n6oqccyMe66ZVDHqaS7PYAyjbt3O2Fni
LxmaM9NkpH7lQAiErRwrN+8yD/ypY5+532naB+QcN7iYsV5o6p78SvGNchvF9x/8
H0lcXBzL3PfEQBeMy6bWkXjE060lxz7hWi6dA24zHXDImJp9Se8DEg3LXf2h4Gpa
r45rGHjoRO/oNb6Ccw/dt1dqEISs1LooPTbtBAcy4F33PDvM3LuKZByZIFJTb8PS
RwFT30I1c1xcp7D4Jgv3cWCks39z0jxfmSPLYyPjI1tT7Zi9m9vZN0ZfVC/XvJiT
fsTKNmsBfsUHg/qzu+yD0e4bTuEKVsDcCg==
=WPhs
-----END PGP MESSAGE-----`;

  result = await gpgmeApi.decrypt(badMdc, {});
  Assert.equal(result.statusFlags, EnigmailConstants.DECRYPTION_FAILED | EnigmailConstants.NODATA);
  Assert.equal(result.exitCode, 1);
  Assert.equal(result.decryptedData, "");

  const unknownPubkey = `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

Hello world.
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.2.3

iD8DBQE+yUcu4mZch0nhy8kRAuh/AKDM1Xc49BKVfJIFg/btWGfbF/pgcwCgw0Zk
3bVpfUMtjVsz6ChXUG35fMY=
=n4PF
-----END PGP SIGNATURE-----`;

  result = await gpgmeApi.decrypt(unknownPubkey, {
    verifyOnly: true
  });
  Assert.equal(result.statusFlags, EnigmailConstants.UNVERIFIED_SIGNATURE | EnigmailConstants.NO_PUBKEY);
  Assert.equal(result.exitCode, 0);
  Assert.equal(result.decryptedData, "Hello world.\n");


  const attachmentFile = do_get_file("resources/attachment.txt", false);
  fileData = EnigmailFiles.readFile(attachmentFile);
  const attachmentSig = do_get_file("resources/attachment.txt.asc", false);
  let sigData = EnigmailFiles.readFile(attachmentSig);
  result = await gpgmeApi.verifyMime(fileData, sigData);
  Assert.equal(result.statusFlags, EnigmailConstants.GOOD_SIGNATURE);
}))));


test(withTestGpgHome(withEnigmail(asyncTest(async function testDeleteKey(esvc, window) {
  const gpgmeApi = getGpgMEApi();
  gpgmeApi.initialize(null, esvc, null);

  const secKeyFile = do_get_file("resources/dev-strike.sec", false);
  let r = await gpgmeApi.importKeyFromFile(secKeyFile, false, null);
  Assert.equal(r.importSum, 1);

  // delete some unknown key
  r = await gpgmeApi.deleteKeys(["0x347562ABCD34234DD34234B3456E3546C2456EEE"], false);
  Assert.ok(r.exitCode !== 0, "deletion not possible");

  // delete private key
  r = await gpgmeApi.deleteKeys(["0x65537E212DC19025AD38EDB2781617319CE311C4"], true);
  Assert.equal(r.exitCode, 0, "deletion of secret key");
}))));


test(withTestGpgHome(withEnigmail(asyncTest(async function testExportKey(esvc, window) {
  const gpgmeApi = getGpgMEApi();
  gpgmeApi.initialize(null, esvc, null);

  const secKeyFile = do_get_file("resources/multi-uid.sec", false);
  let r = await gpgmeApi.importKeyFromFile(secKeyFile, false, null);
  Assert.equal(r.importSum, 1);

  let keyData = (await gpgmeApi.extractPublicKey("0xADC49530CB6B132412D856107F1568CB8997F7BA")).keyData;
  Assert.equal(keyData.substr(0, 36), "-----BEGIN PGP PUBLIC KEY BLOCK-----");

  r = await testGpgKeyData(gpgmeApi, keyData);
  Assert.equal(r.split(/[\r\n]+/).length, 18);
  Assert.ok(r.includes("uid:-::::1536940615::680F6B5FD4CA9FDAB29407FAFBFA15339AB8A5A6::Unit Test <alice@example.invalid>"));
  Assert.ok(r.includes("uid:-::::1536939111::A692D45B4B173E4E7E05BA8E17A2D7EDBD85DB76::test.bob@somewhere.invalid"));
  Assert.ok(r.includes("uid:r::::::D707F090C6B85B86AE9A5168732CAEF3CA7D27FA::Error <revoked@example.org>"));
  Assert.ok(r.includes("uat:-::::1536939071::A3549B6F0E55083DCC5B5E5890E2CD2A4D4143EB"));
  Assert.ok(r.includes("sub:-:3072:1:BDB2B2394A9DDBFF:1536938954::::::e"));
  Assert.ok(r.includes("sub:r:3072:1:8B20932A70419EA6:1536939152::::::s"));
  Assert.ok(r.includes("sub:r:3072:1:0B24E9A73D088034:1536939191::::::e"));
  Assert.ok(r.includes("sub:-:3072:1:2462FC183074D416:1537000928::::::s"));
  Assert.ok(r.includes("sub:-:3072:1:BF99A9839B499171:1537000944::::::e"));

  keyData = (await gpgmeApi.extractSecretKey("0xADC49530CB6B132412D856107F1568CB8997F7BA", true)).keyData;
  Assert.equal(keyData.substr(0, 37), "-----BEGIN PGP PRIVATE KEY BLOCK-----");

  r = await testGpgKeyData(gpgmeApi, keyData);
  Assert.equal(r.split(/[\r\n]+/).length, 20);

  Assert.ok(r.includes("sec:-:3072:1:7F1568CB8997F7BA:1536938954:::-:::scESC"));
  Assert.ok(r.includes("uid:-::::1536940615::680F6B5FD4CA9FDAB29407FAFBFA15339AB8A5A6::Unit Test <alice@example.invalid>"));
  Assert.ok(r.includes("uid:r::::::D707F090C6B85B86AE9A5168732CAEF3CA7D27FA::Error <revoked@example.org>") === false);
  Assert.ok(r.includes("uat:-::::1536939071::A3549B6F0E55083DCC5B5E5890E2CD2A4D4143EB") === false);
  Assert.ok(r.includes("ssb:-:3072:1:BDB2B2394A9DDBFF:1536938954::::::e"));
  Assert.ok(r.includes("ssb:r:3072:1:8B20932A70419EA6:1536939152::::::s"));
  Assert.ok(r.includes("ssb:r:3072:1:0B24E9A73D088034:1536939191::::::e"));
  Assert.ok(r.includes("ssb:-:3072:1:2462FC183074D416:1537000928::::::s"));
  Assert.ok(r.includes("ssb:-:3072:1:BF99A9839B499171:1537000944::::::e"));

  keyData = (await gpgmeApi.getMinimalPubKey("0xADC49530CB6B132412D856107F1568CB8997F7BA", "test.bob@somewhere.invalid", [1536939152, 1536939191])).keyData;
  Assert.equal(keyData.substr(0, 36), "mQGNBFub08oBDACmb04i4u8xUV1ADbnbN5l8");

  r = await testGpgKeyData(gpgmeApi, atob(keyData));
  Assert.equal(r.split(/[\r\n]+/).length, 8);
  Assert.ok(r.includes("uid:-::::1536939111::A692D45B4B173E4E7E05BA8E17A2D7EDBD85DB76::test.bob@somewhere.invalid"));
  Assert.ok(r.includes("uid:-::::1536940615::680F6B5FD4CA9FDAB29407FAFBFA15339AB8A5A6::Unit Test <alice@example.invalid>") === false);
  Assert.ok(r.includes("sub:r:3072:1:8B20932A70419EA6:1536939152::::::s"));
  Assert.ok(r.includes("sub:-:3072:1:2462FC183074D416:1537000928::::::s") === false);
}))));

test(withTestGpgHome(withEnigmail(asyncTest(async function testSignatures(esvc, window) {
  const gpgmeApi = getGpgMEApi();
  gpgmeApi.initialize(null, esvc, null);

  let keyFile = do_get_file("resources/multi-uid.asc", false);
  let r = await gpgmeApi.importKeyFromFile(keyFile);

  Assert.equal(r.exitCode, 0);
  Assert.equal(r.importSum, 1);
  Assert.equal(r.importedKeys[0], "ADC49530CB6B132412D856107F1568CB8997F7BA");

  let signedUids = await gpgmeApi.getKeySignatures("ADC49530CB6B132412D856107F1568CB8997F7BA", true);

  Assert.equal(signedUids.length, 4);
  Assert.equal(signedUids[0].userId, "Unit Test <alice@example.invalid>");
  Assert.equal(signedUids[0].sigList.length, 2);
  Assert.equal(signedUids[0].sigList[0].signerKeyId, "7F1568CB8997F7BA");
  Assert.equal(signedUids[0].sigList[0].sigType, "x");
  Assert.equal(signedUids[0].sigList[0].createdTime, 1536940615);
  Assert.ok(signedUids[0].sigList[0].sigKnown);

  Assert.equal(signedUids[0].sigList[1].signerKeyId, "781617319CE311C4");
  Assert.equal(signedUids[0].sigList[1].sigKnown, false);
  Assert.equal(signedUids[0].sigList[1].createdTime, 1536940295);
}))));

test(withTestGpgHome(withEnigmail(asyncTest(async function testAttachment(esvc, window) {
  const gpgmeApi = getGpgMEApi();
  gpgmeApi.initialize(null, esvc, null);

  const attachment = do_get_file("resources/attachment.txt", false);
  const signature = do_get_file("resources/attachment.txt.asc", false);

  try {
    await gpgmeApi.verifyAttachment(attachment.path, signature.path);
    Assert.ok(false, "Should not obtain a valid verification");
  }
  catch (err) {
    Assert.assertContains(err, "Unverified signature - signed with unknown key");
  }

  let keyFile = do_get_file("resources/dev-strike.asc", false);
  let r = await gpgmeApi.importKeyFromFile(keyFile);
  Assert.equal(r.exitCode, 0);

  try {
    let result = await gpgmeApi.verifyAttachment(attachment.path, signature.path);
    Assert.assertContains(result, 'Good signature from anonymous strike');
    Assert.assertContains(result, 'Key ID: 0x65537E212DC19025AD38EDB2781617319CE311C');
  }
  catch (err) {
    Assert.equal(err, "exception in verifyAttachment");
  }
}))));

test(withTestGpgHome(withEnigmail(asyncTest(async function testEncrypt(esvc, window) {
  const gpgmeApi = getGpgMEApi();
  gpgmeApi.initialize(null, esvc, null);

  const keyFile = do_get_file("resources/dev-strike.sec", false);
  let r = await gpgmeApi.importKeyFromFile(keyFile);
  Assert.equal(r.importSum, 1);

  let encryptFlags = (EnigmailConstants.SEND_ENCRYPTED | EnigmailConstants.SEND_ALWAYS_TRUST | EnigmailConstants.SEND_SIGNED | EnigmailConstants.SEND_ENCRYPT_TO_SELF);

  let result = await gpgmeApi.encryptMessage("0x65537E212DC19025AD38EDB2781617319CE311C4", "", "", encryptFlags, "Hello World");
  Assert.equal(result.exitCode, 0);
  Assert.ok(result.data.search(/^-----BEGIN PGP MESSAGE-----$/m) >= 0, "contains PGP start header");

  encryptFlags = EnigmailConstants.SEND_SIGNED | EnigmailConstants.SEND_TEST;
  result = await gpgmeApi.encryptMessage("0x65537E212DC19025AD38EDB2781617319CE311C4", null, null, encryptFlags, "Hello World");
  Assert.equal(result.exitCode, 0);
  Assert.ok(result.data.search(/-----BEGIN PGP SIGNED MESSAGE-----\r?\nHash: SHA(256|512)/) >= 0, "contains Hash header");

  encryptFlags = EnigmailConstants.SEND_SIGNED | EnigmailConstants.SEND_PGP_MIME;
  result = await gpgmeApi.encryptMessage("0x65537E212DC19025AD38EDB2781617319CE311C4", null, null, encryptFlags, "Hello World");
  Assert.equal(result.exitCode, 0);
  Assert.ok(result.data.search(/^-----BEGIN PGP SIGNATURE-----$/m) >= 0, "contains Hash header");
}))));


test(withTestGpgHome(withEnigmail(asyncTest(async function testEncrypt(esvc, window) {
  const gpgmeApi = getGpgMEApi();
  gpgmeApi.initialize(null, esvc, null);

  // Test ECC Key
  let handle = gpgmeApi.generateKey("Test User", "", "testuser@invalid.domain", 5, 0, "ECC", "");
  let retObj = await handle.promise;
  Assert.equal(retObj.exitCode, 0);
  let fpr = retObj.generatedKeyId;
  Assert.equal(fpr.search(/^0x[0-9A-F]+$/), 0);

  let keyList = await gpgmeApi.getKeys([fpr]);
  Assert.equal(keyList.length, 1);

  let keyObj = keyList[0];
  Assert.equal(keyObj.keyTrust, "u");
  Assert.equal(keyObj.userId, "Test User <testuser@invalid.domain>");
  Assert.equal(keyObj.algoSym, "EdDSA");
  Assert.equal(keyObj.subKeys.length, 1);
  Assert.ok(keyObj.expiryTime > 0);

  // Test RSA Key
  handle = gpgmeApi.generateKey("Test User 2", "", "testuser2@invalid.domain", 0, 4096, "RSA", "");
  retObj = await handle.promise;
  Assert.equal(retObj.exitCode, 0);
  fpr = retObj.generatedKeyId;
  Assert.equal(fpr.search(/^0x[0-9A-F]+$/), 0);

  keyList = await gpgmeApi.getKeys([fpr]);
  Assert.equal(keyList.length, 1);

  keyObj = keyList[0];
  Assert.equal(keyObj.keyTrust, "u");
  Assert.equal(keyObj.userId, "Test User 2 <testuser2@invalid.domain>");
  Assert.equal(keyObj.algoSym, "RSA");
  Assert.equal(keyObj.subKeys.length, 1);
  Assert.equal(keyObj.expiryTime, 0);
}))));

test(withTestGpgHome(withEnigmail(asyncTest(async function testOwnerTrust(esvc, window) {
  const gpgmeApi = getGpgMEApi();
  gpgmeApi.initialize(null, esvc, null);

  const keyFile = do_get_file("resources/dev-strike.sec", false);
  let r = await gpgmeApi.importKeyFromFile(keyFile);
  Assert.equal(r.importSum, 1);

  let keyList = await gpgmeApi.getKeys(["0x65537E212DC19025AD38EDB2781617319CE311C4"]);
  Assert.equal(keyList.length, 1);
  Assert.equal(keyList[0].keyTrust, "-");

  let otFile = do_get_tmp_dir();
  otFile.append("ownertrust-test.txt");
  if (!EnigmailFiles.writeFileContents(otFile, "65537E212DC19025AD38EDB2781617319CE311C4:6:\n")) {
    Assert.ok(false);
  }
  r = await gpgmeApi.importOwnerTrust(otFile);
  Assert.equal(r.exitCode, 0);

  keyList = await gpgmeApi.getKeys(["0x65537E212DC19025AD38EDB2781617319CE311C4"]);
  Assert.equal(keyList.length, 1);
  Assert.equal(keyList[0].keyTrust, "u");

  r = await gpgmeApi.getOwnerTrust(null);
  Assert.equal(r.exitCode, 0);
  Assert.ok(r.ownerTrustData.search(/^65537E212DC19025AD38EDB2781617319CE311C4:6:/m) >= 0);
}))));


test(withTestGpgHome(homeDir => {
  let cbFunc = withEnigmail(asyncTest(async function testGpgConfig(esvc, window) {
    const gpgmeApi = getGpgMEApi();
    gpgmeApi.initialize(null, esvc, null);

    let cfgDir = gpgmeApi.getConfigDir();
    Assert.equal(cfgDir, homeDir);
  }));

  cbFunc(homeDir);
}));

////////////////////////////////////////////////////////
// Helper Functions
////////////////////////////////////////////////////////
async function testGpgKeyData(gpgmeApi, keyData) {
  const importArgs = ["--no-default-keyring", "--no-tty", "--batch", "--no-verbose", "--with-fingerprint", "--with-colons", "--import-options", "import-show", "--dry-run", "--import"];
  let r = await EnigmailExecution.execAsync(gpgmeApi._gpgPath, importArgs, keyData);

  return r.stdoutData;
}
