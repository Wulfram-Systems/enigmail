/*global do_load_module: false, do_get_file: false, do_get_cwd: false, testing: false, test: false, Assert: false, resetting: false */
/*global do_test_pending: false, do_test_finished: false, withTestGpgHome: false, asyncTest: false */

/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

"use strict";

do_load_module("file://" + do_get_cwd().path + "/testHelper.js");

ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-crypto-main.jsm"); /*global pgpjs_crypto: false */

const EnigmailFiles = ChromeUtils.import("chrome://enigmail/content/modules/files.jsm").EnigmailFiles;
const EnigmailArmor = ChromeUtils.import("chrome://enigmail/content/modules/armor.jsm").EnigmailArmor;
const EnigmailConstants = ChromeUtils.import("chrome://enigmail/content/modules/constants.jsm").EnigmailConstants;
const pgpjs_keyStore = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/pgpjs-keystore.jsm").pgpjs_keyStore;
const getOpenPGPLibrary = ChromeUtils.import("chrome://enigmail/content/modules/stdlib/openpgp-loader.jsm").getOpenPGPLibrary;

test(withTestGpgHome(asyncTest(async function testDecrypt() {
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

    const encFile = do_get_file("resources/pgpMime-msg.eml", false);
    let fileData = EnigmailFiles.readFile(encFile);
    let pgpMsg = EnigmailArmor.splitArmoredBlocks(fileData)[0];

    let result = await pgpjs_crypto.processPgpMessage(pgpMsg, {});
    Assert.equal(result.statusFlags, EnigmailConstants.DECRYPTION_FAILED | EnigmailConstants.NO_SECKEY);

    const pubKeyFile = do_get_file("resources/dev-strike.sec", false);
    fileData = EnigmailFiles.readBinaryFile(pubKeyFile);

    let r = await pgpjs_keyStore.writeKey(fileData);
    Assert.equal(r.length, 1);

    result = await pgpjs_crypto.processPgpMessage(pgpMsg, {});
    Assert.equal(result.statusFlags, EnigmailConstants.DECRYPTION_OKAY | EnigmailConstants.GOOD_SIGNATURE | EnigmailConstants.TRUSTED_IDENTITY);
    Assert.equal(result.exitCode, 0);
    Assert.equal(result.sigDetails, "65537E212DC19025AD38EDB2781617319CE311C4 2020-03-21 1584808355 0 4 0 1 8 00 65537E212DC19025AD38EDB2781617319CE311C4");
    Assert.equal(result.decryptedData, "This is a test\n");
    Assert.equal(result.keyId, "65537E212DC19025AD38EDB2781617319CE311C4");
    Assert.equal(result.userId, "anonymous strike <strike.devtest@gmail.com>");
    Assert.equal(result.encryptedFileName, "message.txt");

    // this is a simple plain text wrapped such that it looks like a OpenPGP message
    const storedMsg = `-----BEGIN PGP MESSAGE-----

owE7rZbEEOfZI+yRmpOTr1CeX5SToscVkpFZrABEiQolqcUlCla6mlwA
=aAp2
-----END PGP MESSAGE-----`;

    result = await pgpjs_crypto.processPgpMessage(storedMsg, {});
    Assert.equal(result.statusFlags, 0);
    Assert.equal(result.exitCode, 0);
    Assert.equal(result.sigDetails, "");
    Assert.equal(result.decryptedData, "Hello world.\nThis is a test :-)\n");

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

    result = await pgpjs_crypto.processPgpMessage(signedMsg, {});
    Assert.equal(result.statusFlags, EnigmailConstants.GOOD_SIGNATURE | EnigmailConstants.TRUSTED_IDENTITY);
    Assert.equal(result.exitCode, 0);
    Assert.equal(result.sigDetails, "65537E212DC19025AD38EDB2781617319CE311C4 2020-02-16 1581878756 0 4 0 1 8 00 65537E212DC19025AD38EDB2781617319CE311C4");
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
-----END PGP SIGNATURE-----
`;

    result = await pgpjs_crypto.verify(clearSigned, {});
    Assert.equal(result.statusFlags, EnigmailConstants.GOOD_SIGNATURE | EnigmailConstants.TRUSTED_IDENTITY);
    Assert.equal(result.exitCode, 0);
    Assert.equal(result.sigDetails, "65537E212DC19025AD38EDB2781617319CE311C4 2020-02-16 1581879420 0 4 0 1 8 00 65537E212DC19025AD38EDB2781617319CE311C4");
    Assert.equal(result.keyId, "65537E212DC19025AD38EDB2781617319CE311C4");
    Assert.equal(result.userId, "anonymous strike <strike.devtest@gmail.com>");
    Assert.equal(result.decryptedData, "Hello world.\r\nThis is a test :-)");

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

    result = await pgpjs_crypto.processPgpMessage(noMdcProtection, {});
    Assert.equal(result.statusFlags, EnigmailConstants.DECRYPTION_FAILED | EnigmailConstants.MISSING_MDC);
    Assert.equal(result.exitCode, 0);
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

    result = await pgpjs_crypto.processPgpMessage(badMdc, {});
    Assert.equal(result.statusFlags, EnigmailConstants.DECRYPTION_FAILED);
    Assert.equal(result.exitCode, 1);
    Assert.equal(result.decryptedData, "");

    const packetV3 = `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

Hello world.
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.2.3

iD8DBQE+yUcu4mZch0nhy8kRAuh/AKDM1Xc49BKVfJIFg/btWGfbF/pgcwCgw0Zk
3bVpfUMtjVsz6ChXUG35fMY=
=n4PF
-----END PGP SIGNATURE-----
`;

    result = await pgpjs_crypto.verify(packetV3, {});
    Assert.equal(result.statusFlags, EnigmailConstants.UNVERIFIED_SIGNATURE);
    Assert.equal(result.exitCode, 2);
    Assert.equal(result.decryptedData, "");
  }
  catch (ex) {
    Assert.ok(false, "exception: " + ex.toString());
  }
})));


test(withTestGpgHome(asyncTest(async function testVerifyFile() {
  await pgpjs_keyStore.init();

  const attachmentFile = do_get_file("resources/attachment.txt", false);
  const signatureFile = do_get_file("resources/attachment.txt.asc", false);
  const pubKeyFile = do_get_file("resources/dev-strike.asc", false);

  try {
    await pgpjs_crypto.verifyFile(attachmentFile.path, signatureFile.path);
    Assert.ok(false, "Should not obtain a valid verification");
  }
  catch (err) {
    Assert.assertContains(String(err), "Unverified signature - signed with unknown key");
  }

  let keyData = EnigmailFiles.readBinaryFile(pubKeyFile);
  let result = await pgpjs_keyStore.writeKey(keyData);
  Assert.equal(result.length, 1);

  result = await pgpjs_crypto.verifyFile(attachmentFile.path, signatureFile.path);
  Assert.assertContains(result, 'Good signature from anonymous strike');
  Assert.assertContains(result, 'Key ID: 0x65537E212DC19025AD38EDB2781617319CE311C');
})));
