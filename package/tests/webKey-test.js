/*global do_load_module: false, do_get_file: false, do_get_cwd: false, testing: false, test: false, Assert: false, resetting: false, JSUnit: false, asyncTest: false, do_test_finished: false */
/*global TestHelper: false, withEnvironment: false, nsIWindowsRegKey: true */
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

"use strict";

do_load_module("file://" + do_get_cwd().path + "/testHelper.js");
/*global withEnigmail: false, component: false, withTestGpgHome: false, osUtils: false */

testing("webKey.jsm");
/*global EnigmailWks: false, GPG_WKS_CLIENT: false,
 EnigmailExecution: false, EnigmailFiles: false, EnigmailSend: false,
 EnigmailLog: false */
const subprocess = component("enigmail/subprocess.jsm").subprocess;
const EnigmailOS = component("enigmail/os.jsm").EnigmailOS;
const getGpgMEApi = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI/gpgme.js").getGpgMEApi;

function getWksPath() {
  var wksClient = GPG_WKS_CLIENT;
  if (EnigmailOS.isDosLike) {
    wksClient += ".exe";
  }

  return wksClient;
}

var GpgmeApi = null;

test(withTestGpgHome(withEnigmail(asyncTest(async (esvc, window) => {
  // Test key importing and key listing
  GpgmeApi = getGpgMEApi();
  GpgmeApi.initialize(null, esvc, null);
}))));

test(function getWksPathInBinDir() {
  TestHelper.resetting(GpgmeApi, "_gpgConfPath", "TEST_PATH", function() {
    TestHelper.resetting(EnigmailWks, "wksClientPath", null, function() {
      TestHelper.resetting(EnigmailExecution, "execStart", function(path, args, wat, win, listener, ops) {
        if (EnigmailOS.isDosLike) {
          listener.stdout("bindir:" + do_get_cwd().path + "\r\nlibexecdir:C:\\GnuPG\\lib\\exec\\dir\\test\r\n");
        } else {
          listener.stdout("bindir:" + do_get_cwd().path + "\nlibexecdir:/lib/exec/dir/test\n");
        }
        listener.done(0);

        let p = new Promise((resolve, reject) => {
          resolve(true);
        });

        return {
          'promise': p
        };
      }, function() {
        let win = JSUnit.createStubWindow();
        let handle = EnigmailWks.getWksClientPathAsync(win, function(ret) {
          let p = do_get_cwd().clone();
          p.append(getWksPath());
          Assert.equal(p.path, ret.path);
        });

        if (handle) {
          EnigmailExecution.syncProc(handle.promise);
        }
      });
    });
  });
});

test(function getWksPathInLibexecDir() {
  TestHelper.resetting(GpgmeApi, "_gpgConfPath", "TEST_PATH", function() {
    TestHelper.resetting(EnigmailWks, "wksClientPath", null, function() {
      TestHelper.resetting(EnigmailExecution, "execStart", function(path, args, wat, win, listener, ops) {
        if (EnigmailOS.isDosLike) {
          listener.stdout("libexecdir:" + do_get_cwd().path + "\r\nbindir:C:\\GnuPG\\bin\\dir\\test\r\n");
        } else {
          listener.stdout("libexecdir:" + do_get_cwd().path + "\nbindir:/bin/dir/test\n");
        }
        listener.done(0);
        let p = new Promise((resolve, reject) => {
          resolve(true);
        });

        return {
          'promise': p
        };
      }, function() {
        let win = JSUnit.createStubWindow();
        let handle = EnigmailWks.getWksClientPathAsync(win, function(ret) {
          let p = do_get_cwd().clone();
          p.append(getWksPath());
          Assert.equal(p.path, ret.path);
        });

        if (handle) {
          EnigmailExecution.syncProc(handle.promise);
        }
      });
    });
  });
});

test(function wksSubmitKey() {
  TestHelper.resetting(EnigmailWks, "wksClientPath", "WKS_CLIENT_DUMMY", function() {
    TestHelper.resetting(EnigmailExecution, "execStart", function(path, args, wat, win, listener, ops) {
      Assert.equal(path, "WKS_CLIENT_DUMMY");

      listener.stdout(
        `
From: test1@example.com
To: key-submit@example.com
Subject: Key publishing request
Wks-Draft-Version: 3
MIME-Version: 1.0
Content-Type: multipart/encrypted; protocol="application/pgp-encrypted";
  boundary="=-=01-uhb5j5etxykdj5cqrpky=-="
Date: Thu, 27 Jul 2017 14:21:21 +0000


--=-=01-uhb5j5etxykdj5cqrpky=-=
Content-Type: application/pgp-encrypted

Version: 1

--=-=01-uhb5j5etxykdj5cqrpky=-=
Content-Type: application/octet-stream

-----BEGIN PGP MESSAGE-----
lalala
-----END PGP MESSAGE-----

--=-=01-uhb5j5etxykdj5cqrpky=-=--`
      );
      listener.done(0);
      let p = new Promise((resolve, reject) => {
        resolve(true);
      });

      return {
        'promise': p
      };
    }, function() {
      TestHelper.resetting(EnigmailSend, "simpleSendMessage", function(op1, op2, op3, op4, op5) {
        Assert.equal(op1.identity.email, "test2@example.com");
        Assert.equal(op1.to, "key-submit@example.com");
        Assert.equal(op1.subject, "Key publishing request");
        return true;
      }, function() {
        let win = JSUnit.createStubWindow();
        let handle = EnigmailWks.submitKey({
          'email': 'test2@example.com'
        }, {
          'fpr': '123'
        }, win, function(ret) {
          Assert.equal(true, ret);
        });

        if (handle) {
          EnigmailExecution.syncProc(handle.promise);
        }
      });
    });
  });
});

test(function wksConfirmKey() {
  TestHelper.resetting(EnigmailWks, "wksClientPath", "WKS_CLIENT_DUMMY", function() {
    TestHelper.resetting(EnigmailExecution, "execStart", function(path, args, wat, win, listener, ops) {
      Assert.equal(path, "WKS_CLIENT_DUMMY");
      listener.done(0);
      let p = new Promise((resolve, reject) => {
        resolve(true);
      });

      return {
        'promise': p
      };
    }, function() {
      TestHelper.resetting(EnigmailSend, "simpleSendMessage", function(op1, op2, op3, op4, op5) {
        Assert.equal(op1.identity.email, "test2@example.com");
        Assert.equal(op1.to, "key-submit@example.com");
        Assert.equal(op1.subject, "Key publishing confirmation");
        return true;
      }, function() {
        let win = JSUnit.createStubWindow();
        let mail =
          `
From: test1@example.com
To: key-submit@example.com
Subject: Key publishing confirmation
Wks-Draft-Version: 3
MIME-Version: 1.0
Content-Type: multipart/encrypted; protocol="application/pgp-encrypted";
  boundary="=-=01-uhb5j5etxykdj5cqrpky=-="
Date: Thu, 27 Jul 2017 14:21:21 +0000


--=-=01-uhb5j5etxykdj5cqrpky=-=
Content-Type: application/pgp-encrypted

Version: 1

--=-=01-uhb5j5etxykdj5cqrpky=-=
Content-Type: application/octet-stream

-----BEGIN PGP MESSAGE-----
lalala
-----END PGP MESSAGE-----

--=-=01-uhb5j5etxykdj5cqrpky=-=--`;
        let handle = EnigmailWks.confirmKey({
          'email': 'test2@example.com'
        }, mail, win, function(ret) {
          Assert.equal(true, ret);
        });

        if (handle) {
          EnigmailExecution.syncProc(handle.promise);
        }
      });
    });
  });
});

test(function positiveWksSupportCheck() {
  TestHelper.resetting(EnigmailWks, "wksClientPath", "WKS_CLIENT_DUMMY", function() {
    TestHelper.resetting(EnigmailExecution, "execStart", function(path, args, wat, win, listener, ops) {
      Assert.equal(path, "WKS_CLIENT_DUMMY");
      Assert.equal(args[0], "--supported");
      Assert.equal(args[1], "test2@example.com");
      listener.done(0);
      let p = new Promise((resolve, reject) => {
        resolve(true);
      });

      return {
        'promise': p
      };
    }, function() {
      let win = JSUnit.createStubWindow();
      let handle = EnigmailWks.isWksSupportedAsync('test2@example.com', win, function(ret) {
        Assert.equal(true, ret);
      });

      if (handle) {
        EnigmailExecution.syncProc(handle.promise);
      }
    });
  });
});

test(function negativeWksSupportCheck() {
  TestHelper.resetting(EnigmailWks, "wksClientPath", "WKS_CLIENT_DUMMY", function() {
    TestHelper.resetting(EnigmailExecution, "execStart", function(path, args, wat, win, listener, ops) {
      Assert.equal(path, "WKS_CLIENT_DUMMY");
      Assert.equal(args[0], "--supported");
      Assert.equal(args[1], "test2@example.com");
      listener.done(1);
      let p = new Promise((resolve, reject) => {
        resolve(true);
      });

      return {
        'promise': p
      };
    }, function() {
      let win = JSUnit.createStubWindow();
      let handle = EnigmailWks.isWksSupportedAsync('test2@example.com', win, function(ret) {
        Assert.equal(false, ret);
      });

      if (handle) {
        EnigmailExecution.syncProc(handle.promise);
      }
    });
  });
});
