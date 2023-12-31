/*global do_load_module: false, do_get_file: false, do_get_cwd: false, testing: false, test: false, Assert: false, resetting: false, EnigmailApp: false */
/*global EnigmailFuncs: false, rulesListHolder: false, EC: false, setupTestAccounts: false */

/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

"use strict";

do_load_module("file://" + do_get_cwd().path + "/testHelper.js");

testing("funcs.jsm");

var EnigmailFuncsTests = {
  testStripEmail(str, res) {
    let addr;
    addr = EnigmailFuncs.stripEmail(str);
    Assert.equal(addr, res);
  }
};

setupTestAccounts("tester@enigmail.org");

test(function stripEmail() {
  EnigmailFuncsTests.testStripEmail("some stuff <a@b.de>",
    "a@b.de");

  EnigmailFuncsTests.testStripEmail("\"some stuff\" a@b.de",
    "a@b.de");

  EnigmailFuncsTests.testStripEmail("\"some, stuff\" a@b.de",
    "a@b.de");

  EnigmailFuncsTests.testStripEmail("some stuff <a@b.de>, xyz<xy@a.xx>",
    "a@b.de,xy@a.xx");

  EnigmailFuncsTests.testStripEmail(" a@b.de , <aa@bb.de>",
    "a@b.de,aa@bb.de");

  EnigmailFuncsTests.testStripEmail("    ,,,,;;;; , ; , ;",
    "");

  EnigmailFuncsTests.testStripEmail(";",
    "");


  EnigmailFuncsTests.testStripEmail("    ,,oneRule,;;; , ;",
    "oneRule");

  EnigmailFuncsTests.testStripEmail("    ,,,nokey,;;;; , nokey2 ; , ;",
    "nokey,nokey2");

  EnigmailFuncsTests.testStripEmail(",,,newsgroupa ",
    "newsgroupa");

  // test invalid email addresses:
  EnigmailFuncs.stripEmail(" a@b.de , <aa@bb.de> <aa@bb.dd>", "");
  EnigmailFuncs.stripEmail("\"some stuff a@b.de", "");
  EnigmailFuncs.stripEmail("<evil@example.com,><good@example.com>", "");
});

test(function compareMimePartLevel() {
  Assert.throws(
    function() {
      EnigmailFuncs.compareMimePartLevel("1.2.e", "1.2");
    }
  );

  let e = EnigmailFuncs.compareMimePartLevel("1.1", "1.1.2");
  Assert.equal(e, -2);

  e = EnigmailFuncs.compareMimePartLevel("1.1", "1.2.2");
  Assert.equal(e, -1);

  e = EnigmailFuncs.compareMimePartLevel("1", "2");
  Assert.equal(e, -1);

  e = EnigmailFuncs.compareMimePartLevel("1.2", "1.1.2");
  Assert.equal(e, 1);

  e = EnigmailFuncs.compareMimePartLevel("1.2.2", "1.2");
  Assert.equal(e, 2);

  e = EnigmailFuncs.compareMimePartLevel("1.2.2", "1.2.2");
  Assert.equal(e, 0);

});

test(function testGetOwnEmailAddresses() {
  let r = EnigmailFuncs.getOwnEmailAddresses();

  const expectedResult = [
    "tester@enigmail.org",
    "user2@enigmail-test.net",
    "user3@enigmail-test.net",
    "user4@enigmail-test.net"
  ];

  for (let i of expectedResult) {
    Assert.ok(i in r, `${i} is not in own emails`);
  }
});

test(function testGetNumberOfRecipients() {

  let compFields = {
    to: "tester@enigmail.org, another.tester@enigmail.org",
    cc: "user4@enigmail-test.net, Peter <someone@somewhere.invalid>"
  };

  let n = EnigmailFuncs.getNumberOfRecipients(compFields);
  Assert.equal(n, 2, "number of recipients");

});
