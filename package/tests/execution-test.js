/*global do_load_module: false, do_get_file: false, do_get_cwd: false, testing: false, test: false, Assert: false, resetting: false, JSUnit: false, asyncTest: false, component: false */
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

"use strict";

do_load_module("file://" + do_get_cwd().path + "/testHelper.js"); /*global withEnigmail: false, withTestGpgHome: false */

testing("execution.jsm"); /*global EnigmailExecution: false */

component("enigmail/cryptoAPI/gpgme.js"); /*global getGpgMEApi: false */

test(withTestGpgHome(withEnigmail(asyncTest(async (esvc, window) => {
  // Test key importing and key listing
  const gpgmeApi = getGpgMEApi();
  gpgmeApi.initialize(null, esvc, null);

  const command = gpgmeApi._gpgmePath;
  const args = ["-s"];

  try {
    const result = await EnigmailExecution.execAsync(command, args, '{"op":"version"}');
    Assert.equal(result.exitCode, 0);
      const r = JSON.parse(result.stdoutData);
    Assert.ok(r.gpgme.length > 0);
  }
  catch (ex) {
    Assert.ok(false, "JSON.parse should not fail");
  }
}))));
