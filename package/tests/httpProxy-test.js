/*global do_load_module: false, do_get_file: false, do_get_cwd: false, testing: false, test: false, Assert: false, resetting: false */
/*global do_test_pending: false, do_test_finished: false */

/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

"use strict";

do_load_module("file://" + do_get_cwd().path + "/testHelper.js");

testing("httpProxy.jsm"); /*global EnigmailHttpProxy: false */


function resetProxy() {
  const prefRoot = Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).getBranch(null);

  prefRoot.setIntPref("network.proxy.type", 0);
  prefRoot.setCharPref("network.proxy.http", "");
  prefRoot.setIntPref("network.proxy.http_port", null);
  prefRoot.setCharPref("network.proxy.no_proxies_on", "");
}

test(function proxyTest() {
  const prefRoot = Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService).getBranch(null);

  resetProxy();
  let px = EnigmailHttpProxy.getHttpProxy("somewhere");
  Assert.equal(px, null);

  prefRoot.setIntPref("network.proxy.type", 1);
  prefRoot.setCharPref("network.proxy.http", "enigmail-proxy.host");
  prefRoot.setIntPref("network.proxy.http_port", 1234);
  prefRoot.setCharPref("network.proxy.no_proxies_on", "noproxy.host");

  px = EnigmailHttpProxy.getHttpProxy("somewhere");
  Assert.equal(px, "http://enigmail-proxy.host:1234");

  px = EnigmailHttpProxy.getHttpProxy("https://noproxy.host");
  Assert.equal(px, null);

  px = EnigmailHttpProxy.getHttpProxy("sub.noproxy.host");
  Assert.equal(px, null);

  resetProxy();
});
