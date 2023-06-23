/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

"use strict";

var EXPORTED_SYMBOLS = ["EnigmailHttpProxy"];

const EnigmailPrefs = ChromeUtils.import("chrome://enigmail/content/modules/prefs.jsm").EnigmailPrefs;

var EnigmailHttpProxy = {
  /**
   *  get Proxy for a given hostname as configured in Mozilla
   *
   *  @hostname: String - the host to check if there is a proxy.
   *
   *  @return: String - proxy host URL to provide to GnuPG
   *                    null if no proxy required
   */
  getHttpProxy: function(hostName) {
    let proxyHost = null;
    if (((typeof hostName) !== 'undefined') && EnigmailPrefs.getPref("respectHttpProxy")) {
      // determine proxy host
      let prefsSvc = Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefService);
      let prefRoot = prefsSvc.getBranch(null);
      let useProxy = prefRoot.getIntPref("network.proxy.type");
      if (useProxy === 1) {
        let proxyHostName = prefRoot.getCharPref("network.proxy.http");
        let proxyHostPort = prefRoot.getIntPref("network.proxy.http_port");
        let noProxy = prefRoot.getCharPref("network.proxy.no_proxies_on").split(/[ ,]/);

        for (let host of noProxy) {
          // Replace regex chars, except star.
          host = host.replace(/[.+\-?^${}()|[\]\\]/g, "\\$&");
          // Make star match anything.
          host = host.replace(/\*/g, ".*");
          let proxySearch = new RegExp(host + "$", "i");
          if (host && proxySearch.test(hostName)) {
            proxyHostName = null;
            break;
          }
        }

        if (proxyHostName && proxyHostPort) {
          proxyHost = "http://" + proxyHostName + ":" + proxyHostPort;
        }
      }
    }

    return proxyHost;
  }
};
