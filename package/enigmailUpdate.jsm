/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */


"use strict";

var EXPORTED_SYMBOLS = ["EnigmailUpdate"];

const EnigmailPrefs = ChromeUtils.import("chrome://enigmail/content/modules/prefs.jsm").EnigmailPrefs;
const EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
const EnigmailVersioning = ChromeUtils.import("chrome://enigmail/content/modules/versioning.jsm").EnigmailVersioning;
const EnigmailTimer = ChromeUtils.import("chrome://enigmail/content/modules/timer.jsm").EnigmailTimer;
const EnigmailLocale = ChromeUtils.import("chrome://enigmail/content/modules/locale.jsm").EnigmailLocale;
const EnigmailCompat = ChromeUtils.import("chrome://enigmail/content/modules/compat.jsm").EnigmailCompat;
const EnigmailData = ChromeUtils.import("chrome://enigmail/content/modules/data.jsm").EnigmailData;
const EnigmailApp = ChromeUtils.import("chrome://enigmail/content/modules/app.jsm").EnigmailApp;

Components.utils.importGlobalProperties(["fetch"]);

const UPDATE_QUERY_URL = "https://www.enigmail.net/service/getEnigmailVersion.svc";

var EnigmailUpdate = {
  isUpdateAvailable: async function() {
    EnigmailLog.DEBUG(`enigmailUpdate.jsm: isUpdateAvailable()\n`);

    if (EnigmailCompat.isPostbox()) return false;

    let now = Math.floor(Date.now() / 1000);
    let lastCheck = Number(EnigmailPrefs.getPref("lastUpdateCheck"));
    if (now > lastCheck) {
      EnigmailPrefs.setPref("lastUpdateCheck", String(now));
    }

    const APP_ID = EnigmailApp.getName().toLowerCase().replace(/ /g, "");
    let newVersions = await this.getUpdateInfo(APP_ID);
    if (!newVersions) return false;

    let newVer;
    for (let item of newVersions) {
      if (item.targetApp === APP_ID) {
        newVer = item;
        break;
      }
    }

    if (newVer && EnigmailVersioning.greaterThan(newVer.enigmailVersion, EnigmailApp.getVersion())) {
      // new version is available
      return true;
    }

    return false;
  },

  isUpdateCheckNeeded: function() {
    if (EnigmailCompat.isPostbox()) return false;

    // check once every 24 hours
    let now = Math.floor(Date.now() / 1000);
    return (now > Number(EnigmailPrefs.getPref("lastUpdateCheck")) + 86400);
  },

  isAutoCheckEnabled: function() {
    let farAway = Math.floor(Date.parse('31 Dec 2299') / 1000);
    return Number(EnigmailPrefs.getPref("lastUpdateCheck")) < farAway;
  },

  runUpdateCheck: function() {
    EnigmailLog.DEBUG(`enigmailUpdate.jsm: runUpdateCheck()\n`);

    if (EnigmailCompat.isPostbox()) return;
    let self = this,
      timeoutSec = 0,
      retry = true;

    if (this.isUpdateCheckNeeded()) {
      timeoutSec = 3 + Math.floor(Math.random() * 180);

      EnigmailLog.DEBUG(`enigmailUpdate.jsm: runUpdateCheck: check needed; waiting for ${timeoutSec} seconds\n`);

      EnigmailTimer.setTimeout(async function f() {
        if (await self.isUpdateAvailable()) {
          EnigmailLog.DEBUG(`enigmailUpdate.jsm: runUpdateCheck: update available\n`);
          retry = false; // stop checking if we display the update info dialog
          self.displayUpdateDialog();
        }
      }, timeoutSec * 1000);
    }

    let tryAgain = 86600 - Math.floor(Math.random() * 1800);
    EnigmailLog.DEBUG(`enigmailUpdate.jsm: runUpdateCheck: will try again in ${tryAgain} seconds\n`);

    EnigmailTimer.setTimeout(function f() {
      if (retry)
        self.runUpdateCheck();
    }, tryAgain * 1000);

    return;


  },

  displayUpdateDialog: function() {
    let EnigmailDialog = ChromeUtils.import("chrome://enigmail/content/modules/dialog.jsm").EnigmailDialog;
    EnigmailDialog.info(null, EnigmailLocale.getString("importantUpdate.label"));
  },

  getUpdateInfo: async function(appId) {
    let url = UPDATE_QUERY_URL;

    // if ENIGMAIL_UPDATE_DOWNLOAD_URL env variable is set, use that instead of the
    // official URL (for testing)
    let env = Cc["@mozilla.org/process/environment;1"].getService(Ci.nsIEnvironment);
    if (env.get("ENIGMAIL_UPDATE_DOWNLOAD_URL")) {
      url = env.get("ENIGMAIL_UPDATE_DOWNLOAD_URL");
    }

    url += `?appId=${appId}&appVersion=${EnigmailApp.getApplicationVersion()}&itemVersion=${EnigmailApp.getVersion()}`;

    let myRequest = new Request(url, {
      method: 'GET',
      mode: 'cors',
      redirect: 'follow',
      cache: 'default'
    });

    let response;
    try {
      EnigmailLog.DEBUG(`enigmailUpdate.jsm: getUpdateInfo(): requesting ${url}\n`);
      response = await fetch(myRequest);
      if (!response.ok) {
        return null;
      }

      if (response.headers.has("content-type") && response.headers.get("content-type").search(/^text\/html/i) === 0) {
        // if we get HTML output, we return nothing (for example redirects to error catching pages)
        return null;
      }
      let jsonData = EnigmailData.arrayBufferToString(Cu.cloneInto(await response.arrayBuffer(), this));
      EnigmailLog.DEBUG(`enigmailUpdate.jsm: getUpdateInfo: got JSON data ${jsonData}\n`);

      return JSON.parse(jsonData);
    }
    catch (ex) {
      EnigmailLog.DEBUG(`enigmailUpdate.jsm: getUpdateInfo: error ${ex.toString()}\n`);
      return null;
    }
  }
};
