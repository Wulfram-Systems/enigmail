/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */


"use strict";

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;

const XPCOMUtils = Cu.import("resource://gre/modules/XPCOMUtils.jsm").XPCOMUtils;
const Services = Cu.import("resource://gre/modules/Services.jsm").Services;
const EnigmailApp = Cu.import("chrome://enigmail/content/modules/app.jsm").EnigmailApp;
const EnigmailCore = Cu.import("chrome://enigmail/content/modules/core.jsm").EnigmailCore;
const EnigmailAmPrefsService = Cu.import("chrome://enigmail/content/modules/amPrefsService.jsm").EnigmailAmPrefsService;
const EnigmailPgpmimeHander = Cu.import("chrome://enigmail/content/modules/pgpmimeHandler.jsm").EnigmailPgpmimeHander;
const AddonManager = Components.utils.import("resource://gre/modules/AddonManager.jsm").AddonManager;

const NS_ENIGCLINE_SERVICE_CID = Components.ID("{f4d4138e-dd4d-4cb0-b408-a41429d38e34}");
const NS_CLINE_SERVICE_CONTRACTID = "@mozilla.org/enigmail/cline-handler;1";
const NS_XPCOM_SHUTDOWN_OBSERVER_ID = "xpcom-shutdown";

const nsICommandLineHandler = Ci.nsICommandLineHandler;
const nsIFactory = Ci.nsIFactory;
const nsISupports = Ci.nsISupports;

const APP_STARTUP = 1;
const APP_SHUTDOWN = 2;

function EnigmailStartup() {}

EnigmailStartup.prototype = {
  classDescription: "Enigmail Core Service",
  classID: NS_ENIGCLINE_SERVICE_CID,
  contractID: NS_CLINE_SERVICE_CONTRACTID,
  _xpcom_categories: [{
    category: "command-line-handler",
    entry: "m-cline-enigmail",
    service: false
  }],
  QueryInterface: XPCOMUtils.generateQI([nsICommandLineHandler, nsIFactory, nsISupports]),

  // nsICommandLineHandler
  handle: function(cmdLine) {
    // does nothing
  },

  helpInfo: "",

  lockFactory: function(lock) {}
};


function performShutdown(aSubject, aTopic, aData) {
  const EnigmailLog = Cu.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;

  Services.obs.removeObserver(performShutdown, aTopic);

  EnigmailLog.DEBUG("enigmail-startup.js: onShutdown()\n");
  EnigmailCore.shutdown(APP_SHUTDOWN);
}


function startup() {
  // Services.console.logStringMessage("Enigmail startup ...");

  AddonManager.getAddonByID("{847b3a00-7ab1-11d4-8f02-006008948af5}", addonData => {
    const appData = {
      version: addonData.version
    };

    EnigmailApp.initAddon(appData);
    EnigmailAmPrefsService.startup(APP_STARTUP);
    EnigmailCore.startup(APP_STARTUP);
    EnigmailPgpmimeHander.startup(APP_STARTUP);

    // register for shutdown-event
    Services.obs.addObserver(performShutdown, "profile-before-change", false);

    Services.console.logStringMessage("Enigmail startup completed");

    // Try to start Unit-Test framework
    let JSUnitService;
    try {
      JSUnitService = Cu.import("chrome://enigmail/content/jsunit/jsunit-service.js").JSUnitService;
    }
    catch (x) {
      return;
    }

    try {
      if (JSUnitService) {
        JSUnitService.startup(APP_STARTUP).catch(ex => {
          Services.console.logStringMessage(ex);
        });
      }
    }
    catch (ex) {
      Services.console.logStringMessage(ex);
    }
  });
}


startup();
const NSGetFactory = XPCOMUtils.generateNSGetFactory([EnigmailStartup]);
