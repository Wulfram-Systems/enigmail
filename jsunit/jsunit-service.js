/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

"use strict";

/* global dump: false */

var EXPORTED_SYMBOLS = ["JSUnitService"];

const JSUnit = ChromeUtils.import("chrome://enigmail/content/jsunit/jsunit-main.jsm").JSUnit;
const Services = ChromeUtils.import("resource://gre/modules/Services.jsm").Services;
const OS = ChromeUtils.import("resource://gre/modules/osfile.jsm").OS;
const {
  setTimeout,
  clearTimeout
} = ChromeUtils.import("resource://gre/modules/Timer.jsm");


function DEBUG_LOG(str) {
  dump("jsunit-service.js: " + str + "\n");
}

var gStartTime;


function startCmdLineTests(fileName, logFileName, doneFile) {
  var appStartup = Cc["@mozilla.org/toolkit/app-startup;1"].getService(Ci.nsIAppStartup);
  gStartTime = Date.now();

  JSUnit.init(false, logFileName);
  JSUnit.printMsg("Starting JS unit tests " + fileName + "\n");
  Services.console.logStringMessage("Starting JS unit tests " + fileName);
  hideMainWindow();

  try {
    try {
      // ensure cache is deleted upon next application start
      Cc["@mozilla.org/xre/app-info;1"].getService(Ci.nsIXULRuntime).invalidateCachesOnRestart();
      JSUnit.executeScript(fileName, false, true);
    }
    catch (ex) {
      JSUnit.logTestResult("Exception occurred:\n" + ex.toString(), null, "");
      dump("** Tests aborted **\n");
    }
    JSUnit.printStats();
    Services.console.logStringMessage("JSUnit Test completed");

    if (doneFile) {
      let stream = JSUnit.createFileStream(doneFile);
      const doneStr = "DONE\n";
      stream.write(doneStr, doneStr.length);
      stream.close();
    }
  }
  catch (exc) {
    Services.console.logStringMessage(exc.toString() + "\n" + exc.stack);
    dump("** Error occurred **\n" + exc.toString());
  }

  appStartup.quit(Ci.nsIAppStartup.eForceQuit);
}


function arrayBufferToString(buffer) {
  const MAXLEN = 102400;

  let uArr = new Uint8Array(buffer);
  let ret = "";
  let len = buffer.byteLength;

  for (let j = 0; j < Math.floor(len / MAXLEN) + 1; j++) {
    ret += String.fromCharCode.apply(null, uArr.subarray(j * MAXLEN, ((j + 1) * MAXLEN)));
  }

  return ret;
}

/**
 * Hide the main messenger
 */
function hideMainWindow() {
  const MAIN_WINDOW = "chrome://messenger/content/messenger.xul";

  try {
    let windowManager = Cc["@mozilla.org/appshell/window-mediator;1"].getService(Ci.nsIWindowMediator);

    let winEnum = windowManager.getEnumerator(null);
    while (winEnum.hasMoreElements()) {var thisWin = winEnum.getNext();
      if (thisWin.location.href === MAIN_WINDOW) {
        thisWin.minimize();
      }
    }
  }
  catch(ex) {}
}

var JSUnitService = {
  getLaunchFile: async function() {
    let ds = Cc["@mozilla.org/file/directory_service;1"].getService(Ci.nsIProperties);
    let cfgFile = ds.get("ProfD", Ci.nsIFile);

    cfgFile.append("jsunit.json");
    try {
      if (!cfgFile.exists()) return null;

      let decoder = new TextDecoder();
      let arr = await OS.File.read(cfgFile.path);
      let fileContents = arrayBufferToString(arr); // Convert the array to a text
      let cfg = JSON.parse(fileContents);
      return cfg;
    }
    catch (x) {}
    return null;
  },

  startup: async function() {
    let launchCfg = await this.getLaunchFile();
    if (!launchCfg) return;

    //Services.console.logStringMessage("Starting unit tests");

    setTimeout(function _f() {
      DEBUG_LOG(`JSUnit starting tests from ${launchCfg.mainFile}\n`);
      startCmdLineTests(launchCfg.mainFile, launchCfg.logFile, launchCfg.doneFile);
    }, 3000);
  }
};
