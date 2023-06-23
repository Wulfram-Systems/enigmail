/*
 * This Source Code Form is licensed under the GNU LGPL 3.0 license.
 *
 */

"use strict";

const Services = ChromeUtils.import("resource://gre/modules/Services.jsm").Services;
const EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;

var EXPORTED_SYMBOLS = ["getOpenPGPLibrary"];

// Complete list of gobal prpoperties (as of TB 65), taken from
// [mozilla-source]/js/xpconnect/src/Sandbox.cpp

try {
  // Gecko 68
  Components.utils.importGlobalProperties(["Blob",
    "CSS",
    "CSSRule",
    "ChromeUtils",
    "DOMParser",
    "Directory",
    "Element",
    "Event",
    "File",
    "FileReader",
    "FormData",
    "InspectorUtils",
    "MessageChannel",
    "Node",
    "NodeFilter",
    "PromiseDebugging",
    "TextDecoder",
    "TextEncoder",
    "URL",
    "URLSearchParams",
    "XMLHttpRequest",
    "XMLSerializer",
    "atob",
    "btoa",
    "caches",
    "crypto",
    "fetch",
    "indexedDB"
  ]);
}
catch (x) {
  // Gecko 52
  Components.utils.importGlobalProperties(["Blob",
    "CSS",
    "Directory",
    "File",
    "TextDecoder",
    "TextEncoder",
    "URL",
    "XMLHttpRequest",
    "atob",
    "btoa",
    "crypto",
    "fetch",
    "indexedDB"
  ]);
}

const {
  TransformStream,
  ReadableStream,
  WritableStream
} = ChromeUtils.import("chrome://enigmail/content/modules/stdlib/web-streams.jsm");

var gLibrary = null;

function getOpenPGPLibrary() {
  if (gLibrary === null) {
    gLibrary = loadOpenPGPjsLib();
  }

  return gLibrary;
}

function loadOpenPGPjsLib() {
  /* Prerequisites required by openpgp-lib.js */

  let appShellSvc = Cc["@mozilla.org/appshell/appShellService;1"].getService(Ci.nsIAppShellService);
  let userAgent = appShellSvc.hiddenDOMWindow.navigator.userAgent;
  let nav = {
    userAgent: userAgent
  };

  let doc = {
    createElement: function() {
      return null;
    },
    head: {
      appendChild: function() {
        return null;
      }
    }
  };

  // The scope ("global object") for OpenPGP.js
  let g = {
    setTimeout: ChromeUtils.import("resource://gre/modules/Timer.jsm").setTimeout,
    window: {
      document: doc,
      crypto: crypto,
      navigator: nav
    },
    document: doc,
    navigator: nav,
    userAgent: userAgent,
    console: {
      assert: function() {},
      log: function(str) {
        Services.console.logStringMessage(str);
      },
      error: function(str) {
        Services.console.logStringMessage(str);
      },
      table: function() {},
      warn: function() {},
      trace: function(str) {
        Services.console.logStringMessage("Stack trace" + str ? str : "");
      }
    },

    // imports from global scope
    atob: atob,
    btoa: btoa,
    Blob: Blob,
    crypto: crypto,
    fetch: fetch,
    URL: URL,
    TransformStream: TransformStream,
    ReadableStream: ReadableStream,
    WritableStream: WritableStream,
    TextDecoder: TextDecoder,
    TextEncoder: TextEncoder,
    XMLHttpRequest: XMLHttpRequest,
    MessageChannel: appShellSvc.hiddenDOMWindow.MessageChannel
  };

  // no idea why, but openpgp.js won't load without this defined
  g.self = g.window;

  Services.scriptloader.loadSubScript("chrome://enigmail/content/modules/stdlib/openpgp-lib.js", g, "UTF-8");

  const openPGPLib = g.openpgp;
  const cfg = openPGPLib.config;
  cfg.show_comment = false;
  cfg.show_version = false;
  cfg.compression = openPGPLib.enums.compression.zlib;
  cfg.tolerant = true;

  return openPGPLib;
}
