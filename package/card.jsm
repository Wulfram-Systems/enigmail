/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */


"use strict";

var EXPORTED_SYMBOLS = ["EnigmailCard"];

const EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
const EnigmailExecution = ChromeUtils.import("chrome://enigmail/content/modules/execution.jsm").EnigmailExecution;
const EnigmailCryptoAPI = ChromeUtils.import("chrome://enigmail/content/modules/cryptoAPI.jsm").EnigmailCryptoAPI;

var EnigmailCard = {
  getCardStatus: function(exitCodeObj, errorMsgObj) {
    EnigmailLog.DEBUG("card.jsm: EnigmailCard.getCardStatus\n");
    const cApi = EnigmailCryptoAPI();

    if (!cApi.supportsFeature("smartcard")) {
      exitCodeObj.value = -1;
      errorMsgObj.value = "";
      return "";
    }

    const args = ["--charset", "utf-8", "--display-charset", "utf-8", "--no-auto-check-trustdb", "--no-verbose", "--status-fd", "2", "--fixed-list-mode", "--with-colons", "--card-status"];
    const statusMsgObj = {};
    const statusFlagsObj = {};

    const outputTxt = EnigmailExecution.execCmd(cApi._gpgPath, args, "", exitCodeObj, statusFlagsObj, statusMsgObj, errorMsgObj);

    if ((exitCodeObj.value === 0) && !outputTxt) {
      exitCodeObj.value = -1;
      return "";
    }

    return outputTxt;
  }
};
