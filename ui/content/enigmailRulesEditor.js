/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// Uses: chrome://enigmail/content/ui/enigmailCommon.js

"use strict";

var Cu = Components.utils;
var Cc = Components.classes;
var Ci = Components.interfaces;

var EnigmailRules = ChromeUtils.import("chrome://enigmail/content/modules/rules.jsm").EnigmailRules;
var EnigmailLog = ChromeUtils.import("chrome://enigmail/content/modules/log.jsm").EnigmailLog;
var EnigmailCore = ChromeUtils.import("chrome://enigmail/content/modules/core.jsm").EnigmailCore;
var EnigmailSearchCallback = ChromeUtils.import("chrome://enigmail/content/modules/searchCallback.jsm").EnigmailSearchCallback;
var EnigmailDialog = ChromeUtils.import("chrome://enigmail/content/modules/dialog.jsm").EnigmailDialog;
var EnigmailLocale = ChromeUtils.import("chrome://enigmail/content/modules/locale.jsm").EnigmailLocale;
var EnigmailWindows = ChromeUtils.import("chrome://enigmail/content/modules/windows.jsm").EnigmailWindows;
var EnigmailFuncs = ChromeUtils.import("chrome://enigmail/content/modules/funcs.jsm").EnigmailFuncs;

const INPUT = 0;
const RESULT = 1;

var gSearchInput = null;
var gNumRows = null;
var gTimeoutId = {};
var gDisplayAcRules = false;

function onLoadDialog() {
  var enigmailSvc = EnigmailCore.getService(window);
  if (!enigmailSvc)
    return;

  document.getElementById("pgpMime").setAttribute("collapsed", "true");

  let acRules = document.getElementById("displayAutocryptRules");
  if (acRules) {
    EnigmailFuncs.collapseAdvanced(acRules.parentNode, 'collapsed');
  }

  var rulesListObj = {};
  if (EnigmailRules.getRulesData(rulesListObj)) {
    var treeChildren = document.getElementById("rulesTreeChildren");
    var rulesList = rulesListObj.value;
    if (rulesList.firstChild.nodeName == "parsererror") {
      EnigmailDialog.alert(window, "Invalid pgprules.xml file:\n" + rulesList.firstChild.textContent);
      return;
    }
    EnigmailLog.DEBUG("enigmailRulesEditor.js: dlgOnLoad: keys loaded\n");
    gNumRows = 0;

    let autocryptRules = [];
    var node = rulesList.firstChild.firstChild;
    while (node) {
      if (node.tagName == "pgpRule") {
        var userObj = {
          email: node.getAttribute("email"),
          keyId: node.getAttribute("keyId"),
          sign: node.getAttribute("sign"),
          encrypt: node.getAttribute("encrypt"),
          pgpMime: node.getAttribute("pgpMime"),
          negate: "0"
        };
        if (node.getAttribute("negateRule")) {
          userObj.negate = node.getAttribute("negateRule");
        }

        if (userObj.email.indexOf("{autocrypt://") === 0) {
          let treeItem = document.createXULElement("treeitem");
          createRow(treeItem, userObj);
          autocryptRules.push(treeItem);
        }
        else {
          let treeItem = document.createXULElement("treeitem");
          createRow(treeItem, userObj);
          treeChildren.appendChild(treeItem);
        }
      }
      node = node.nextSibling;
    }

    for (let row of autocryptRules) {
      treeChildren.appendChild(row);
    }
  }
  gSearchInput = document.getElementById("filterEmail");
  EnigmailSearchCallback.setup(gSearchInput, gTimeoutId, applyFilter, 200);
  applyFilter();
  onSelectCallback();
}

function onAcceptDialog() {
  EnigmailLog.DEBUG("enigmailRulesEditor.js: dlgOnAccept:\n");
  EnigmailRules.clearRules();

  var node = getFirstNode();
  while (node) {
    EnigmailRules.addRule(true,
      node.getAttribute("email"),
      node.getAttribute("keyId"),
      node.getAttribute("sign"),
      node.getAttribute("encrypt"),
      node.getAttribute("pgpMime"),
      node.getAttribute("negateRule")
    );
    node = node.nextSibling;
  }
  EnigmailRules.saveRulesFile();

  return true;
}

function createCol(value, label, treeItem, translate) {
  var column = document.createXULElement("treecell");
  column.setAttribute("id", value);
  treeItem.setAttribute(value, label);
  switch (value) {
    case "sign":
    case "encrypt":
    case "pgpMime":
      switch (Number(label)) {
        case 0:
          label = EnigmailLocale.getString("never");
          break;
        case 1:
          label = EnigmailLocale.getString("possible");
          break;
        case 2:
          label = EnigmailLocale.getString("always");
          break;
      }
      break;
    case "keyId":
      if (label == ".") {
        label = EnigmailLocale.getString("nextRcpt");
      }
      break;
    case "negateRule":
      if (Number(label) == 1) {
        label = EnigmailLocale.getString("negateRule");
      }
      else {
        label = "";
      }
  }
  column.setAttribute("label", label);
  return column;
}

function createRow(treeItem, userObj) {
  var negate = createCol("negateRule", userObj.negate, treeItem);
  var email = createCol("email", userObj.email, treeItem);
  var keyId = createCol("keyId", userObj.keyId, treeItem);
  var sign = createCol("sign", userObj.sign, treeItem);
  var encrypt = createCol("encrypt", userObj.encrypt, treeItem);
  var pgpMime = createCol("pgpMime", userObj.pgpMime, treeItem);
  var treeRow = document.createXULElement("treerow");
  treeRow.appendChild(negate);
  treeRow.appendChild(email);
  treeRow.appendChild(keyId);
  treeRow.appendChild(encrypt);
  treeRow.appendChild(sign);
  treeRow.appendChild(pgpMime);
  treeRow.setAttribute("rowId", ++gNumRows);


  if (treeItem.firstChild) {
    treeItem.replaceChild(treeRow, treeItem.firstChild);
  }
  else {
    treeItem.appendChild(treeRow);
  }
}

function getFirstNode() {
  return document.getElementById("rulesTreeChildren").firstChild;
}


function getSelectedNodes() {
  let rulesTree = document.getElementById("rulesTree");
  let selList = [];
  let rangeCount = rulesTree.view.selection.getRangeCount();

  for (let i = 0; i < rangeCount; i++) {
    let start = {};
    let end = {};
    rulesTree.view.selection.getRangeAt(i, start, end);
    for (let c = start.value; c <= end.value; c++) {
      selList.push(rulesTree.view.getItemAtIndex(c));
    }
  }
  return selList;
}


function onSelectCallback() {
  let nodeList = getSelectedNodes();

  const singleSelectionElements = ["modifyRule", "moveUp", "moveDown"];

  if (nodeList.length === 1 && nodeList[0].getAttribute("email").indexOf("{autocrypt://") < 0) {
    for (let e of singleSelectionElements) {
      document.getElementById(e).removeAttribute("disabled");
    }
  }
  else {
    for (let e of singleSelectionElements) {
      document.getElementById(e).setAttribute("disabled", "true");
    }
  }


  if (nodeList.length > 0) {
    document.getElementById("deleteRule").removeAttribute("disabled");
  }
  else {
    document.getElementById("deleteRule").setAttribute("disabled", "true");
  }
}

function editRule() {
  let nodeList = getSelectedNodes();
  if (nodeList.length === 0) return;

  var node = nodeList[0];
  if (node) {
    var inputObj = {};
    var resultObj = {};
    inputObj.command = "edit";
    inputObj.options = "nosave";
    inputObj.toAddress = node.getAttribute("email");
    inputObj.keyId = node.getAttribute("keyId").split(/[ ,]+/);
    inputObj.sign = Number(node.getAttribute("sign"));
    inputObj.encrypt = Number(node.getAttribute("encrypt"));
    inputObj.pgpmime = Number(node.getAttribute("pgpMime"));
    inputObj.negate = Number(node.getAttribute("negateRule"));

    window.openDialog("chrome://enigmail/content/ui/enigmailSingleRcptSettings.xul", "", "dialog,modal,centerscreen,resizable", inputObj, resultObj);
    if (resultObj.cancelled === false) {
      createRow(node, resultObj);
    }
  }
}

function addRule() {
  var inputObj = {};
  var resultObj = {};
  inputObj.options = "nosave";
  inputObj.toAddress = "{}";
  inputObj.command = "add";

  window.openDialog("chrome://enigmail/content/ui/enigmailSingleRcptSettings.xul", "", "dialog,modal,centerscreen,resizable", inputObj, resultObj);
  if (resultObj.cancelled === false) {
    var treeItem = document.createXULElement("treeitem");
    createRow(treeItem, resultObj);
    var treeChildren = document.getElementById("rulesTreeChildren");
    if (treeChildren.firstChild) {
      treeChildren.insertBefore(treeItem, treeChildren.firstChild);
    }
    else {
      treeChildren.appendChild(treeItem);
    }
  }
}

function deleteRule() {
  let nodeList = getSelectedNodes();

  if (nodeList.length > 0) {
    if (EnigmailDialog.confirmDlg(window, EnigmailLocale.getString(nodeList.length === 1 ? "deleteRule.single" : "deleteRule.multiple"), EnigmailLocale.getString("dlg.button.delete"))) {
      var treeChildren = document.getElementById("rulesTreeChildren");
      for (let node of nodeList) {
        treeChildren.removeChild(node);
      }
    }
  }
}

function moveRuleUp() {
  let nodeList = getSelectedNodes();
  if (nodeList.length !== 1) return;

  var node = nodeList[0];
  if (!node) return;
  var prev = node.previousSibling;
  if (prev) {
    var rulesTree = document.getElementById("rulesTree");
    var currentIndex = rulesTree.currentIndex;
    var treeChildren = document.getElementById("rulesTreeChildren");
    var newNode = node.cloneNode(true);
    treeChildren.removeChild(node);
    treeChildren.insertBefore(newNode, prev);
    rulesTree.currentIndex = -1;
    rulesTree.currentIndex = currentIndex - 1;
  }
}

function moveRuleDown() {
  let nodeList = getSelectedNodes();
  if (nodeList.length !== 1) return;

  var node = nodeList[0];
  var nextNode = node.nextSibling;
  if (nextNode) {
    var rulesTree = document.getElementById("rulesTree");
    var currentIndex = rulesTree.currentIndex;
    var treeChildren = document.getElementById("rulesTreeChildren");
    var newNode = nextNode.cloneNode(true);
    treeChildren.removeChild(nextNode);
    treeChildren.insertBefore(newNode, node);
    rulesTree.currentIndex = currentIndex + 1;
  }
}

function applySearchFilter() {
  var searchTxt = document.getElementById("filterEmail").value;
  if (!searchTxt) return;
  searchTxt = searchTxt.toLowerCase();
  var node = getFirstNode();
  while (node) {
    if ((!gDisplayAcRules) && (node.getAttribute("email").indexOf("{autocrypt://") === 0)) {
      node.hidden = true;
    }
    else if (node.getAttribute("email").toLowerCase().indexOf(searchTxt) < 0) {
      node.hidden = true;
    }
    else {
      node.hidden = false;
    }
    node = node.nextSibling;
  }
}

function resetFilter() {
  document.getElementById("filterEmail").value = "";
  var node = getFirstNode();
  while (node) {
    if ((!gDisplayAcRules) && (node.getAttribute("email").indexOf("{autocrypt://") === 0)) {
      node.hidden = true;
    }
    else
      node.hidden = false;
    node = node.nextSibling;
  }
}

function applyFilter() {
  if (gSearchInput.value === "") {
    resetFilter();
    return;
  }

  applySearchFilter();
}


function toggleAutocryptRules() {
  gDisplayAcRules = document.getElementById("displayAutocryptRules").checked ? true : false;
  applyFilter();
}

document.addEventListener("dialogaccept", function(event) {
  if (!onAcceptDialog())
    event.preventDefault(); // Prevent the dialog closing.
});
