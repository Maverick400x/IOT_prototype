// Blockchain based IoT Device Authentication
// CN Course Project
// Uses Web Crypto API for SHA-256 hashing and ECDSA signatures

// ---------------- Global variables ----------------
var nodes = [
  { name: "Node A", online: true, chain: [] },
  { name: "Node B", online: true, chain: [] },
  { name: "Node C", online: true, chain: [] }
];
var devices = {};      // stores device keys (this is on the device side)
var cache = {};        // gateway cache of verified devices
var logs = [];
var attackerKey = null;
var nextIp = 10;
var times = [];

// ---------------- Helper functions ----------------

// convert bytes to hex string
function toHex(buffer) {
  var arr = new Uint8Array(buffer);
  var s = "";
  for (var i = 0; i < arr.length; i++) {
    s += arr[i].toString(16).padStart(2, "0");
  }
  return s;
}

// convert hex string back to bytes
function fromHex(hex) {
  var arr = new Uint8Array(hex.length / 2);
  for (var i = 0; i < arr.length; i++) {
    arr[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return arr;
}

// SHA-256 hash of a string
async function sha256(text) {
  var data = new TextEncoder().encode(text);
  var hash = await crypto.subtle.digest("SHA-256", data);
  return toHex(hash);
}

function shortHash(h) {
  if (!h) return "";
  return h.substring(0, 12) + "...";
}

function getTime() {
  return new Date().toLocaleTimeString();
}

function wait(ms) {
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

// generate ECDSA key pair for a device
async function generateKeys() {
  var keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  var pub = await crypto.subtle.exportKey("raw", keyPair.publicKey);
  return { keyPair: keyPair, publicKey: toHex(pub) };
}

// ---------------- Blockchain functions ----------------

// hash of block = SHA256(index + timestamp + type + data + previous hash)
async function calculateHash(block) {
  return await sha256(block.index + block.timestamp + block.type + JSON.stringify(block.data) + block.prevHash);
}

// check if chain is valid
async function isChainValid(chain) {
  for (var i = 0; i < chain.length; i++) {
    var newHash = await calculateHash(chain[i]);
    if (newHash != chain[i].hash) {
      return { valid: false, block: i };
    }
    if (i > 0 && chain[i].prevHash != chain[i - 1].hash) {
      return { valid: false, block: i };
    }
  }
  return { valid: true };
}

// get list of nodes that are online and have valid chain
async function getGoodNodes() {
  var good = [];
  for (var i = 0; i < nodes.length; i++) {
    if (nodes[i].online) {
      var check = await isChainValid(nodes[i].chain);
      nodes[i].valid = check.valid;
      nodes[i].badBlock = check.block;
      if (check.valid) good.push(nodes[i]);
    }
  }
  return good;
}

// add new block to all good nodes
async function addBlock(type, data) {
  var good = await getGoodNodes();
  if (good.length == 0) {
    alertMsg("regMsg", "Error: no blockchain node available");
    return;
  }
  var chain = good[0].chain;
  var block = {
    index: chain.length,
    timestamp: Date.now(),
    type: type,
    data: data,
    prevHash: chain[chain.length - 1].hash
  };
  block.hash = await calculateHash(block);
  for (var i = 0; i < good.length; i++) {
    good[i].chain.push(JSON.parse(JSON.stringify(block)));
  }
}

// find latest record of a device in a chain
function findDevice(chain, id) {
  var record = null;
  for (var i = 0; i < chain.length; i++) {
    var b = chain[i];
    if (b.data.deviceId == id && (b.type == "REGISTER" || b.type == "REVOKE")) {
      if (record == null) record = {};
      record = Object.assign(record, b.data);
    }
  }
  return record;
}

// ask blockchain about a device (majority of good nodes)
async function queryBlockchain(id) {
  var good = await getGoodNodes();
  if (good.length == 0) return { error: "No blockchain node available" };
  var count = {};
  for (var i = 0; i < good.length; i++) {
    var key = JSON.stringify(findDevice(good[i].chain, id));
    if (!count[key]) count[key] = [];
    count[key].push(good[i].name);
  }
  var best = null;
  for (var k in count) {
    if (best == null || count[k].length > count[best].length) best = k;
  }
  return { record: JSON.parse(best), nodesUsed: count[best].join(", ") };
}

// ---------------- Device functions ----------------

async function registerDevice(id, type) {
  var keys = await generateKeys();
  devices[id] = { id: id, type: type, keyPair: keys.keyPair, publicKey: keys.publicKey };
  await addBlock("REGISTER", { deviceId: id, type: type, publicKey: keys.publicKey, status: "Authorized" });
}

async function revokeDevice(id) {
  await addBlock("REVOKE", { deviceId: id, status: "Revoked" });
  delete cache[id];
  alertMsg("regMsg", id + " has been revoked");
  showAll();
}

// ---------------- Authentication ----------------

var out;
function print(text) {
  out.textContent += text + "\n";
}

async function authenticate(id, useFakeKey) {
  out = document.getElementById("output");
  out.textContent = "";
  var start = performance.now();
  var device = devices[id];
  var result = false;
  var reason = "";

  print("Step 1: " + id + " connected to gateway via WiFi and sent auth request");
  await wait(100);

  // gateway creates random challenge
  var nonce = toHex(crypto.getRandomValues(new Uint8Array(16)));
  print("Step 2: Gateway sent challenge (nonce) = " + nonce);
  await wait(100);

  // device signs the challenge
  var privateKey = useFakeKey ? attackerKey.keyPair.privateKey : device.keyPair.privateKey;
  var message = new TextEncoder().encode(nonce + id);
  var signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, message);
  print("Step 3: Device signed challenge. Signature = " + shortHash(toHex(signature)) + (useFakeKey ? " (FAKE KEY)" : ""));
  await wait(100);

  // check cache first, else ask blockchain
  var record = null;
  var useCache = document.getElementById("useCache").checked;
  if (useCache && cache[id]) {
    record = cache[id];
    print("Step 4: Device found in gateway cache, blockchain query skipped");
  } else {
    await wait(150);
    var res = await queryBlockchain(id);
    if (res.error) {
      reason = res.error;
    } else if (res.record == null) {
      reason = "Device not registered on blockchain";
    } else if (res.record.status != "Authorized") {
      reason = "Device is " + res.record.status;
    } else {
      record = res.record;
    }
    print("Step 4: Blockchain checked (" + (res.nodesUsed || "none") + ") -> " + (record ? "Authorized" : reason));
    for (var i = 0; i < nodes.length; i++) {
      if (nodes[i].online && nodes[i].valid == false) print("        Warning: " + nodes[i].name + " ignored (chain tampered)");
    }
  }

  // verify signature using public key from blockchain
  if (record) {
    var pubKey = await crypto.subtle.importKey("raw", fromHex(record.publicKey), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    var ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pubKey, signature, message);
    if (ok) {
      print("Step 5: Signature verified with public key from blockchain");
      result = true;
      cache[id] = record;
    } else {
      reason = "Signature not valid (wrong key)";
      print("Step 5: Signature verification FAILED");
      delete cache[id];
    }
  } else {
    print("Step 5: Skipped");
  }

  var timeTaken = Math.round(performance.now() - start);

  if (result) {
    print("Step 6: ACCESS GRANTED");
    if (!device.ip) device.ip = "192.168.4." + (nextIp++);
    print("Step 7: IP assigned " + device.ip + " (DHCP), data sent to cloud using UDP/MQTT: " + getReading(device.type));
    reason = "Valid device";
  } else {
    print("Step 6: ACCESS DENIED - " + reason);
    print("Step 7: Device blocked, no IP given");
  }
  await addBlock(result ? "AUTH_OK" : "AUTH_FAIL", { deviceId: id, result: result ? "granted" : "denied" });
  print("Event saved in blockchain. Time taken: " + timeTaken + " ms");

  times.push(timeTaken);
  logs.unshift({ time: getTime(), id: id + (useFakeKey ? " (fake key)" : ""), result: result, reason: reason, ms: timeTaken });
  showAll();
}

function getReading(type) {
  if (type == "Temperature Sensor") return (22 + Math.random() * 5).toFixed(1) + " C";
  if (type == "Humidity Sensor") return Math.round(40 + Math.random() * 20) + " %";
  if (type == "Smart Meter") return (Math.random() * 2).toFixed(2) + " kW";
  return "image frame";
}

// ---------------- Display functions ----------------

function alertMsg(id, text) {
  document.getElementById(id).textContent = text;
}

function getStatus(id) {
  var chain = nodes[0].chain;
  for (var i = 0; i < nodes.length; i++) {
    if (nodes[i].online && nodes[i].valid != false) { chain = nodes[i].chain; break; }
  }
  return findDevice(chain, id);
}

async function showAll() {
  await getGoodNodes();

  // node table
  var html = "";
  for (var i = 0; i < nodes.length; i++) {
    var n = nodes[i];
    html += "<tr><td>" + n.name + "</td><td>" + (n.online ? "<span class='green'>Online</span>" : "<span class='redtext'>Offline</span>") +
      "</td><td>" + n.chain.length + "</td><td>" + (!n.online ? "-" : n.valid ? "<span class='green'>Yes</span>" : "<span class='redtext'>No (block " + n.badBlock + ")</span>") +
      "</td><td><button class='small' onclick='toggleNode(" + i + ")'>" + (n.online ? "Turn Off" : "Turn On") + "</button>" +
      (n.online && !n.valid ? " <button class='small' onclick='repairNode(" + i + ")'>Repair</button>" : "") + "</td></tr>";
  }
  document.getElementById("nodeTable").innerHTML = html;

  // device table + dropdown
  html = "";
  var options = "";
  var selected = document.getElementById("authDevice").value;
  for (var id in devices) {
    var rec = getStatus(id);
    var status = rec ? rec.status : "Not Registered";
    var cls = status == "Authorized" ? "green" : "redtext";
    html += "<tr><td>" + id + "</td><td>" + devices[id].type + "</td><td class='hash'>" + shortHash(devices[id].publicKey) +
      "</td><td class='" + cls + "'>" + status + "</td><td>" +
      (status == "Authorized" ? "<button class='small red' onclick=\"revokeDevice('" + id + "')\">Revoke</button>" : "-") + "</td></tr>";
    options += "<option value='" + id + "'>" + id + "</option>";
  }
  document.getElementById("deviceTable").innerHTML = html;
  document.getElementById("authDevice").innerHTML = options;
  if (selected) document.getElementById("authDevice").value = selected;

  // blockchain table
  var node = nodes[document.getElementById("viewNode").value];
  html = "";
  for (var j = 0; j < node.chain.length; j++) {
    var b = node.chain[j];
    var data = b.type == "GENESIS" ? "Genesis Block" : b.data.deviceId + " " + (b.data.status || b.data.result);
    var bad = node.valid == false && j >= node.badBlock;
    html += "<tr" + (bad ? " class='badrow'" : "") + "><td>" + b.index + "</td><td>" + new Date(b.timestamp).toLocaleTimeString() +
      "</td><td>" + b.type + "</td><td>" + data + "</td><td class='hash'>" + shortHash(b.prevHash) + "</td><td class='hash'>" + shortHash(b.hash) + "</td></tr>";
  }
  document.getElementById("chainTable").innerHTML = html;

  // log table
  html = "";
  for (var k = 0; k < logs.length; k++) {
    var l = logs[k];
    html += "<tr><td>" + l.time + "</td><td>" + l.id + "</td><td class='" + (l.result ? "green" : "redtext") + "'>" +
      (l.result ? "Granted" : "Denied") + "</td><td>" + l.reason + "</td><td>" + l.ms + " ms</td></tr>";
  }
  document.getElementById("logTable").innerHTML = html;

  var granted = logs.filter(function (x) { return x.result; }).length;
  document.getElementById("total").textContent = logs.length;
  document.getElementById("granted").textContent = granted;
  document.getElementById("denied").textContent = logs.length - granted;
  var sum = 0;
  for (var t = 0; t < times.length; t++) sum += times[t];
  document.getElementById("avg").textContent = times.length ? Math.round(sum / times.length) : 0;
}

// ---------------- Node functions ----------------

async function toggleNode(i) {
  nodes[i].online = !nodes[i].online;
  // when node comes back, copy latest chain from another good node
  if (nodes[i].online) {
    var good = await getGoodNodes();
    for (var j = 0; j < good.length; j++) {
      if (good[j].chain.length > nodes[i].chain.length && nodes[i].valid) {
        nodes[i].chain = JSON.parse(JSON.stringify(good[j].chain));
      }
    }
  }
  showAll();
}

async function repairNode(i) {
  nodes[i].online = false;
  var good = await getGoodNodes();
  nodes[i].online = true;
  if (good.length > 0) {
    nodes[i].chain = JSON.parse(JSON.stringify(good[0].chain));
    alertMsg("chainMsg", nodes[i].name + " repaired by copying chain from " + good[0].name);
  }
  showAll();
}

// ---------------- Button events ----------------

function setButtons(disabled) {
  var btns = document.querySelectorAll("button");
  for (var i = 0; i < btns.length; i++) btns[i].disabled = disabled;
}

document.getElementById("btnRegister").onclick = async function () {
  var id = document.getElementById("devId").value.trim().toUpperCase();
  var type = document.getElementById("devType").value;
  if (id == "") {
    alertMsg("regMsg", "Please enter device ID");
    return;
  }
  var rec = getStatus(id);
  if (rec) {
    alertMsg("regMsg", id + " is already registered");
    return;
  }
  await registerDevice(id, type);
  document.getElementById("devId").value = "";
  alertMsg("regMsg", id + " registered successfully and added to blockchain");
  showAll();
};

document.getElementById("btnAuth").onclick = async function () {
  setButtons(true);
  await authenticate(document.getElementById("authDevice").value, document.getElementById("fakeKey").checked);
  setButtons(false);
};

// test cases from our report
document.getElementById("btnTest").onclick = async function () {
  setButtons(true);
  var tests = [["SENSOR001", false], ["SENSOR999", false], ["SENSOR002", true], ["SENSOR003", false]];
  for (var i = 0; i < tests.length; i++) {
    await authenticate(tests[i][0], tests[i][1]);
    await wait(1200);
  }
  setButtons(false);
};

document.getElementById("viewNode").onchange = showAll;

document.getElementById("btnValidate").onclick = async function () {
  var node = nodes[document.getElementById("viewNode").value];
  var check = await isChainValid(node.chain);
  if (check.valid) alertMsg("chainMsg", node.name + ": Blockchain is valid");
  else alertMsg("chainMsg", node.name + ": Blockchain is NOT valid. Hash mismatch at block " + check.block);
  showAll();
};

// change data of a block without updating hash (to show tamper detection)
document.getElementById("btnTamper").onclick = async function () {
  var node = nodes[document.getElementById("viewNode").value];
  var no = parseInt(document.getElementById("tamperNo").value);
  if (isNaN(no) || no < 1 || no >= node.chain.length) {
    alertMsg("chainMsg", "Enter a valid block number (1 to " + (node.chain.length - 1) + ")");
    return;
  }
  var block = node.chain[no];
  if (block.type == "REVOKE") block.data.status = "Authorized";
  else if (block.type == "REGISTER") block.data.publicKey = attackerKey.publicKey;
  else block.data.result = "granted";
  cache = {};
  alertMsg("chainMsg", "Block " + no + " in " + node.name + " was changed. Click Validate Chain to check.");
  showAll();
};

// ---------------- Start ----------------

async function start() {
  if (!window.crypto || !crypto.subtle) {
    alertMsg("regMsg", "Web Crypto not supported in this browser. Please open using http://localhost or https.");
    return;
  }
  // genesis block
  var genesis = { index: 0, timestamp: Date.now(), type: "GENESIS", data: {}, prevHash: "0" };
  genesis.hash = await calculateHash(genesis);
  for (var i = 0; i < nodes.length; i++) nodes[i].chain.push(JSON.parse(JSON.stringify(genesis)));

  attackerKey = await generateKeys();

  // sample devices
  await registerDevice("SENSOR001", "Temperature Sensor");
  await registerDevice("SENSOR002", "Humidity Sensor");
  await registerDevice("SENSOR003", "Smart Meter");
  await addBlock("REVOKE", { deviceId: "SENSOR003", status: "Revoked" });

  // unknown device (has keys but not on blockchain)
  var k = await generateKeys();
  devices["SENSOR999"] = { id: "SENSOR999", type: "Temperature Sensor", keyPair: k.keyPair, publicKey: k.publicKey };

  showAll();
}

start();
