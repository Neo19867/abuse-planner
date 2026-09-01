const assert = require("assert");
const fs = require("fs");
const vm = require("vm");

const html = fs.readFileSync("index.html", "utf8");
const match = html.match(/<script>([\s\S]*)<\/script>/);
assert(match, "planner script not found");
const script = match[1];

class MemoryStorage {
  constructor(values = {}) {
    this.values = {...values};
  }
  getItem(key) {
    return Object.prototype.hasOwnProperty.call(this.values, key)
      ? this.values[key]
      : null;
  }
  setItem(key, value) {
    this.values[key] = String(value);
  }
  removeItem(key) {
    delete this.values[key];
  }
}

function element(id) {
  return {
    id,
    value: "",
    checked: false,
    style: {},
    className: "",
    textContent: "",
    innerHTML: "",
    addEventListener() {},
    appendChild() {},
    getContext() {
      return {
        fillStyle: "",
        font: "",
        fillRect() {},
        fillText() {},
      };
    },
  };
}

function run(storage, payload) {
  const elements = new Map();
  const get = (id) => {
    if (!elements.has(id)) elements.set(id, element(id));
    return elements.get(id);
  };
  const encoded = payload
    ? Buffer.from(JSON.stringify(payload), "utf8").toString("base64url")
    : "";
  const context = {
    console,
    Date,
    Intl,
    Math,
    Number,
    String,
    Boolean,
    Object,
    Array,
    JSON,
    RegExp,
    Uint8Array,
    TextDecoder,
    atob,
    localStorage: storage,
    location: {
      hash: encoded ? `#pro-uchet=${encoded}` : "",
      pathname: "/abuse-planner/",
      search: "",
    },
    history: {
      replaceState(_state, _title, url) {
        context.location.hash = "";
        context.replacedUrl = url;
      },
    },
    navigator: {clipboard: {writeText: async () => {}}},
    document: {
      getElementById: get,
      createElement: (tag) => element(tag),
    },
    addEventListener() {},
    setInterval() {},
    prompt() {},
    alert() {},
    confirm: () => true,
    innerWidth: 1080,
    innerHeight: 1920,
  };
  context.window = context;
  vm.createContext(context);
  vm.runInContext(script, context);
  return {context, elements};
}

function isoDay(start, offset) {
  const date = new Date(`${start}T12:00:00Z`);
  date.setUTCDate(date.getUTCDate() + offset);
  return date.toISOString().slice(0, 10);
}

function payload(start, orderBase = 1) {
  return {
    app: "pro-uchet",
    schema: 1,
    exportedAt: "2026-09-01T12:00:00+07:00",
    period: {start, end: isoDay(start, 13)},
    settings: {
      rate: 400,
      target: 1.6,
      minPeriodHours: 80,
      yandexHours: "12:30",
      yandexCoef: 1.76,
      settingsVersion: 3,
    },
    rows: Array.from({length: 14}, (_, index) => ({
      date: isoDay(start, index),
      fs: index === 0 ? "08:00-10:31" : "",
      breaks: "",
      fhm: index === 0 ? 150 : 0,
      fo: index === 0 ? orderBase : 0,
      done: index === 0,
    })),
  };
}

const storage = new MemoryStorage();
const first = run(storage, payload("2026-08-29", 4));
let rows = JSON.parse(storage.getItem("courierPlan_rows_v14"));
let settings = JSON.parse(storage.getItem("courierPlan_settings_v14"));
assert.strictEqual(rows.length, 14);
assert.strictEqual(rows[0].fo, 4);
assert.strictEqual(rows[0].fs, "08:00-10:31");
assert.strictEqual(rows[0].fhm, 150);
assert.strictEqual(rows[0].afm, 150);
assert.strictEqual(first.elements.get("factSummary").textContent, "4 / 02:30");
assert.strictEqual(settings.rate, 400);
assert.strictEqual(settings.target, 1.6);
assert.match(first.elements.get("proUchetImportStatus").textContent, /2026-08-29/);
assert.strictEqual(first.context.location.hash, "");

rows[2].phm = 777;
storage.setItem("courierPlan_rows_v14", JSON.stringify(rows));
run(storage, payload("2026-08-29", 5));
rows = JSON.parse(storage.getItem("courierPlan_rows_v14"));
assert.strictEqual(rows[0].fo, 5, "facts must refresh");
assert.strictEqual(rows[2].phm, 777, "same-period plan must survive refresh");

run(storage, payload("2026-09-12", 2));
rows = JSON.parse(storage.getItem("courierPlan_rows_v14"));
assert.strictEqual(rows[0].phm, 0, "Saturday must not get weekday plan");
assert.strictEqual(rows[2].phm, 600, "Monday must get default weekday plan");
assert.strictEqual(rows[0].fo, 2);

console.log("Pro Uchet import smoke test passed");
