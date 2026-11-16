import fs from "node:fs";
import path from "node:path";

const CREDENTIAL_PREFIX_RE = /(?:se-session|oc-relay|worker-relay)-[A-Za-z0-9_-]{12,}/g;
const CREDENTIAL_PREFIX_TEST_RE = /(?:se-session|oc-relay|worker-relay)-[A-Za-z0-9_-]{12,}/;
const BASE64_PREFIX_TEST_RE = /(?:c2Utc2Vzc2lvbi0|b2MtcmVsYXkt|d29ya2VyLXJlbGF5LQ)/;
const AUTH_HEADER_RE = /(Authorization:\s*(?:Bearer|Basic)\s+)[A-Za-z0-9._~+/=-]{12,}/gi;
const B64_TOKEN_RE = /[A-Za-z0-9+/_-]{16,}={0,2}/g;
const SECRET_STORE_PATH_RE =
  /(?:^|[\s"'`=:/\\])(?:\.se-session-[^\s"'`]*|se-envelopes(?:$|[\s"'`/\\])|service\.json(?:$|[\s"'`])|service-[A-Za-z0-9_.-]+\.json(?:$|[\s"'`]))/;

function safeDecodeURIComponent(text) {
  if (!text || !text.includes("%")) {
    return text;
  }
  try {
    return decodeURIComponent(text);
  } catch {
    return text.replace(/%[0-9A-Fa-f]{2}/g, (seq) => {
      try {
        return decodeURIComponent(seq);
      } catch {
        return seq;
      }
    });
  }
}

function buildVariantsForSecret(secret) {
  const clean = String(secret || "").trim();
  if (clean.length < 8) {
    return [];
  }
  const out = new Set();
  const candidates = [
    clean,
    encodeURIComponent(clean),
    Buffer.from(clean, "utf8").toString("base64"),
    Buffer.from(clean, "utf8").toString("base64").replace(/=+$/, ""),
    Buffer.from(clean, "utf8").toString("base64url"),
    Buffer.from(`opencode:${clean}`, "utf8").toString("base64"),
    Buffer.from(`opencode:${clean}`, "utf8").toString("base64").replace(/=+$/, ""),
    Buffer.from(`:${clean}`, "utf8").toString("base64"),
    Buffer.from(`:${clean}`, "utf8").toString("base64").replace(/=+$/, ""),
  ];
  for (const item of candidates) {
    if (item && item.length >= 8) {
      out.add(item);
    }
  }
  return Array.from(out);
}

function readJsonIfExists(filePath) {
  if (!filePath) {
    return null;
  }
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function createSecretRegistry() {
  const seenSecrets = new Set();
  const variants = new Set();
  const fileMtimes = new Map();

  function addSecret(secret) {
    const clean = String(secret || "").trim();
    if (
      clean.length < 8 ||
      clean === "none" ||
      clean === "se-keychain-managed" ||
      clean.startsWith("{env:")
    ) {
      return;
    }
    if (seenSecrets.has(clean)) {
      return;
    }
    seenSecrets.add(clean);
    for (const v of buildVariantsForSecret(clean)) {
      variants.add(v);
    }
  }

  function refreshFromFile(filePath, extractor) {
    if (!filePath) {
      return;
    }
    try {
      const st = fs.statSync(filePath);
      const prev = fileMtimes.get(filePath);
      if (prev === st.mtimeMs) {
        return;
      }
      fileMtimes.set(filePath, st.mtimeMs);
      const parsed = readJsonIfExists(filePath);
      if (parsed && typeof parsed === "object") {
        extractor(parsed);
      }
    } catch {
      // Ignore absent or unreadable files inside confined sandbox modes.
    }
  }

  function refresh() {
    for (const envName of [
      "OPENCODE_PASSWORD",
      "OPENCODE_SERVER_PASSWORD",
      "LOCAL_ASSIST_SESSION_TOKEN",
    ]) {
      if (process.env[envName]) {
        addSecret(process.env[envName]);
      }
    }

    const xdgConfig = process.env.XDG_CONFIG_HOME || "";
    if (xdgConfig) {
      refreshFromFile(path.join(xdgConfig, "opencode", "service.json"), (obj) => {
        if (typeof obj.password === "string") {
          addSecret(obj.password);
        }
      });
    }

    const xdgState = process.env.XDG_STATE_HOME || "";
    if (xdgState) {
      refreshFromFile(path.join(xdgState, "opencode", "service.json"), (obj) => {
        if (typeof obj.password === "string") {
          addSecret(obj.password);
        }
      });
    }

    const opencodeCfg = process.env.OPENCODE_CONFIG || "";
    if (opencodeCfg) {
      refreshFromFile(opencodeCfg, (obj) => {
        const providers = obj && typeof obj.provider === "object" ? obj.provider : null;
        if (!providers) {
          return;
        }
        for (const prov of Object.values(providers)) {
          const apiKey = prov && prov.options && prov.options.apiKey;
          if (typeof apiKey === "string") {
            addSecret(apiKey);
          }
        }
      });
    }
  }

  function textContainsLeak(rawText, { checkStorePaths = false } = {}) {
    if (typeof rawText !== "string" || rawText.length === 0) {
      return false;
    }
    refresh();
    const decodedUrl = safeDecodeURIComponent(rawText);
    const surfaces = decodedUrl === rawText ? [rawText] : [rawText, decodedUrl];

    for (const surface of surfaces) {
      if (CREDENTIAL_PREFIX_TEST_RE.test(surface) || BASE64_PREFIX_TEST_RE.test(surface)) {
        return true;
      }
      if (checkStorePaths && SECRET_STORE_PATH_RE.test(surface)) {
        return true;
      }
      for (const v of variants) {
        if (surface.includes(v)) {
          return true;
        }
      }
    }

    const matches = rawText.match(B64_TOKEN_RE);
    if (matches) {
      for (const candidate of matches) {
        try {
          const norm = candidate.replace(/-/g, "+").replace(/_/g, "/");
          const padLen = (4 - (norm.length % 4)) % 4;
          const decoded = Buffer.from(norm + "=".repeat(padLen), "base64").toString("utf8");
          if (!decoded) {
            continue;
          }
          const decUrl = safeDecodeURIComponent(decoded);
          if (
            CREDENTIAL_PREFIX_TEST_RE.test(decoded) ||
            CREDENTIAL_PREFIX_TEST_RE.test(decUrl) ||
            (checkStorePaths &&
              (SECRET_STORE_PATH_RE.test(decoded) || SECRET_STORE_PATH_RE.test(decUrl)))
          ) {
            return true;
          }
          for (const s of seenSecrets) {
            if (decoded.includes(s) || decUrl.includes(s)) {
              return true;
            }
          }
        } catch {
          // Ignore non-base64 tokens.
        }
      }
    }
    return false;
  }

  function scrubString(text) {
    if (typeof text !== "string" || text.length === 0) {
      return text;
    }
    refresh();
    let out = text.replace(AUTH_HEADER_RE, "$1[REDACTED_CREDENTIAL]");
    out = out.replace(CREDENTIAL_PREFIX_RE, "[REDACTED_CREDENTIAL]");
    const sortedVariants = Array.from(variants).sort((a, b) => b.length - a.length);
    for (const v of sortedVariants) {
      if (out.includes(v)) {
        out = out.split(v).join("[REDACTED_CREDENTIAL]");
      }
    }
    return out;
  }

  function scrubValueInPlace(node, memo = new WeakMap()) {
    if (typeof node === "string") {
      return scrubString(node);
    }
    if (!node || typeof node !== "object") {
      return node;
    }
    if (memo.has(node)) {
      return memo.get(node);
    }
    memo.set(node, node);
    if (Array.isArray(node)) {
      let arrayFallbackNeeded = false;
      const scrubbedArr = new Array(node.length);
      for (let i = 0; i < node.length; i += 1) {
        const nextVal = scrubValueInPlace(node[i], memo);
        scrubbedArr[i] = nextVal;
        if (nextVal !== node[i]) {
          try {
            node[i] = nextVal;
            if (node[i] !== nextVal) {
              arrayFallbackNeeded = true;
            }
          } catch {
            arrayFallbackNeeded = true;
          }
        }
      }
      if (!arrayFallbackNeeded) {
        return node;
      }
      memo.set(node, scrubbedArr);
      for (let i = 0; i < scrubbedArr.length; i += 1) {
        if (scrubbedArr[i] === node) {
          scrubbedArr[i] = scrubbedArr;
        }
      }
      return scrubbedArr;
    }

    function buildDisambiguatedPairs(itemEntries) {
      const unchangedKeys = new Set(
        itemEntries.filter((e) => e.scrubbedKey === e.rawKey).map((e) => e.rawKey)
      );
      const usedKeys = new Set();
      const pairs = [];
      for (const entry of itemEntries) {
        let targetKey = entry.scrubbedKey;
        if (entry.scrubbedKey !== entry.rawKey) {
          let idx = 2;
          while (usedKeys.has(targetKey) || unchangedKeys.has(targetKey)) {
            targetKey = `${entry.scrubbedKey}#${idx}`;
            idx += 1;
          }
        } else if (usedKeys.has(targetKey)) {
          let idx = 2;
          while (usedKeys.has(`${targetKey}#${idx}`)) {
            idx += 1;
          }
          targetKey = `${targetKey}#${idx}`;
        }
        usedKeys.add(targetKey);
        pairs.push([targetKey, entry.scrubbedVal]);
      }
      return pairs;
    }

    const isError = node instanceof Error;
    let errorFallbackNeeded = false;
    let scrubbedMsg;
    let scrubbedOwnName;
    let scrubbedStack;
    let hasNonEnumCause = false;
    let origNonEnumCause;
    let scrubbedNonEnumCause;

    if (isError) {
      if (typeof node.message === "string") {
        scrubbedMsg = scrubString(node.message);
      }
      const nameDesc = Object.getOwnPropertyDescriptor(node, "name");
      if (nameDesc && !nameDesc.enumerable && typeof node.name === "string") {
        scrubbedOwnName = scrubString(node.name);
      }
      if (typeof node.stack === "string") {
        scrubbedStack = scrubString(node.stack);
      }
      const causeDesc = Object.getOwnPropertyDescriptor(node, "cause");
      if (causeDesc && !causeDesc.enumerable) {
        hasNonEnumCause = true;
        origNonEnumCause = node.cause;
        scrubbedNonEnumCause = scrubValueInPlace(origNonEnumCause, memo);
      }

      if (scrubbedMsg !== undefined && scrubbedMsg !== node.message) {
        try {
          node.message = scrubbedMsg;
          if (node.message !== scrubbedMsg) {
            errorFallbackNeeded = true;
          }
        } catch {
          errorFallbackNeeded = true;
        }
      }
      if (scrubbedOwnName !== undefined && scrubbedOwnName !== node.name) {
        try {
          Object.defineProperty(node, "name", {
            value: scrubbedOwnName,
            writable: true,
            enumerable: false,
            configurable: true,
          });
          if (node.name !== scrubbedOwnName) {
            errorFallbackNeeded = true;
          }
        } catch {
          errorFallbackNeeded = true;
        }
      }
      if (scrubbedStack !== undefined && scrubbedStack !== node.stack) {
        try {
          Object.defineProperty(node, "stack", {
            value: scrubbedStack,
            writable: true,
            enumerable: false,
            configurable: true,
          });
          if (node.stack !== scrubbedStack) {
            errorFallbackNeeded = true;
          }
        } catch {
          errorFallbackNeeded = true;
        }
      }
      if (hasNonEnumCause && scrubbedNonEnumCause !== origNonEnumCause) {
        try {
          Object.defineProperty(node, "cause", {
            value: scrubbedNonEnumCause,
            writable: true,
            enumerable: false,
            configurable: true,
          });
          if (node.cause !== scrubbedNonEnumCause) {
            errorFallbackNeeded = true;
          }
        } catch {
          errorFallbackNeeded = true;
        }
      }
    }

    const rawKeys = Object.keys(node);
    const entries = [];
    let anyKeyChanged = false;
    for (const rawKey of rawKeys) {
      const scrubbedKey = scrubString(rawKey);
      if (scrubbedKey !== rawKey) {
        anyKeyChanged = true;
      }
      entries.push({
        rawKey,
        scrubbedKey,
        scrubbedVal: scrubValueInPlace(node[rawKey], memo),
      });
    }

    function buildContainerFallback(pairs) {
      if (isError) {
        const effMsg =
          scrubbedMsg !== undefined
            ? scrubbedMsg
            : typeof node.message === "string"
              ? node.message
              : "";
        const errFallback = new Error(effMsg);
        const effName =
          scrubbedOwnName !== undefined
            ? scrubbedOwnName
            : typeof node.name === "string" && node.name !== "Error"
              ? scrubString(node.name)
              : undefined;
        if (effName !== undefined) {
          Object.defineProperty(errFallback, "name", {
            value: effName,
            writable: true,
            enumerable: false,
            configurable: true,
          });
        }
        if (scrubbedStack !== undefined) {
          Object.defineProperty(errFallback, "stack", {
            value: scrubbedStack,
            writable: true,
            enumerable: false,
            configurable: true,
          });
        }
        memo.set(node, errFallback);
        if (hasNonEnumCause) {
          Object.defineProperty(errFallback, "cause", {
            value: scrubbedNonEnumCause === node ? errFallback : scrubbedNonEnumCause,
            writable: true,
            enumerable: false,
            configurable: true,
          });
        }
        for (const [targetKey, val] of pairs) {
          errFallback[targetKey] = val === node ? errFallback : val;
        }
        return errFallback;
      }

      const out = {};
      memo.set(node, out);
      for (const [targetKey, val] of pairs) {
        out[targetKey] = val === node ? out : val;
      }
      return out;
    }

    if (!anyKeyChanged) {
      let fallbackNeeded = errorFallbackNeeded;
      if (!fallbackNeeded) {
        for (const entry of entries) {
          if (entry.scrubbedVal !== node[entry.rawKey]) {
            try {
              node[entry.rawKey] = entry.scrubbedVal;
              if (node[entry.rawKey] !== entry.scrubbedVal) {
                fallbackNeeded = true;
              }
            } catch {
              fallbackNeeded = true;
            }
          }
        }
      }
      if (!fallbackNeeded) {
        return node;
      }
      return buildContainerFallback(entries.map((e) => [e.rawKey, e.scrubbedVal]));
    }

    const finalPairs = buildDisambiguatedPairs(entries);

    let inPlaceOk = !errorFallbackNeeded;
    if (inPlaceOk) {
      try {
        for (const entry of entries) {
          const deleted = delete node[entry.rawKey];
          if (!deleted && Object.prototype.hasOwnProperty.call(node, entry.rawKey)) {
            inPlaceOk = false;
            break;
          }
        }
        if (inPlaceOk) {
          for (const [targetKey, val] of finalPairs) {
            node[targetKey] = val;
            if (node[targetKey] !== val) {
              inPlaceOk = false;
              break;
            }
          }
        }
        if (inPlaceOk) {
          for (const entry of entries) {
            if (
              entry.scrubbedKey !== entry.rawKey &&
              Object.prototype.hasOwnProperty.call(node, entry.rawKey)
            ) {
              inPlaceOk = false;
              break;
            }
          }
        }
      } catch {
        inPlaceOk = false;
      }
    }

    if (inPlaceOk) {
      return node;
    }
    return buildContainerFallback(finalPairs);
  }

  refresh();
  return {
    refresh,
    textContainsLeak,
    scrubString,
    scrubValueInPlace,
  };
}

function createShellSpoolScrubber(registry) {
  const checkedSpools = new Map();

  return function scrubRecentShellSpools() {
    const xdgData = process.env.XDG_DATA_HOME || "";
    if (!xdgData) {
      return;
    }
    const shellRoot = path.join(xdgData, "opencode", "shell");
    let topEntries = [];
    try {
      const rootStat = fs.lstatSync(shellRoot);
      if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
        return;
      }
      topEntries = fs.readdirSync(shellRoot, { withFileTypes: true });
    } catch {
      return;
    }

    const candidates = [];
    for (const entry of topEntries) {
      const entryPath = path.join(shellRoot, entry.name);
      if (entry.isSymbolicLink()) {
        continue;
      }
      if (entry.isFile() && entry.name.endsWith(".out")) {
        candidates.push(entryPath);
      } else if (entry.isDirectory()) {
        try {
          const subEntries = fs.readdirSync(entryPath, { withFileTypes: true });
          for (const sub of subEntries) {
            if (!sub.isSymbolicLink() && sub.isFile() && sub.name.endsWith(".out")) {
              candidates.push(path.join(entryPath, sub.name));
            }
          }
        } catch {
          // Ignore transient directory removal.
        }
      }
    }

    for (const filePath of candidates) {
      try {
        const st = fs.lstatSync(filePath);
        if (!st.isFile() || st.isSymbolicLink() || st.size === 0 || st.size > 16 * 1024 * 1024) {
          continue;
        }
        const stamp = `${st.mtimeMs}:${st.size}`;
        if (checkedSpools.get(filePath) === stamp) {
          continue;
        }
        const raw = fs.readFileSync(filePath, "utf8");
        const scrubbed = registry.scrubString(raw);
        if (scrubbed !== raw) {
          fs.writeFileSync(filePath, scrubbed, { encoding: "utf8", mode: 0o600 });
          const postStat = fs.lstatSync(filePath);
          checkedSpools.set(filePath, `${postStat.mtimeMs}:${postStat.size}`);
        } else {
          checkedSpools.set(filePath, stamp);
        }
      } catch {
        // Ignore unreadable or concurrently removed spool files.
      }
    }
  };
}

function isLocalAssistMcpConfigured() {
  const cfgPath = process.env.OPENCODE_CONFIG || "";
  const cfg = readJsonIfExists(cfgPath);
  const srv = cfg && cfg.mcp && cfg.mcp.servers && cfg.mcp.servers.local_assist;
  if (!srv || typeof srv !== "object") {
    return false;
  }
  return srv.disabled !== true;
}

export default {
  id: "free-inference.credential-guard",
  async setup(ctx) {
    const registry = createSecretRegistry();
    const scrubShellSpools = createShellSpoolScrubber(registry);
    let mcpReady = false;
    let warnedMcpTimeout = false;

    if (ctx && ctx.session && typeof ctx.session.hook === "function") {
      await ctx.session.hook("prompt", async () => {
        if (mcpReady || !isLocalAssistMcpConfigured()) {
          return;
        }
        if (!ctx.tool || typeof ctx.tool.list !== "function") {
          return;
        }
        const deadline = Date.now() + 2500;
        while (Date.now() < deadline) {
          try {
            const tools = await ctx.tool.list();
            if (
              Array.isArray(tools) &&
              tools.some((t) => String((t && (t.id || t.name)) || "").startsWith("local_assist_"))
            ) {
              mcpReady = true;
              return;
            }
          } catch {
            // Retry until bounded deadline.
          }
          await new Promise((resolve) => setTimeout(resolve, 25));
        }
        if (!mcpReady && !warnedMcpTimeout) {
          warnedMcpTimeout = true;
          process.stderr.write(
            "[credential-guard] warning: local_assist MCP tools did not finish registering within 2500ms; proceeding with prompt.\n"
          );
        }
      });

      await ctx.session.hook("http.request", async (ev) => {
        const req = ev && ev.request;
        if (!req || typeof req.clone !== "function") {
          return;
        }
        let bodyText = "";
        try {
          bodyText = await req.clone().text();
        } catch {
          return;
        }
        if (bodyText && registry.textContainsLeak(bodyText, { checkStorePaths: false })) {
          throw new Error("credential-guard: credential_leak_blocked");
        }
      });
    }

    if (ctx && ctx.tool && typeof ctx.tool.hook === "function") {
      await ctx.tool.hook("execute.before", async (ev) => {
        const target = ev && ev.input !== undefined ? ev.input : ev;
        let serialized = "";
        try {
          serialized = JSON.stringify(target ?? "");
        } catch {
          serialized = String(target ?? "");
        }
        if (registry.textContainsLeak(serialized, { checkStorePaths: true })) {
          throw new Error(
            "credential-guard: blocked restricted credential or secret-store reference in tool input"
          );
        }
      });

      await ctx.tool.hook("execute.after", async (ev) => {
        if (!ev || typeof ev !== "object") {
          return;
        }
        const sharedMemo = new WeakMap();
        if ("result" in ev) {
          ev.result = registry.scrubValueInPlace(ev.result, sharedMemo);
        }
        if ("output" in ev) {
          ev.output = registry.scrubValueInPlace(ev.output, sharedMemo);
        }
        if ("error" in ev && ev.error !== undefined && ev.error !== null) {
          ev.error = registry.scrubValueInPlace(ev.error, sharedMemo);
        }
        scrubShellSpools();
      });
    }
  },
};
