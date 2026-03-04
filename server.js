// server.js - v2.7.8 — 2026-03-04
// Changes from v2.7.7:
//   - Gemini model updated to gemini-2.5-flash-lite (2.0 models deprecated)
//   - Gemini model now configurable via ENV (GEMINI_MODEL)
//   - Startup log updated to reflect correct Gemini model
//   - No functional logic changes

import { createServer } from "http";
import { readFileSync, existsSync, writeFileSync, mkdirSync } from "fs";
import { spawn } from "child_process";
import * as dotenv from "dotenv";
dotenv.config();

const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.5-flash-lite";

// 529-only retry wrapper for Claude API calls
const withClaudeRetry = async (fn, retries=3, delay=5000) => {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try { return await fn(); }
    catch (e) {
      const is529 = e.message && (e.message.includes("529") || e.message.includes("overloaded"));
      if (is529 && attempt < retries) {
        console.log(`⏳ Claude overloaded, retry ${attempt}/${retries} in ${delay*attempt}ms...`);
        await new Promise(r => setTimeout(r, delay * attempt));
      } else { throw e; }
    }
  }
};

import { Resend } from "resend";
const resend = new Resend(process.env.RESEND_API_KEY);

const PORT = process.env.PORT || 3000;
const runningScripts = new Set();

// ── PROTECTION LAYER ──────────────────────────────────────────────────────────
const FREE_EMAIL_DOMAINS = new Set([
  "gmail.com","yahoo.com","hotmail.com","outlook.com","aol.com",
  "icloud.com","mail.com","protonmail.com","zoho.com","yandex.com",
  "live.com","msn.com","me.com","mac.com","inbox.com","gmx.com",
  "fastmail.com","tutanota.com","guerrillamail.com","mailinator.com",
  "tempmail.com","throwaway.email","sharklasers.com","yopmail.com"
]);

const auditCache  = new Map();
const ipRateLimit = new Map();
const CACHE_TTL_MS   = 7 * 24 * 60 * 60 * 1000;
const RATE_WINDOW_MS = 24 * 60 * 60 * 1000;
const RATE_MAX = 1000;
const CACHE_FILE = "./results/audit-cache.json";

function loadCache() {
  try {
    if (existsSync(CACHE_FILE)) {
      const data = JSON.parse(readFileSync(CACHE_FILE, "utf8"));
      for (const [k, v] of Object.entries(data)) auditCache.set(k, v);
      console.log(`📦 Loaded ${auditCache.size} cached audits (cache lookup disabled)`);
    }
  } catch (e) { console.log("Cache load error:", e.message); }
}

function saveCache() {
  try {
    if (!existsSync("./results")) mkdirSync("./results", { recursive: true });
    const obj = {};
    for (const [k, v] of auditCache.entries()) obj[k] = v;
    writeFileSync(CACHE_FILE, JSON.stringify(obj, null, 2));
  } catch (e) { console.log("Cache save error:", e.message); }
}

function getEmailDomain(email) {
  return (email || "").split("@")[1]?.toLowerCase() || "";
}

function getClientIP(req) {
  return req.headers["x-forwarded-for"]?.split(",")[0]?.trim()
    || req.socket?.remoteAddress
    || "unknown";
}

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = ipRateLimit.get(ip);
  if (!entry || (now - entry.windowStart) > RATE_WINDOW_MS) {
    ipRateLimit.set(ip, { count: 1, windowStart: now });
    return { allowed: true };
  }
  if (entry.count >= RATE_MAX) {
    const resetIn = Math.ceil((RATE_WINDOW_MS - (now - entry.windowStart)) / 3600000);
    return { allowed: false, resetIn };
  }
  entry.count++;
  return { allowed: true };
}

function getCachedAudit(domain) {
  const entry = auditCache.get(domain);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > CACHE_TTL_MS) { auditCache.delete(domain); return null; }
  return entry;
}

function getDomain(url) {
  try { return new URL(url).hostname.replace(/^www\./, ""); }
  catch { return url; }
}

// ── CSV PARSER ────────────────────────────────────────────────────────────────
function parseCSV(filepath) {
  if (!existsSync(filepath)) return [];
  const raw = readFileSync(filepath, "utf8");
  const rows = [];
  let i = 0;
  while (i < raw.length && raw[i] !== "\n") i++;
  i++;
  while (i < raw.length) {
    const cols = [];
    while (i < raw.length) {
      if (raw[i] === '"') {
        i++;
        let field = "";
        while (i < raw.length) {
          if (raw[i] === '"' && raw[i+1] === '"') { field += '"'; i += 2; }
          else if (raw[i] === '"') { i++; break; }
          else { field += raw[i++]; }
        }
        cols.push(field);
      } else {
        let field = "";
        while (i < raw.length && raw[i] !== "," && raw[i] !== "\n") field += raw[i++];
        cols.push(field.trim());
      }
      if (i < raw.length && raw[i] === ",") i++;
      else { if (i < raw.length && raw[i] === "\n") i++; break; }
    }
    if (cols.length >= 10 && cols[0]?.includes("202")) {
      rows.push({
        timestamp: cols[0], brand: cols[1], platform: cols[2], question: cols[3], response: cols[4],
        categoryAccuracy: parseInt(cols[5])||0, explanationQuality: parseInt(cols[6])||0,
        contextRelevance: parseInt(cols[7])||0, featureRecognition: parseInt(cols[8])||0,
        overallScore: parseInt(cols[9])||0, keyGaps: cols[10]||"",
      });
    }
  }
  return rows;
}

function aggregateScores(rows) {
  const byDate = {};
  for (const row of rows) {
    const date = row.timestamp.substring(0, 10);
    if (!byDate[date]) byDate[date] = {};
    if (!byDate[date][row.platform]) byDate[date][row.platform] = [];
    byDate[date][row.platform].push(row);
  }
  const history = Object.entries(byDate).sort().map(([date, platforms]) => {
    const entry = { date };
    for (const [p, rows] of Object.entries(platforms))
      entry[p] = Math.round(rows.reduce((a,r) => a+r.overallScore, 0) / rows.length);
    return entry;
  });
  const latestDate = Object.keys(byDate).sort().reverse()[0];
  const latestRows = latestDate ? rows.filter(r => r.timestamp.substring(0,10) === latestDate) : [];
  const dimensions = {};
  for (const platform of ["ChatGPT","Claude","Gemini","Perplexity"]) {
    const pr = latestRows.filter(r => r.platform === platform);
    if (pr.length) dimensions[platform] = {
      overall:     Math.round(pr.reduce((a,r)=>a+r.overallScore,0)/pr.length),
      category:    Math.round(pr.reduce((a,r)=>a+r.categoryAccuracy,0)/pr.length),
      explanation: Math.round(pr.reduce((a,r)=>a+r.explanationQuality,0)/pr.length),
      context:     Math.round(pr.reduce((a,r)=>a+r.contextRelevance,0)/pr.length),
      features:    Math.round(pr.reduce((a,r)=>a+r.featureRecognition,0)/pr.length),
    };
  }
  return { history, dimensions, latestDate };
}

// ── SCRIPT RUNNER ─────────────────────────────────────────────────────────────
function runScript(scriptName, res) {
  if (runningScripts.has(scriptName)) {
    res.writeHead(409, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
    res.end(JSON.stringify({ error: `${scriptName} already running` }));
    return;
  }
  const scripts = scriptName === "all"
    ? ["monitor.js","agent.js","publisher.js"]
    : [`${scriptName}.js`];
  res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", "Connection": "keep-alive", "Access-Control-Allow-Origin": "*" });
  const send = (msg, type="log") => res.write(`data: ${JSON.stringify({ type, msg, time: new Date().toISOString() })}\n\n`);
  runningScripts.add(scriptName);
  send(`Starting ${scriptName}...`, "info");
  let idx = 0;
  function runNext() {
    if (idx >= scripts.length) {
      send(`✅ ${scriptName} complete`, "success");
      runningScripts.delete(scriptName);
      res.write(`data: ${JSON.stringify({ type: "done" })}\n\n`);
      res.end(); return;
    }
    const script = scripts[idx++];
    send(`▶ Running ${script}`, "info");
    const proc = spawn("node", [script], { stdio: "pipe" });
    proc.stdout.on("data", d => d.toString().split("\n").filter(Boolean).forEach(l => send(l)));
    proc.stderr.on("data", d => d.toString().split("\n").filter(Boolean).forEach(l => send(l,"error")));
    proc.on("close", code => {
      if (code === 0) { send(`✅ ${script} done`, "success"); setTimeout(runNext, 2000); }
      else { send(`❌ ${script} failed`, "error"); runningScripts.delete(scriptName); res.write(`data: ${JSON.stringify({ type:"done" })}\n\n`); res.end(); }
    });
  }
  runNext();
}

// ── AUDIT HANDLER ─────────────────────────────────────────────────────────────
async function handleAudit(body, res, ip) {
  res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", "Connection": "keep-alive", "Access-Control-Allow-Origin": "*" });
  const send = (data) => res.write(`data: ${JSON.stringify(data)}\n\n`);

  try {
    const { company, url, email, firstName, audience, competitors } = body;

    if (FREE_EMAIL_DOMAINS.has(getEmailDomain(email))) {
      send({ type: "error", code: "FREE_EMAIL", msg: "Please use your work email address." });
      res.end(); return;
    }

    const rateCheck = checkRateLimit(ip);
    if (!rateCheck.allowed) {
      send({ type: "error", code: "RATE_LIMIT", msg: `You've already run an audit today. Try again in ${rateCheck.resetIn} hour(s).` });
      res.end(); return;
    }

    send({ step: 1, status: "active" });

    const Anthropic = (await import("@anthropic-ai/sdk")).default;
    const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

    const queryRes = await anthropic.messages.create({
      model: "claude-haiku-4-5-20251001", max_tokens: 500,
      messages: [{ role: "user", content:
        `Generate 7 questions a buyer would ask an AI assistant about ${company} (${url}).
Target audience: ${audience||"B2B buyers"}. Competitors: ${competitors||"unknown"}.
Return ONLY a JSON array of 7 question strings.` }],
    });

    let queries;
    try { queries = JSON.parse(queryRes.content[0].text.replace(/```json|```/g,"").trim()); }
    catch { queries = [`What is ${company}?`,`What does ${company} do?`,`Who is ${company} for?`,`What category is ${company}?`,`How is ${company} different?`,`What are ${company}'s features?`,`Who competes with ${company}?`]; }

    send({ stepDone: 1 });

    const OpenAI = (await import("openai")).default;
    const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

    const withTimeout = (promise, ms=25000) =>
      Promise.race([promise, new Promise((_,reject) => setTimeout(() => reject(new Error("Timeout after 25s")), ms))]);

    const platforms = [
      { name: "ChatGPT", step: 2, fn: async q => {
        const r = await withTimeout(openai.chat.completions.create({
          model:"gpt-4o-mini", max_tokens:200,
          messages:[{role:"user",content:q}]
        }));
        return r.choices[0].message.content;
      }},
      { name: "Claude", step: 3, fn: async q => {
        const r = await withTimeout(anthropic.messages.create({
          model:"claude-haiku-4-5-20251001", max_tokens:200,
          messages:[{role:"user",content:q}]
        }));
        return r.content[0].text;
      }},
      { name: "Gemini", step: 4, fn: async q => {
        const r = await withTimeout(fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${process.env.GOOGLE_AI_KEY}`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              contents: [{ parts: [{ text: q }] }],
              generationConfig: { maxOutputTokens: 200 }
            })
          }
        ));
        const d = await r.json();
        if (d.error) throw new Error(`Gemini API: ${d.error.message}`);
        return d.candidates?.[0]?.content?.parts?.[0]?.text || "";
      }},
      { name: "Perplexity", step: 5, fn: async q => {
        const r = await withTimeout(fetch("https://api.perplexity.ai/chat/completions",{
          method:"POST",
          headers:{
            Authorization:`Bearer ${process.env.PERPLEXITY_API_KEY}`,
            "Content-Type":"application/json"
          },
          body:JSON.stringify({
            model:"sonar",
            max_tokens:200,
            messages:[{role:"user",content:q}]
          })
        }));
        const d = await r.json();
        return d.choices[0].message.content;
      }},
    ];

    send({ step: 2, status: "active" });
    send({ step: 3, status: "active" });
    send({ step: 4, status: "active" });
    send({ step: 5, status: "active" });

    const allResults = await Promise.all(platforms.map(async platform => {
      const results = await Promise.all(queries.map(async query => {
        try { return { query, response: await platform.fn(query) }; }
        catch (e) {
          console.log(`⚠️  ${platform.name} skipped: ${e.message}`);
          return { query, response: `[Skipped: ${e.message}]` };
        }
      }));
      send({ stepDone: platform.step });
      return { platform: platform.name, results };
    }));

    send({ type: "done", results: allResults });

  } catch (e) {
    console.error("Audit error:", e.message);
    send({ type: "error", msg: e.message });
  }
  res.end();
}

// ── SERVER ────────────────────────────────────────────────────────────────────
const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const path = url.pathname;
  const ip = req.socket.remoteAddress;

  if (req.method === "POST" && path === "/api/audit") {
    let body = "";
    req.on("data", d => body += d);
    req.on("end", async () => {
      await handleAudit(JSON.parse(body), res, ip);
    });
    return;
  }

  res.writeHead(404);
  res.end();
});

loadCache();

server.listen(PORT, "0.0.0.0", () => {
  console.log(`\n🖥️  AIsubtext API Server v2.7.8`);
  console.log(`📡 http://localhost:${PORT}`);
  console.log(`🤖 Gemini model: ${GEMINI_MODEL}`);
  console.log(`⚡ Parallel querying enabled, 25s timeout per engine\n`);
});
