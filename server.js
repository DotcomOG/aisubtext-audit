// server.js - v2.8.0 — 2026-03-04
// Changes from v2.7.9:
//   - Remediation: score-based action count — score <40: 20 actions, 40-60: 15 actions, >60: 10 actions
//   - Remediation: max_tokens 2000 → 4000 (needed for 20 action objects)
//   - Remediation: added "week" and "owner" fields per action for Full Implementation Plan differentiation
// All other logic identical to v2.7.9.

import { createServer } from "http";
import { readFileSync, existsSync, writeFileSync, mkdirSync } from "fs";
import { spawn } from "child_process";
import * as dotenv from "dotenv";
dotenv.config();

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
const RATE_MAX = 1000; // effectively disabled — set to 1 to re-enable for public
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

    // Cache lookup DISABLED — always run fresh audit
    // const domain = getDomain(url);
    // const cached = getCachedAudit(domain);
    // if (cached) { send({ type: "done", ... }); res.end(); return; }

    send({ step: 1, status: "active" });

    const Anthropic = (await import("@anthropic-ai/sdk")).default;
    const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

    const queryRes = await anthropic.messages.create({
      model: "claude-haiku-4-5-20251001", max_tokens: 500,
      messages: [{ role: "user", content:
        `Generate 7 questions a buyer would ask an AI assistant about ${company} (${url}).
Target audience: ${audience||"B2B buyers"}. Competitors: ${competitors||"unknown"}.
Return ONLY a JSON array of 7 question strings, no markdown, no explanation.` }],
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
      { name: "ChatGPT",    step: 2, fn: async q => { const r = await withTimeout(openai.chat.completions.create({ model:"gpt-4o-mini", max_tokens:200, messages:[{role:"user",content:q}] })); return r.choices[0].message.content; } },
      { name: "Claude",     step: 3, fn: async q => { const r = await withTimeout(anthropic.messages.create({ model:"claude-haiku-4-5-20251001", max_tokens:200, messages:[{role:"user",content:q}] })); return r.content[0].text; } },
      { name: "Gemini",     step: 4, fn: async q => { const r = await withTimeout(fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${process.env.GOOGLE_AI_KEY}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ contents: [{ parts: [{ text: q }] }], generationConfig: { maxOutputTokens: 200 } })
        }));
        const d = await r.json();
        if (d.error) throw new Error(`Gemini API: ${d.error.message}`);
        return d.candidates[0].content.parts[0].text;
      } },
      { name: "Perplexity", step: 5, fn: async q => { const r = await withTimeout(fetch("https://api.perplexity.ai/chat/completions",{method:"POST",headers:{Authorization:`Bearer ${process.env.PERPLEXITY_API_KEY}`,"Content-Type":"application/json"},body:JSON.stringify({model:"sonar",max_tokens:200,messages:[{role:"user",content:q}]})})); const d = await r.json(); return d.choices[0].message.content; } },
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

    send({ step: 6, status: "active" });

    // ── SKIP DETECTION ────────────────────────────────────────────────────────
    const isSkipped = (response) => response.startsWith("[Skipped:");

    const validResults = allResults.filter(p =>
      p.results.some(r => !isSkipped(r.response))
    );
    const skippedPlatforms = allResults
      .filter(p => p.results.every(r => isSkipped(r.response)))
      .map(p => p.platform);

    if (skippedPlatforms.length > 0) {
      console.log(`⚠️  Platforms fully skipped: ${skippedPlatforms.join(", ")}`);
    }

    const skippedNote = skippedPlatforms.length
      ? `\nNOTE: The following platforms had complete API failures — set score to null and keyGap to "Service unavailable during audit", do NOT fabricate scores: ${skippedPlatforms.join(", ")}`
      : "";

    // ── SCORING — strict buyer-decision rubric ────────────────────────────────
    const scoreRes = await withClaudeRetry(() => anthropic.messages.create({
      model: "claude-haiku-4-5-20251001", max_tokens: 800,
      messages: [{ role: "user", content:
        `You are a strict B2B buyer evaluating whether AI engine responses would help you make a purchase decision about ${company} (${url}). Audience: ${audience||"B2B buyers"}.${skippedNote}

Score each platform 0-100 using this STRICT rubric. Be a harsh grader — most brands should score 20-55. Only score above 70 if ALL criteria are clearly met.

DEDUCT points heavily for:
- Generic category description with no real differentiation (-20 pts)
- Missing specific features or use cases for ${audience||"B2B buyers"} (-15 pts)
- No mention of who this product is specifically for (-15 pts)
- Competitors not named or incorrectly positioned (-10 pts)
- No pricing tier, company size fit, or proof points (-10 pts)
- Response could apply to ANY competitor in the space (-20 pts)
- No clear reason to choose this over alternatives (-10 pts)

Only award scores above 60 if the response names specific differentiating features, correctly identifies the target buyer, and accurately positions vs named competitors.

Results:
${validResults.map(p=>`${p.platform}:\n${p.results.filter(r=>!isSkipped(r.response)).map(r=>`Q:${r.query}\nA:${r.response.substring(0,150)}`).join("\n")}`).join("\n---\n")}

Calculate overall as average of non-null scores only.
KEY GAP RULE: Each keyGap must be 10 words or fewer. One sharp phrase only. Examples: "No differentiators mentioned", "Confused with competitors", "Generic category description only", "Refuses to answer".
TOP RECOMMENDATION RULE: Maximum 2 sentences. First sentence: the single most important fix. Second sentence: why it matters.
Return ONLY valid JSON: {"overall":0,"platforms":{"ChatGPT":{"score":0,"keyGap":""},"Claude":{"score":0,"keyGap":""},"Gemini":{"score":0,"keyGap":""},"Perplexity":{"score":0,"keyGap":""}},"topRecommendation":""}` }],
    }));

    let scores;
    try { scores = JSON.parse(scoreRes.content[0].text.replace(/```json|```/g,"").trim()); }
    catch { scores = { overall: 0, platforms: {}, topRecommendation: "Create an AI Brand Page" }; }

    // Force-null skipped platforms regardless of scorer output
    for (const p of skippedPlatforms) {
      if (scores.platforms[p] !== undefined) {
        scores.platforms[p] = { score: null, keyGap: "Service unavailable during audit" };
      }
    }

    // Recalculate overall from non-null scores only
    const scoredPlatforms = Object.values(scores.platforms).filter(p => p.score !== null && p.score !== undefined);
    if (scoredPlatforms.length > 0) {
      scores.overall = Math.round(scoredPlatforms.reduce((a, p) => a + p.score, 0) / scoredPlatforms.length);
    }

    // Cache saving DISABLED — do not store results
    // auditCache.set(domain, { result: { score: scores.overall, scores }, timestamp: Date.now(), company });
    // saveCache();

    send({ stepDone: 6 });
    send({ type: "done", score: scores.overall, scores });

    sendAuditEmail({ firstName, email, company, url, scores }).catch(e => console.error("Email error:", e.message));

  } catch (e) {
    console.error("Audit error:", e.message);
    send({ type: "error", msg: e.message });
  }
  res.end();
}

// ── EMAIL ─────────────────────────────────────────────────────────────────────
async function sendAuditEmail({ firstName, email, company, url, scores }) {
  try {
    const overall = scores.overall || 0;
    const platforms = scores.platforms || {};
    const color = (n) => n >= 70 ? "#00c896" : n >= 40 ? "#ffcc00" : "#ff4d1c";
    const platformRows = ["ChatGPT","Claude","Gemini","Perplexity"].map(p => {
      const d = platforms[p] || {};
      const sc = d.score;
      const scoreDisplay = (sc !== null && sc !== undefined) ? `${sc}/100` : "N/A";
      const scoreColor = (sc !== null && sc !== undefined) ? color(sc) : "#aaaaaa";
      return `<tr>
        <td style="font-family:'DM Mono',monospace;font-size:12px;padding:10px 16px;border-bottom:1px solid #1a1a1a;color:#ffffff;text-transform:uppercase;letter-spacing:0.1em;">${p}</td>
        <td style="font-family:'Bebas Neue',Impact,sans-serif;font-size:22px;padding:10px 16px;border-bottom:1px solid #1a1a1a;color:${scoreColor};text-align:right;">${scoreDisplay}</td>
        <td style="font-family:'DM Mono',monospace;font-size:11px;padding:10px 16px;border-bottom:1px solid #1a1a1a;color:#aaaaaa;">${d.keyGap || "—"}</td>
      </tr>`;
    }).join("");

    const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#080808;font-family:'DM Sans',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#080808;padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:#080808;border:1px solid #1a1a1a;">
        <tr><td style="padding:32px 40px;border-bottom:1px solid #1a1a1a;">
          <div style="font-family:Impact,sans-serif;font-size:28px;letter-spacing:3px;color:#f5f2eb;">AI<span style="color:#ff4d1c;">subtext</span></div>
          <div style="font-family:'DM Mono',monospace;font-size:11px;color:#aaaaaa;letter-spacing:2px;text-transform:uppercase;margin-top:6px;">AEO Audit Report</div>
        </td></tr>
        <tr><td style="padding:40px;border-bottom:1px solid #1a1a1a;background:#0d0d0d;">
          <div style="font-family:'DM Mono',monospace;font-size:11px;color:#ffffff;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px;">${company.toUpperCase()}</div>
          <div style="font-family:Impact,sans-serif;font-size:72px;color:${color(overall)};line-height:1;margin-bottom:4px;">${overall}</div>
          <div style="font-family:'DM Mono',monospace;font-size:11px;color:#ffffff;letter-spacing:2px;text-transform:uppercase;">Composite AEO Score / 100</div>
        </td></tr>
        <tr><td style="padding:32px 40px;border-bottom:1px solid #1a1a1a;">
          <div style="font-family:'DM Mono',monospace;font-size:11px;color:#ffffff;letter-spacing:2px;text-transform:uppercase;margin-bottom:16px;">Scores By Engine</div>
          <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #1a1a1a;">
            <tr style="background:#111;">
              <td style="font-family:'DM Mono',monospace;font-size:10px;padding:8px 16px;color:#aaaaaa;letter-spacing:1px;text-transform:uppercase;">Engine</td>
              <td style="font-family:'DM Mono',monospace;font-size:10px;padding:8px 16px;color:#aaaaaa;letter-spacing:1px;text-transform:uppercase;text-align:right;">Score</td>
              <td style="font-family:'DM Mono',monospace;font-size:10px;padding:8px 16px;color:#aaaaaa;letter-spacing:1px;text-transform:uppercase;">Key Gap</td>
            </tr>
            ${platformRows}
          </table>
        </td></tr>
        ${scores.topRecommendation ? `<tr><td style="padding:32px 40px;border-bottom:1px solid #1a1a1a;">
          <div style="font-family:'DM Mono',monospace;font-size:11px;color:#ff4d1c;letter-spacing:2px;text-transform:uppercase;margin-bottom:10px;">Top Recommendation</div>
          <div style="font-size:15px;color:#f5f2eb;line-height:1.7;">${scores.topRecommendation}</div>
        </td></tr>` : ""}
        <tr><td style="padding:40px;text-align:center;">
          <div style="font-size:15px;color:#f5f2eb;margin-bottom:24px;">Ready to improve your AEO score and outrank competitors in AI?</div>
          <a href="https://aisubtext.ai#pricing" style="display:inline-block;background:#ff4d1c;color:#080808;font-family:'DM Mono',monospace;font-size:12px;font-weight:600;letter-spacing:2px;text-transform:uppercase;padding:14px 32px;text-decoration:none;">Get Full Fix Plan →</a>
        </td></tr>
        <tr><td style="padding:24px 40px;border-top:1px solid #1a1a1a;text-align:center;">
          <div style="font-family:'DM Mono',monospace;font-size:11px;color:#aaaaaa;">AIsubtext · The AEO Benchmark Platform</div>
          <div style="font-family:'DM Mono',monospace;font-size:10px;color:#555555;margin-top:6px;">© 2026 AIsubtext · A Quontora product · aisubtext.ai</div>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;

    // EMAIL PAUSED
    // const result = await resend.emails.send({
    //   from: "AIsubtext <audit@aisubtext.ai>",
    //   to: email,
    //   subject: `Your AEO Audit: ${company} scored ${overall}/100`,
    //   html,
    // });
    // console.log(`📧 Resend result:`, JSON.stringify(result));
    console.log(`📧 Email paused - skipping send to ${email}`);
  } catch (e) {
    console.error("Email send failed:", e.message);
  }
}

// ── HTTP SERVER ───────────────────────────────────────────────────────────────
const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const path = url.pathname;
  const ip = getClientIP(req);

  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }

  if (path === "/api/status") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "running", running: [...runningScripts], cachedAudits: auditCache.size, time: new Date().toISOString() }));
    return;
  }

  if (path === "/api/scores") {
    try {
      const rows = parseCSV("./results/monitor-results.csv");
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(aggregateScores(rows)));
    } catch (e) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (path === "/api/corrections") {
    try {
      if (!existsSync("./results/proposed-updates.md")) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ corrections: [] })); return;
      }
      const content = readFileSync("./results/proposed-updates.md", "utf8");
      const corrections = [];
      const sections = content.split("---").filter(s => s.includes("Proposed addition"));
      for (const section of sections) {
        const headerMatch = section.match(/###\s+\d+\.\s+(.+?)\n/);
        const contentMatch = section.match(/>\s*(.+?)(?=\n- \[)/s);
        const gapMatch = section.match(/\*\*Gap:\*\*\s*(.+?)(?=\n)/);
        const approved = /\[X\]|\[x\]/i.test(section.match(/- \[.?\] Approve/)?.[0]||"");
        const rejected = /\[X\]|\[x\]/i.test(section.match(/- \[.?\] Reject/)?.[0]||"");
        if (headerMatch && contentMatch) {
          const parts = headerMatch[1].split("·").map(s=>s.trim());
          corrections.push({ platform:parts[0]||"", question:(parts[1]||"").replace(/^"|"$/g,""), score:parseInt((parts[2]||"0").replace(/\D/g,""))||0, content:contentMatch[1].trim(), gap:gapMatch?gapMatch[1].trim():"", status:approved?"approved":rejected?"rejected":"pending" });
        }
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ corrections }));
    } catch (e) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (req.method === "POST" && path.startsWith("/api/run/")) {
    const script = path.replace("/api/run/","");
    if (!["monitor","agent","publisher","all"].includes(script)) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Unknown script" })); return;
    }
    runScript(script, res); return;
  }

  if (req.method === "POST" && path === "/api/audit") {
    let body = "";
    req.on("data", d => body += d);
    req.on("end", async () => {
      try { await handleAudit(JSON.parse(body), res, ip); }
      catch (e) { res.writeHead(400); res.end(JSON.stringify({ error: e.message })); }
    });
    return;
  }

  if (req.method === "POST" && path === "/api/competitors") {
    let body = "";
    req.on("data", d => body += d);
    req.on("end", async () => {
      try {
        console.log("🔍 Competitors request received");
        const { url: targetUrl, company } = JSON.parse(body);
        const Anthropic = (await import("@anthropic-ai/sdk")).default;
        const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
        let siteContent = "";
        try {
          const siteRes = await fetch(targetUrl, { signal: AbortSignal.timeout(8000), headers: { "User-Agent": "Mozilla/5.0" } });
          const html = await siteRes.text();
          siteContent = html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").substring(0, 3000);
        } catch (e) { siteContent = `Company: ${company}, URL: ${targetUrl}`; }
        const aiRes = await withClaudeRetry(() => anthropic.messages.create({
          model: "claude-haiku-4-5-20251001", max_tokens: 300,
          messages: [{ role: "user", content:
            `Based on this website content for ${company} (${targetUrl}), identify their top 4-6 competitors.
Website text: "${siteContent}"
Return ONLY valid JSON: {"competitors":["Competitor A","Competitor B"],"audience":"one sentence description of target audience"}
No markdown, no explanation.` }],
        }));
        let data;
        try { data = JSON.parse(aiRes.content[0].text.replace(/```json|```/g,"").trim()); }
        catch { data = { competitors: [], audience: "" }; }
        res.writeHead(200, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
        res.end(JSON.stringify(data));
      } catch (e) {
        res.writeHead(500, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
        res.end(JSON.stringify({ error: e.message, competitors: [], audience: "" }));
      }
    });
    return;
  }

  if (req.method === "POST" && path === "/api/remediation") {
    let body = "";
    req.on("data", d => body += d);
    req.on("end", async () => {
      try {
        const { company, url: targetUrl, audience, scores } = JSON.parse(body);
        if (!company || !scores) {
          res.writeHead(400, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
          res.end(JSON.stringify({ error: "company and scores required" })); return;
        }
        const Anthropic = (await import("@anthropic-ai/sdk")).default;
        const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
        const platforms = scores.platforms || {};
        const gapSummary = ["ChatGPT","Claude","Gemini","Perplexity"]
          .map(p => {
            const d = platforms[p] || {};
            if (d.score === null || d.score === undefined) return null;
            return d.keyGap ? `${p} (score ${d.score}/100): ${d.keyGap}` : null;
          })
          .filter(Boolean).join("\n");

        // v2.8.0: score-based action count
        const overall = scores.overall || 0;
        const actionCount = overall < 40 ? 20 : overall <= 60 ? 15 : 10;

        const briefRes = await anthropic.messages.create({
          model: "claude-haiku-4-5-20251001", max_tokens: 4000, // v2.8.0: was 2000, increased for up to 20 actions
          messages: [{ role: "user", content:
            `You are an AEO (Answer Engine Optimization) strategist. A brand just completed an AI visibility audit.

Brand: ${company}
Website: ${targetUrl}
Audience: ${audience || "B2B buyers"}
Composite AEO Score: ${overall}/100
Top Recommendation from audit: ${scores.topRecommendation || "none"}

Per-engine gaps:
${gapSummary || "No gap data available"}

Generate a prioritized remediation content brief with exactly ${actionCount} actions. Each action must be concrete, specific to this brand, and immediately actionable. A score below 40 means critical gaps across multiple engines — all ${actionCount} slots must be filled with distinct, meaningful fixes spanning content creation, schema markup, PR/authority, competitive positioning, and social proof. Do not repeat action types unless targeting different engines or audiences.

Return ONLY valid JSON — no markdown, no explanation:
{
  "estimatedScoreGain": <integer 5-50>,
  "briefSummary": "<one sentence summary of the core problem>",
  "priorityActions": [
    {
      "rank": 1,
      "type": "<one of: FAQ Page | Schema Markup | Wikipedia Citation | Brand Definition Page | Competitor Comparison Page | Press Coverage | LinkedIn Authority Post | AI Brand Page | Case Study | Thought Leadership Article | G2 / Review Profile | Podcast Appearance | Partner Co-Marketing | Data/Research Report | Video Explainer | Customer Testimonial Page | Industry Awards Submission | Reddit / Forum Presence | Newsletter Feature | Product Hunt Launch>",
      "title": "<specific page/content title tailored to ${company}>",
      "why": "<one sentence: which engines are confused about what, and why this specific action fixes it>",
      "effort": "<Low | Medium | High>",
      "impact": "<Low | Medium | High>",
      "week": "<Week 1 | Week 2 | Week 3-4 | Week 5-8 | Week 9-12>",
      "owner": "<Content Team | Dev/SEO Team | PR Team | Executive | Marketing Ops>",
      "quickWin": <true if effort Low and impact High, else false>
    }
  ]
}` }],
        });
        let brief;
        try { brief = JSON.parse(briefRes.content[0].text.replace(/```json|```/g,"").trim()); }
        catch {
          brief = {
            estimatedScoreGain: 10,
            briefSummary: "AI engines lack sufficient brand context to represent this company accurately.",
            priorityActions: [
              { rank: 1, type: "FAQ Page", title: `${company} — Frequently Asked Questions`, why: "AI engines defaulting to generic descriptions due to lack of structured Q&A content.", effort: "Low", impact: "High", quickWin: true },
              { rank: 2, type: "Brand Definition Page", title: `What is ${company}?`, why: "No authoritative definition page for AI crawlers to index.", effort: "Low", impact: "High", quickWin: true },
              { rank: 3, type: "Schema Markup", title: "Organization + Product schema on homepage", why: "Missing structured data prevents AI engines from extracting key facts.", effort: "Medium", impact: "High", quickWin: false },
              { rank: 4, type: "Competitor Comparison Page", title: `${company} vs Competitors`, why: "AI engines unable to accurately position brand in competitive landscape.", effort: "Medium", impact: "Medium", quickWin: false },
              { rank: 5, type: "Wikipedia Citation", title: "Third-party citation in relevant Wikipedia articles", why: "No authoritative external references for AI engines to cite.", effort: "High", impact: "High", quickWin: false },
              { rank: 6, type: "Press Coverage", title: `${company} — Industry Press Announcement`, why: "No third-party validation signals for AI engines to reference.", effort: "High", impact: "High", quickWin: false },
              { rank: 7, type: "Case Study", title: `${company} Customer Success Story`, why: "No proof points or outcomes for AI engines to surface to buyers.", effort: "Medium", impact: "High", quickWin: false },
              { rank: 8, type: "LinkedIn Authority Post", title: `${company} Sector Leadership Series`, why: "Low recency signals causing AI engines to default to stale descriptions.", effort: "Low", impact: "Medium", quickWin: false },
              { rank: 9, type: "AI Brand Page", title: `About ${company} — AI-Optimized Brand Page`, why: "No structured brand page optimized for AI engine retrieval.", effort: "Low", impact: "High", quickWin: true },
              { rank: 10, type: "Thought Leadership Article", title: `${company}'s Perspective on Industry Trends`, why: "No thought leadership content for AI engines to associate with brand authority.", effort: "Medium", impact: "Medium", quickWin: false }
            ]
          };
        }
        try {
          const { appendFileSync, existsSync: fsExists, mkdirSync: fsMkdir } = await import("fs");
          if (!fsExists("./results")) fsMkdir("./results", { recursive: true });
          const row = `"${new Date().toISOString()}","${company}","${targetUrl}","${scores.overall || 0}","${brief.estimatedScoreGain}"\n`;
          if (!fsExists("./results/remediation-requests.csv")) appendFileSync("./results/remediation-requests.csv", "Timestamp,Company,URL,AuditScore,EstimatedGain\n");
          appendFileSync("./results/remediation-requests.csv", row);
          console.log(`🤖 Remediation brief generated: ${company} | score:${scores.overall} | est. gain:+${brief.estimatedScoreGain}`);
        } catch (logErr) { console.log("Remediation log error:", logErr.message); }
        res.writeHead(200, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
        res.end(JSON.stringify(brief));
      } catch (e) {
        console.error("Remediation error:", e.message);
        res.writeHead(500, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  if (req.method === "POST" && path === "/api/claim") {
    let body = "";
    req.on("data", d => body += d);
    req.on("end", async () => {
      try {
        const { email, company, domain, score, source } = JSON.parse(body);
        if (!email || !company) { res.writeHead(400); res.end(JSON.stringify({ error: "email and company required" })); return; }
        const { appendFileSync, existsSync: fsExists, mkdirSync: fsMkdir } = await import("fs");
        if (!fsExists("./results")) fsMkdir("./results", { recursive: true });
        const row = `"${new Date().toISOString()}","${email}","${company}","${domain}","${score}","${source||'index'}"\n`;
        if (!fsExists("./results/leads.csv")) appendFileSync("./results/leads.csv", "Timestamp,Email,Company,Domain,Score,Source\n");
        appendFileSync("./results/leads.csv", row);
        console.log(`📩 New lead: ${email} | ${company} | score:${score}`);
        res.writeHead(200, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
        res.end(JSON.stringify({ ok: true }));
      } catch (e) {
        res.writeHead(500, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  if (req.method === "POST" && path === "/api/quickscan") {
    let body = "";
    req.on("data", d => body += d);
    req.on("end", async () => {
      try {
        const { company, url: targetUrl } = JSON.parse(body);
        if (!company || !targetUrl) { res.writeHead(400); res.end(JSON.stringify({ error: "company and url required" })); return; }
        const domain = getDomain(targetUrl);
        const cached = getCachedAudit(domain);
        if (cached) {
          res.writeHead(200, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
          res.end(JSON.stringify({ score: cached.result.score, cached: true, cachedAt: new Date(cached.timestamp).toLocaleDateString() }));
          return;
        }
        const OpenAI = (await import("openai")).default;
        const Anthropic = (await import("@anthropic-ai/sdk")).default;
        const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
        const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
        const questions = [
          `What is ${company} and what does it do?`,
          `Who is ${company} designed for and what problem does it solve?`,
        ];
        const [chatgptResults, perplexityResults] = await Promise.all([
          Promise.all(questions.map(async q => {
            try { const r = await openai.chat.completions.create({ model: "gpt-4o-mini", max_tokens: 200, messages: [{ role: "user", content: q }] }); return r.choices[0].message.content; }
            catch (e) { return `ERROR: ${e.message}`; }
          })),
          Promise.all(questions.map(async q => {
            try {
              const r = await fetch("https://api.perplexity.ai/chat/completions", { method: "POST", headers: { Authorization: `Bearer ${process.env.PERPLEXITY_API_KEY}`, "Content-Type": "application/json" }, body: JSON.stringify({ model: "sonar", max_tokens: 200, messages: [{ role: "user", content: q }] }) });
              const d = await r.json(); return d.choices[0].message.content;
            } catch (e) { return `ERROR: ${e.message}`; }
          })),
        ]);
        const scoreRes = await anthropic.messages.create({
          model: "claude-haiku-4-5-20251001", max_tokens: 300,
          messages: [{ role: "user", content:
            `Score AI brand accuracy for ${company} (${targetUrl}).
ChatGPT responses: ${chatgptResults.map((r,i) => `Q${i+1}: ${r.substring(0,100)}`).join(" | ")}
Perplexity responses: ${perplexityResults.map((r,i) => `Q${i+1}: ${r.substring(0,100)}`).join(" | ")}
Return ONLY valid JSON: {"score":0,"chatgpt":0,"perplexity":0,"topGap":"one sentence","visibility":"low|medium|high"}` }],
        });
        let scores;
        try { scores = JSON.parse(scoreRes.content[0].text.replace(/```json|```/g,"").trim()); }
        catch { scores = { score: 0, chatgpt: 0, perplexity: 0, topGap: "Unable to score", visibility: "low" }; }
        auditCache.set(domain, { result: { score: scores.score, scores }, timestamp: Date.now(), company });
        saveCache();
        res.writeHead(200, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
        res.end(JSON.stringify({ ...scores, cached: false }));
      } catch (e) {
        res.writeHead(500, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
        res.end(JSON.stringify({ error: e.message, score: 0 }));
      }
    });
    return;
  }

  if (path === "/api/gemini-models") {
    const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${process.env.GOOGLE_AI_KEY}`);
    const d = await r.json();
    res.writeHead(200, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
    res.end(JSON.stringify(d));
    return;
  }

  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
});

loadCache();
server.listen(PORT, "0.0.0.0", () => {
  console.log(`\n🖥️  AIsubtext API Server v2.8.0`);
  console.log(`📡 http://localhost:${PORT}`);
  console.log(`🛡️  Protections: free email blocking, rate limiting disabled`);
  console.log(`🚫 Audit cache: DISABLED (every report runs fresh)`);
  console.log(`⚡ Parallel querying enabled, 25s timeout per engine`);
  console.log(`🤖 Gemini: gemini-2.5-flash (direct fetch)`);
  console.log(`📊 Scoring: strict buyer-decision rubric (20-55 expected range)`);
  console.log(`📋 Remediation: score-based actions (<40→20, 40-60→15, >60→10), max_tokens 4000`);
  console.log(`\nEndpoints:`);
  console.log(`  GET  /api/status`);
  console.log(`  GET  /api/scores`);
  console.log(`  GET  /api/corrections`);
  console.log(`  POST /api/run/:script`);
  console.log(`  POST /api/audit`);
  console.log(`  POST /api/quickscan`);
  console.log(`  POST /api/claim`);
  console.log(`  POST /api/competitors`);
  console.log(`  POST /api/remediation\n`);
});
