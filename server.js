// server.js - v3.1.0 — 2026-03-11
// Changes from v3.0.1:
// - Adds two-layer reporting: user_report + internal_report
// - Adds model_versions, run_type, status to audit_cache
// - Prevents quickscan from overwriting full audit records
// - Returns user-facing report publicly, stores full remediation report privately
// - Keeps PostgreSQL as persistent storage

import { createServer } from "http";
import { existsSync, readFileSync } from "fs";
import { spawn } from "child_process";
import * as dotenv from "dotenv";
import pg from "pg";

dotenv.config();

const PORT = process.env.PORT || 3000;
const runningScripts = new Set();

const { Pool } = pg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("railway")
    ? { rejectUnauthorized: false }
    : false,
});

// ── DB INIT ───────────────────────────────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS audit_cache (
      domain TEXT PRIMARY KEY,
      company TEXT,
      email TEXT DEFAULT '',
      first_name TEXT DEFAULT '',
      audience TEXT DEFAULT '',
      competitors TEXT DEFAULT '',
      overall_score INTEGER DEFAULT 0,
      scores JSONB,
      queries JSONB,
      responses JSONB,
      user_report JSONB,
      internal_report JSONB,
      model_versions JSONB,
      run_type TEXT DEFAULT 'full',
      status TEXT DEFAULT 'complete',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS leads (
      id SERIAL PRIMARY KEY,
      email TEXT,
      company TEXT,
      domain TEXT,
      score INTEGER DEFAULT 0,
      source TEXT DEFAULT 'audit',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  const migrationQueries = [
    `ALTER TABLE audit_cache ADD COLUMN IF NOT EXISTS user_report JSONB;`,
    `ALTER TABLE audit_cache ADD COLUMN IF NOT EXISTS internal_report JSONB;`,
    `ALTER TABLE audit_cache ADD COLUMN IF NOT EXISTS model_versions JSONB;`,
    `ALTER TABLE audit_cache ADD COLUMN IF NOT EXISTS run_type TEXT DEFAULT 'full';`,
    `ALTER TABLE audit_cache ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'complete';`,
  ];

  for (const q of migrationQueries) {
    try {
      await pool.query(q);
    } catch (e) {
      console.log("Migration warning:", e.message);
    }
  }

  console.log("✅ Database tables ready");
}
// ── DB HELPERS ────────────────────────────────────────────────────────────────
async function getCachedAudit(domain) {
  try {
    const res = await pool.query("SELECT * FROM audit_cache WHERE domain = $1", [domain]);
    if (!res.rows.length) return null;

    const row = res.rows[0];
    const age = Date.now() - new Date(row.updated_at).getTime();

    // 7-day TTL
    if (age > 7 * 24 * 60 * 60 * 1000) {
      await pool.query("DELETE FROM audit_cache WHERE domain = $1", [domain]);
      return null;
    }

    return row;
  } catch (e) {
    console.log("getCachedAudit error:", e.message);
    return null;
  }
}

async function saveAuditCache(domain, data) {
  try {
    await pool.query(
      `
      INSERT INTO audit_cache (
        domain, company, email, first_name, audience, competitors,
        overall_score, scores, queries, responses,
        user_report, internal_report, model_versions, run_type, status, updated_at
      )
      VALUES (
        $1,$2,$3,$4,$5,$6,
        $7,$8,$9,$10,
        $11,$12,$13,$14,$15,NOW()
      )
      ON CONFLICT (domain) DO UPDATE SET
        company = EXCLUDED.company,
        email = EXCLUDED.email,
        first_name = EXCLUDED.first_name,
        audience = EXCLUDED.audience,
        competitors = EXCLUDED.competitors,
        overall_score = EXCLUDED.overall_score,
        scores = EXCLUDED.scores,
        queries = EXCLUDED.queries,
        responses = EXCLUDED.responses,
        user_report = EXCLUDED.user_report,
        internal_report = EXCLUDED.internal_report,
        model_versions = EXCLUDED.model_versions,
        run_type = EXCLUDED.run_type,
        status = EXCLUDED.status,
        updated_at = NOW()
      `,
      [
        domain,
        data.company || "",
        data.email || "",
        data.firstName || "",
        data.audience || "",
        data.competitors || "",
        data.overallScore || 0,
        JSON.stringify(data.scores || {}),
        JSON.stringify(data.queries || []),
        JSON.stringify(data.responses || []),
        JSON.stringify(data.userReport || {}),
        JSON.stringify(data.internalReport || {}),
        JSON.stringify(data.modelVersions || {}),
        data.runType || "full",
        data.status || "complete",
      ]
    );
  } catch (e) {
    console.log("saveAuditCache error:", e.message);
  }
}

async function saveLead(email, company, domain, score, source) {
  try {
    await pool.query(
      "INSERT INTO leads (email, company, domain, score, source) VALUES ($1,$2,$3,$4,$5)",
      [email, company, domain, score || 0, source || "audit"]
    );
  } catch (e) {
    console.log("saveLead error:", e.message);
  }
}

async function getLeadByDomain(domain) {
  try {
    const res = await pool.query(
      "SELECT * FROM leads WHERE domain = $1 ORDER BY created_at DESC LIMIT 1",
      [domain]
    );
    return res.rows[0] || null;
  } catch {
    return null;
  }
}

async function getAllSubmissions() {
  try {
    const cacheRes = await pool.query("SELECT * FROM audit_cache ORDER BY updated_at DESC");
    const leadsRes = await pool.query("SELECT * FROM leads");

    const leadsMap = {};
    for (const lead of leadsRes.rows) {
      if (!leadsMap[lead.domain]) leadsMap[lead.domain] = lead;
    }

    return cacheRes.rows.map((row) => {
      const lead = leadsMap[row.domain] || {};
      const scores = row.scores || {};
      const userReport = row.user_report || {};
      const internalReport = row.internal_report || {};

      return {
        id: row.domain,
        company: row.company || lead.company || row.domain,
        domain: row.domain,
        overallScore: row.overall_score || 0,
        timestamp: new Date(row.updated_at).getTime(),
        scannedAt: row.updated_at,
        email: row.email || lead.email || "",
        firstName: row.first_name || "",
        audience: row.audience || "",
        competitors: row.competitors || "",
        source: lead.source || "audit",
        runType: row.run_type || "full",
        status: row.status || "complete",
        platforms: scores.platforms || {},
        topRecommendation: scores.topRecommendation || userReport.topRecommendation || "",
        userSummary: userReport.summary || "",
        internalPriority: internalReport.priority || "",
        hasContact: !!(row.email || lead.email),
        userReport,
        internalReport,
        responses: row.responses || null,
        queries: row.queries || null,
        modelVersions: row.model_versions || {},
      };
    });
  } catch (e) {
    console.log("getAllSubmissions error:", e.message);
    return [];
  }
}

async function getSingleSubmission(domain) {
  try {
    const row = (await pool.query("SELECT * FROM audit_cache WHERE domain = $1", [domain])).rows[0];
    if (!row) return null;

    const lead = await getLeadByDomain(domain);
    const scores = row.scores || {};

    return {
      company: row.company || lead?.company || domain,
      domain: row.domain,
      email: row.email || lead?.email || "",
      firstName: row.first_name || "",
      audience: row.audience || "",
      competitors: row.competitors || "",
      source: lead?.source || "audit",
      timestamp: new Date(row.updated_at).getTime(),
      overallScore: row.overall_score || 0,
      runType: row.run_type || "full",
      status: row.status || "complete",
      platforms: scores.platforms || {},
      topRecommendation: scores.topRecommendation || "",
      userReport: row.user_report || {},
      internalReport: row.internal_report || {},
      modelVersions: row.model_versions || {},
      queries: row.queries || [],
      responses: row.responses || [],
      hasContact: !!(row.email || lead?.email),
    };
  } catch (e) {
    console.log("getSingleSubmission error:", e.message);
    return null;
  }
}

// ── PROTECTION LAYER ──────────────────────────────────────────────────────────
const FREE_EMAIL_DOMAINS = new Set([
  "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
  "icloud.com", "mail.com", "protonmail.com", "zoho.com", "yandex.com",
  "live.com", "msn.com", "me.com", "mac.com", "inbox.com", "gmx.com",
  "fastmail.com", "tutanota.com", "guerrillamail.com", "mailinator.com",
  "tempmail.com", "throwaway.email", "sharklasers.com", "yopmail.com"
]);

const ipRateLimit = new Map();
const RATE_WINDOW_MS = 24 * 60 * 60 * 1000;
const RATE_MAX = 1;

function getEmailDomain(email) {
  return (email || "").split("@")[1]?.toLowerCase() || "";
}

function getClientIP(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.socket?.remoteAddress ||
    "unknown"
  );
}

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = ipRateLimit.get(ip);

  if (!entry || now - entry.windowStart > RATE_WINDOW_MS) {
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

function getDomain(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
}

// ── CSV PARSER (monitor-results.csv only — still file-based) ─────────────────
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
          if (raw[i] === '"' && raw[i + 1] === '"') {
            field += '"';
            i += 2;
          } else if (raw[i] === '"') {
            i++;
            break;
          } else {
            field += raw[i++];
          }
        }
        cols.push(field);
      } else {
        let field = "";
        while (i < raw.length && raw[i] !== "," && raw[i] !== "\n") field += raw[i++];
        cols.push(field.trim());
      }

      if (i < raw.length && raw[i] === ",") i++;
      else {
        if (i < raw.length && raw[i] === "\n") i++;
        break;
      }
    }

    if (cols.length >= 10 && cols[0]?.includes("202")) {
      rows.push({
        timestamp: cols[0],
        brand: cols[1],
        platform: cols[2],
        question: cols[3],
        response: cols[4],
        categoryAccuracy: parseInt(cols[5]) || 0,
        explanationQuality: parseInt(cols[6]) || 0,
        contextRelevance: parseInt(cols[7]) || 0,
        featureRecognition: parseInt(cols[8]) || 0,
        overallScore: parseInt(cols[9]) || 0,
        keyGaps: cols[10] || "",
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
    for (const [p, platformRows] of Object.entries(platforms)) {
      entry[p] = Math.round(
        platformRows.reduce((a, r) => a + r.overallScore, 0) / platformRows.length
      );
    }
    return entry;
  });

  const latestDate = Object.keys(byDate).sort().reverse()[0];
  const latestRows = latestDate
    ? rows.filter((r) => r.timestamp.substring(0, 10) === latestDate)
    : [];

  const dimensions = {};
  for (const platform of ["ChatGPT", "Claude", "Gemini", "Perplexity"]) {
    const pr = latestRows.filter((r) => r.platform === platform);
    if (pr.length) {
      dimensions[platform] = {
        overall: Math.round(pr.reduce((a, r) => a + r.overallScore, 0) / pr.length),
        category: Math.round(pr.reduce((a, r) => a + r.categoryAccuracy, 0) / pr.length),
        explanation: Math.round(pr.reduce((a, r) => a + r.explanationQuality, 0) / pr.length),
        context: Math.round(pr.reduce((a, r) => a + r.contextRelevance, 0) / pr.length),
        features: Math.round(pr.reduce((a, r) => a + r.featureRecognition, 0) / pr.length),
      };
    }
  }

  return { history, dimensions, latestDate };
}

// ── SCRIPT RUNNER ─────────────────────────────────────────────────────────────
function runScript(scriptName, res) {
  if (runningScripts.has(scriptName)) {
    res.writeHead(409, {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    });
    res.end(JSON.stringify({ error: `${scriptName} already running` }));
    return;
  }

  const scripts = scriptName === "all"
    ? ["monitor.js", "agent.js", "publisher.js"]
    : [`${scriptName}.js`];

  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "Access-Control-Allow-Origin": "*",
  });

  const send = (msg, type = "log") =>
    res.write(`data: ${JSON.stringify({ type, msg, time: new Date().toISOString() })}\n\n`);

runningScripts.add(scriptName);
  send(`Starting ${scriptName}...`, "info");

  let idx = 0;

  function runNext() {
    if (idx >= scripts.length) {

      send(`✅ ${scriptName} complete`, "success");
      runningScripts.delete(scriptName);
      res.write(`data: ${JSON.stringify({ type: "done" })}\n\n`);
      res.end();
      return;
    }

    const script = scripts[idx++];
    send(`▶ Running ${script}`, "info");
    const proc = spawn("node", [script], { stdio: "pipe" });

    proc.stdout.on("data", (d) =>
      d.toString().split("\n").filter(Boolean).forEach((l) => send(l))
    );
    proc.stderr.on("data", (d) =>
      d.toString().split("\n").filter(Boolean).forEach((l) => send(l, "error"))
    );
    proc.on("close", (code) => {
      if (code === 0) {
        send(`✅ ${script} done`, "success");
        setTimeout(runNext, 2000);
      } else {
        send(`❌ ${script} failed`, "error");
        runningScripts.delete(scriptName);
        res.write(`data: ${JSON.stringify({ type: "done" })}\n\n`);
        res.end();
      }
    });
  }

  runNext();
}

// ── REPORT BUILDERS ───────────────────────────────────────────────────────────
function sanitizeJsonText(text) {
  return (text || "").replace(/```json|```/g, "").trim();
}

function fallbackUserReport(company, scores) {
  return {
    headline: `${company} has an early AI visibility baseline, but the public report is incomplete.`,
    summary: "AI systems show mixed understanding of the brand. Strengthen clarity, category definition, and proof points.",
    topFindings: [
      "Brand understanding is inconsistent across AI systems.",
      "Positioning may be too vague or underspecified.",
      "Concrete proof points are limited or not consistently surfaced."
    ],
    recommendations: [
      scores?.topRecommendation || "Create a clear AI Brand Page that defines what the company is, who it serves, and why it matters.",
      "Add category language, customer examples, and measurable proof points to your site.",
      "Clarify competitor context so AI systems can place the brand correctly."
    ],
    topRecommendation:
      scores?.topRecommendation ||
      "Create a clear AI Brand Page that defines what the company is, who it serves, and why it matters.",
    cta: "Book a strategy session to review the full remediation plan and next implementation steps."
  };
}

function fallbackInternalReport(company, audience, competitors, scores, allResults) {
  return {
    diagnosis:
      `${company} appears to suffer from incomplete AI brand interpretation. The brand likely lacks structured, repeated signals that explain category, audience, differentiation, and proof.`,
    priority: "Clarify brand definition and create a structured source page AI systems can reliably interpret.",
    remediationPlan: [
      "Publish a dedicated brand-definition page covering what the company does, for whom, and how it is different.",
      "Add explicit category language and competitor contrast.",
      "Add proof points: named clients, case studies, outcomes, testimonials, and specific use cases.",
      "Align homepage, about, service, and metadata language around one consistent brand narrative."
    ],
    implementationPlan: [
      "Create an AI Brand Page with company definition, target audience, core offering, and differentiators.",
      "Update homepage copy so category and audience are explicit in the first screenful.",
      "Add at least 2-3 concrete examples or case studies with measurable outcomes.",
      "Re-test after publishing the updated content."
    ],
    serviceNotes: [
      `Audience provided: ${audience || "not provided"}`,
      `Competitors provided: ${competitors || "not provided"}`,
      `Overall score: ${scores?.overall || 0}`,
      `Platforms tested: ${allResults.map((r) => r.platform).join(", ")}`
    ],
    messagingFixes: [
      "Reduce ambiguity in the brand definition sentence.",
      "Use repeated, consistent category language across key pages.",
      "State outcomes and differentiation directly, not implicitly."
    ],
    salesAngle:
      "Position the next step as an AI Brand Audit + Remediation engagement focused on correcting AI interpretation and improving recommendation quality."
  };
}

async function buildReports({
  anthropic,
  company,
  url,
  audience,
  competitors,
  scores,
  allResults,
}) {
  const condensedResults = allResults.map((platform) => ({
    platform: platform.platform,
    results: platform.results.map((r) => ({
      query: r.query,
      response: (r.response || "").substring(0, 500),
    })),
  }));

  const prompt = `
You are generating TWO reports for an AI brand audit.

Company: ${company}
URL: ${url}
Audience: ${audience || "unknown"}
Competitors: ${competitors || "unknown"}

Scores JSON:
${JSON.stringify(scores)}

AI results JSON:
${JSON.stringify(condensedResults)}

Return ONLY valid JSON in this exact structure:
{
  "userReport": {
    "headline": "",
    "summary": "",
    "topFindings": ["", "", ""],
    "recommendations": ["", "", ""],
    "topRecommendation": "",
    "cta": ""
  },
  "internalReport": {
    "diagnosis": "",
    "priority": "",
    "remediationPlan": ["", "", "", ""],
    "implementationPlan": ["", "", "", ""],
    "serviceNotes": ["", "", ""],
    "messagingFixes": ["", "", ""],
    "salesAngle": ""
  }
}

Rules:
- userReport is public-facing and concise.
- internalReport is operator-only and more explicit.
- recommendations must be concrete and brand-side, not instructions to an AI model.
- implementationPlan should focus on website/content/brand fixes.
- Keep language professional and direct.
`;

  try {
    const reportRes = await anthropic.messages.create({
      model: "claude-sonnet-4-6",
      max_tokens: 1200,
      temperature: 0,
      messages: [{ role: "user", content: prompt }],
    });

    const parsed = JSON.parse(sanitizeJsonText(reportRes.content?.[0]?.text || ""));

    return {
      userReport: parsed.userReport || fallbackUserReport(company, scores),
      internalReport:
        parsed.internalReport ||
        fallbackInternalReport(company, audience, competitors, scores, allResults),
    };
  } catch (e) {
    console.log("buildReports fallback:", e.message);
    return {
      userReport: fallbackUserReport(company, scores),
      internalReport: fallbackInternalReport(company, audience, competitors, scores, allResults),
    };
  }
}

// ── AUDIT HANDLER ─────────────────────────────────────────────────────────────
async function handleAudit(body, res, ip) {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "Access-Control-Allow-Origin": "*",
  });

  const send = (data) => res.write(`data: ${JSON.stringify(data)}\n\n`);

  try {
    const { company, url, email, firstName, audience, competitors } = body;

    if (!company || !url || !email) {
      send({ type: "error", code: "MISSING_FIELDS", msg: "company, url, and email are required." });
      res.end();
      return;
    }

    if (FREE_EMAIL_DOMAINS.has(getEmailDomain(email))) {
      send({
        type: "error",
        code: "FREE_EMAIL",
        msg: "Please use your work email address.",
      });
      res.end();
      return;
    }

    const rateCheck = checkRateLimit(ip);
    if (!rateCheck.allowed) {
      send({
        type: "error",
        code: "RATE_LIMIT",
        msg: `You've already run an audit today. Try again in ${rateCheck.resetIn} hour(s).`,
      });
      res.end();
      return;
    }

    const domain = getDomain(url);
    const cached = await getCachedAudit(domain);

    if (cached && cached.run_type === "full") {
      send({
        type: "cached",
        score: cached.overall_score || 0,
        scores: cached.scores || {},
        userReport: cached.user_report || {},
        cachedAt: new Date(cached.updated_at).toLocaleDateString(),
      });
      res.end();
      return;
    }

    send({ step: 1, status: "active", label: "Generating buyer questions" });

    const Anthropic = (await import("@anthropic-ai/sdk")).default;
    const OpenAI = (await import("openai")).default;
    const { GoogleGenerativeAI } = await import("@google/generative-ai");

    const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
    const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
    const genAI = new GoogleGenerativeAI(process.env.GOOGLE_AI_KEY);

    const modelVersions = {
      queryModel: "claude-sonnet-4-6",
      scoringModel: "claude-sonnet-4-6",
      reportModel: "claude-sonnet-4-6",
      chatgpt: "gpt-4o",
      claude: "claude-sonnet-4-6",
      gemini: "gemini-2.0-flash-lite",
      perplexity: "sonar",
    };

    const queryRes = await anthropic.messages.create({
      model: modelVersions.queryModel,
      max_tokens: 500,
      temperature: 0,
      messages: [{
        role: "user",
        content:
          `Generate 7 questions a buyer would ask an AI assistant about ${company} (${url}).
Target audience: ${audience || "B2B buyers"}.
Competitors: ${competitors || "unknown"}.
Return ONLY a JSON array of 7 question strings, no markdown, no explanation.`,
      }],
    });

    let queries;
    try {
      queries = JSON.parse(sanitizeJsonText(queryRes.content[0].text));
    } catch {
      queries = [
        `What is ${company}?`,
        `What does ${company} do?`,
        `Who is ${company} for?`,
        `What category is ${company}?`,
        `How is ${company} different?`,
        `What are ${company}'s features?`,
        `Who competes with ${company}?`,
      ];
    }

    send({ stepDone: 1 });

    const platforms = [
      {
        name: "ChatGPT",
        step: 2,
        fn: async (q) => {
          const r = await openai.chat.completions.create({
            model: modelVersions.chatgpt,
            max_tokens: 300,
            messages: [{ role: "user", content: q }],
          });
          return r.choices[0].message.content;
        },
      },
      {
        name: "Claude",
        step: 3,
        fn: async (q) => {
          const r = await anthropic.messages.create({
            model: modelVersions.claude,
            max_tokens: 300,
            temperature: 0,
            messages: [{ role: "user", content: q }],
          });
          return r.content[0].text;
        },
      },
      {
        name: "Gemini",
        step: 4,
        fn: async (q) => {
          const model = genAI.getGenerativeModel({ model: modelVersions.gemini });
          const r = await model.generateContent(q);
          return r.response.text();
        },
      },
      {
        name: "Perplexity",
        step: 5,
        fn: async (q) => {
          const r = await fetch("https://api.perplexity.ai/chat/completions", {
            method: "POST",
            headers: {
              Authorization: `Bearer ${process.env.PERPLEXITY_API_KEY}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              model: modelVersions.perplexity,
              max_tokens: 300,
              messages: [{ role: "user", content: q }],
            }),
          });
          const d = await r.json();
          return d?.choices?.[0]?.message?.content || "ERROR: No response";
        },
      },
    ];

    const allResults = [];

    for (const platform of platforms) {
      send({ step: platform.step, status: "active", label: `Running ${platform.name}` });

      const results = [];
      for (const query of queries) {
        try {
          results.push({ query, response: await platform.fn(query) });
        } catch (e) {
          results.push({ query, response: `ERROR: ${e.message}` });
        }
        await new Promise((r) => setTimeout(r, 500));
      }

      allResults.push({ platform: platform.name, results });
      send({ stepDone: platform.step });
    }

    send({ step: 6, status: "active", label: "Scoring results" });

    const scoreRes = await anthropic.messages.create({
      model: modelVersions.scoringModel,
      max_tokens: 900,
      temperature: 0,
      messages: [{
        role: "user",
        content:
`Score AI brand accuracy for ${company} (${url}).
Audience: ${audience || "unknown"}.
Competitors: ${competitors || "unknown"}.

Results:
${allResults.map((p) => `${p.platform}:\n${p.results.map((r) => `Q:${r.query}\nA:${(r.response || "").substring(0, 180)}`).join("\n")}`).join("\n---\n")}

Return ONLY valid JSON:
{
  "overall": 0,
  "platforms": {
    "ChatGPT": { "score": 0, "keyGap": "" },
    "Claude": { "score": 0, "keyGap": "" },
    "Gemini": { "score": 0, "keyGap": "" },
    "Perplexity": { "score": 0, "keyGap": "" }
  },
  "topRecommendation": ""
}

Rules:
- topRecommendation must be one actionable sentence written directly TO the company.
- Start topRecommendation with a verb like Publish, Create, Add, Clarify, or Build.
- Focus on brand/site/content actions, not instructions to an AI system.`,
      }],
    });

    let scores;
    try {
      scores = JSON.parse(sanitizeJsonText(scoreRes.content[0].text));
    } catch {
      scores = {
        overall: 0,
        platforms: {},
        topRecommendation: "Create a clear AI Brand Page that explains what the company does, who it serves, and how it is different.",
      };
    }

    send({ stepDone: 6 });
    send({ step: 7, status: "active", label: "Building reports" });

    const { userReport, internalReport } = await buildReports({
      anthropic,
      company,
      url,
      audience,
      competitors,
      scores,
      allResults,
    });

    await saveAuditCache(domain, {
      company,
      email: email || "",
      firstName: firstName || "",
      audience: audience || "",
      competitors: competitors || "",
      overallScore: scores.overall,
      scores,
      queries,
      responses: allResults,
      userReport,
      internalReport,
      modelVersions,
      runType: "full",
      status: "complete",
    });

    await saveLead(email, company, domain, scores.overall, "audit");

    send({ stepDone: 7 });
    send({
      type: "done",
      score: scores.overall,
      scores,
      userReport,
    });
  } catch (e) {
    send({ type: "error", msg: e.message });
  }

  res.end();
}

// ── HTTP SERVER ───────────────────────────────────────────────────────────────
const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const path = url.pathname;
  const ip = getClientIP(req);

  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  if (path === "/api/status") {
    try {
      const count = await pool.query("SELECT COUNT(*) FROM audit_cache");
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        status: "running",
        running: [...runningScripts],
        cachedAudits: parseInt(count.rows[0].count, 10),
        time: new Date().toISOString(),
      }));
    } catch (e) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        status: "running",
        running: [...runningScripts],
        cachedAudits: 0,
        dbError: e.message,
        time: new Date().toISOString(),
      }));
    }
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
      const { existsSync, readFileSync } = await import("fs");

      if (!existsSync("./results/proposed-updates.md")) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ corrections: [] }));
        return;
      }

      const content = readFileSync("./results/proposed-updates.md", "utf8");
      const corrections = [];
      const sections = content.split("---").filter((s) => s.includes("Proposed addition"));

      for (const section of sections) {
        const headerMatch = section.match(/###\s+\d+\.\s+(.+?)\n/);
        const contentMatch = section.match(/>\s*(.+?)(?=\n- \[)/s);
        const gapMatch = section.match(/\*\*Gap:\*\*\s*(.+?)(?=\n)/);
        const approved = /\[X\]|\[x\]/i.test(section.match(/- \[.?\] Approve/)?.[0] || "");
        const rejected = /\[X\]|\[x\]/i.test(section.match(/- \[.?\] Reject/)?.[0] || "");

        if (headerMatch && contentMatch) {
          const parts = headerMatch[1].split("·").map((s) => s.trim());
          corrections.push({
            platform: parts[0] || "",
            question: (parts[1] || "").replace(/^"|"$/g, ""),
            score: parseInt((parts[2] || "0").replace(/\D/g, ""), 10) || 0,
            content: contentMatch[1].trim(),
            gap: gapMatch ? gapMatch[1].trim() : "",
            status: approved ? "approved" : rejected ? "rejected" : "pending",
          });
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

  if (path === "/api/submissions") {
    try {
      const submissions = await getAllSubmissions();
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ submissions, total: submissions.length }));
    } catch (e) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (path.startsWith("/api/submission/")) {
    const domain = decodeURIComponent(path.replace("/api/submission/", ""));
    try {
      const sub = await getSingleSubmission(domain);
      if (!sub) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Not found" }));
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(sub));
    } catch (e) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (req.method === "POST" && path.startsWith("/api/run/")) {
    const script = path.replace("/api/run/", "");
    if (!["monitor", "agent", "publisher", "all"].includes(script)) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Unknown script" }));
      return;
    }
    runScript(script, res);
    return;
  }

  if (req.method === "POST" && path === "/api/audit") {
    let body = "";
    req.on("data", (d) => body += d);
    req.on("end", async () => {
      try {
        await handleAudit(JSON.parse(body), res, ip);
      } catch (e) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  if (req.method === "POST" && path === "/api/competitors") {
    let body = "";
    req.on("data", (d) => body += d);
    req.on("end", async () => {
      try {
        const { url: targetUrl, company } = JSON.parse(body);

        const Anthropic = (await import("@anthropic-ai/sdk")).default;
        const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

        let siteContent = "";
        try {
          const siteRes = await fetch(targetUrl, {
            signal: AbortSignal.timeout(8000),
            headers: { "User-Agent": "Mozilla/5.0" },
          });
          const html = await siteRes.text();
          siteContent = html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").substring(0, 3000);
        } catch {
          siteContent = `Company: ${company}, URL: ${targetUrl}`;
        }

        const aiRes = await anthropic.messages.create({
          model: "claude-sonnet-4-6",
          max_tokens: 300,
          temperature: 0,
          messages: [{
            role: "user",
            content:
              `Based on this website content for ${company} (${targetUrl}), identify their top 4-6 competitors.
Website text: "${siteContent}"
Return ONLY valid JSON: {"competitors":["Competitor A","Competitor B"],"audience":"one sentence description of target audience"}
No markdown, no explanation.`,
          }],
        });

        let data;
        try {
          data = JSON.parse(sanitizeJsonText(aiRes.content[0].text));
        } catch {
          data = { competitors: [], audience: "" };
        }

        res.writeHead(200, {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        });
        res.end(JSON.stringify(data));
      } catch (e) {
        res.writeHead(500, {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        });
        res.end(JSON.stringify({ error: e.message, competitors: [], audience: "" }));
      }
    });
    return;
  }

  if (req.method === "POST" && path === "/api/claim") {
    let body = "";
    req.on("data", (d) => body += d);
    req.on("end", async () => {
      try {
        const { email, company, domain, score, source } = JSON.parse(body);

        if (!email || !company) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "email and company required" }));
          return;
        }

        await saveLead(email, company, domain, score, source);
        console.log(`📩 New lead: ${email} | ${company} | score:${score}`);

        res.writeHead(200, {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        });
        res.end(JSON.stringify({ ok: true }));
      } catch (e) {
        res.writeHead(500, {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  if (req.method === "POST" && path === "/api/quickscan") {
    let body = "";
    req.on("data", (d) => body += d);
    req.on("end", async () => {
      try {
        const { company, url } = JSON.parse(body);

        if (!company || !url) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "company and url required" }));
          return;
        }

        const domain = getDomain(url);
        const cached = await getCachedAudit(domain);

        // If a full audit exists, use it rather than running a weaker overwrite-prone scan
        if (cached && cached.run_type === "full") {
          res.writeHead(200, {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          });
          res.end(JSON.stringify({
            score: cached.overall_score || 0,
            cached: true,
            cachedAt: new Date(cached.updated_at).toLocaleDateString(),
            topRecommendation:
              cached.scores?.topRecommendation ||
              cached.user_report?.topRecommendation ||
              "",
            visibility: (cached.overall_score || 0) >= 75
              ? "high"
              : (cached.overall_score || 0) >= 45
                ? "medium"
                : "low",
          }));
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
          Promise.all(questions.map(async (q) => {
            try {
              const r = await openai.chat.completions.create({
                model: "gpt-4o-mini",
                max_tokens: 200,
                messages: [{ role: "user", content: q }],
              });
              return r.choices[0].message.content;
            } catch (e) {
              return `ERROR: ${e.message}`;
            }
          })),
          Promise.all(questions.map(async (q) => {
            try {
              const r = await fetch("https://api.perplexity.ai/chat/completions", {
                method: "POST",
                headers: {
                  Authorization: `Bearer ${process.env.PERPLEXITY_API_KEY}`,
                  "Content-Type": "application/json",
                },
                body: JSON.stringify({
                  model: "sonar",
                  max_tokens: 200,
                  messages: [{ role: "user", content: q }],
                }),
              });
              const d = await r.json();
              return d?.choices?.[0]?.message?.content || "ERROR: No response";
            } catch (e) {
              return `ERROR: ${e.message}`;
            }
          })),
        ]);

        const scoreRes = await anthropic.messages.create({
          model: "claude-haiku-4-5-20251001",
          max_tokens: 300,
          temperature: 0,
          messages: [{
            role: "user",
            content:
              `Score AI brand accuracy for ${company} (${url}).
ChatGPT responses: ${chatgptResults.map((r, i) => `Q${i + 1}: ${String(r).substring(0, 100)}`).join(" | ")}
Perplexity responses: ${perplexityResults.map((r, i) => `Q${i + 1}: ${String(r).substring(0, 100)}`).join(" | ")}
Return ONLY valid JSON: {"score":0,"chatgpt":0,"perplexity":0,"topGap":"one sentence","visibility":"low|medium|high"}
Score 0-100. Score reflects how accurately and completely AI describes this brand.`,
          }],
        });

        let scores;
        try {
          scores = JSON.parse(sanitizeJsonText(scoreRes.content[0].text));
        } catch {
          scores = {
            score: 0,
            chatgpt: 0,
            perplexity: 0,
            topGap: "Unable to score",
            visibility: "low",
          };
        }

        // IMPORTANT: quickscan no longer writes into audit_cache
        res.writeHead(200, {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        });
        res.end(JSON.stringify({
          ...scores,
          cached: false,
          domain,
        }));
      } catch (e) {
        res.writeHead(500, {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        });
        res.end(JSON.stringify({ error: e.message, score: 0 }));
      }
    });
    return;
  }

  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
});

// ── BOOT ──────────────────────────────────────────────────────────────────────
async function boot() {
  await initDB();

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`\n🖥️  AIsubtext API Server v3.1.0`);
    console.log(`📡 http://localhost:${PORT}`);
    console.log(`🗄️  Storage: PostgreSQL (persistent)`);
    console.log(`🛡️  Protections: free email blocking, IP rate limiting (1/24h)`);
    console.log(`📋 Reporting: user_report + internal_report`);
    console.log(`⚠️  Quickscan no longer overwrites full audit records`);

    console.log(`\nEndpoints:`);
    console.log(`  GET  /api/status`);
    console.log(`  GET  /api/scores`);
    console.log(`  GET  /api/corrections`);
    console.log(`  GET  /api/submissions`);
    console.log(`  GET  /api/submission/:domain`);
    console.log(`  POST /api/run/:script`);
    console.log(`  POST /api/audit`);
    console.log(`  POST /api/quickscan`);
    console.log(`  POST /api/claim`);
    console.log(`  POST /api/competitors\n`);
  });
}

boot().catch((e) => {
  console.error("Boot failed:", e);
  process.exit(1);
});
