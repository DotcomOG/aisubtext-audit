// ── REMEDIATION BOT ENDPOINT ──────────────────────────────────────────────────
// server.js patch — v2.6.0 — 2026-03-03
// Changes from v2.5.0: Added /api/remediation endpoint (Content Brief Bot)
//
// INSTRUCTIONS: Paste this block inside your HTTP server createServer() handler,
// AFTER the /api/competitors block and BEFORE the final 404 handler.
// Also update the version comment at the top of server.js to v2.6.0.
// Add this line to the console.log Endpoints list at the bottom:
//   console.log(`  POST /api/remediation`);

  if (req.method === "POST" && path === "/api/remediation") {
    let body = "";
    req.on("data", d => body += d);
    req.on("end", async () => {
      try {
        const { company, url, audience, scores } = JSON.parse(body);
        if (!company || !scores) {
          res.writeHead(400, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
          res.end(JSON.stringify({ error: "company and scores required" }));
          return;
        }

        const Anthropic = (await import("@anthropic-ai/sdk")).default;
        const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

        const platforms = scores.platforms || {};
        const gapSummary = ["ChatGPT", "Claude", "Gemini", "Perplexity"]
          .map(p => {
            const d = platforms[p] || {};
            return d.keyGap ? `${p} (score ${d.score}/100): ${d.keyGap}` : null;
          })
          .filter(Boolean)
          .join("\n");

        const briefRes = await anthropic.messages.create({
          model: "claude-haiku-4-5-20251001",
          max_tokens: 900,
          messages: [{
            role: "user",
            content: `You are an AEO (Answer Engine Optimization) strategist. A brand just completed an AI visibility audit.

Brand: ${company}
Website: ${url}
Audience: ${audience || "B2B buyers"}
Composite AEO Score: ${scores.overall || 0}/100
Top Recommendation from audit: ${scores.topRecommendation || "none"}

Per-engine gaps:
${gapSummary || "No gap data available"}

Generate a prioritized remediation content brief with exactly 5 actions. Each action must be concrete, specific to this brand, and immediately actionable.

Return ONLY valid JSON — no markdown, no explanation:
{
  "estimatedScoreGain": <integer 5-30>,
  "briefSummary": "<one sentence summary of the core problem>",
  "priorityActions": [
    {
      "rank": 1,
      "type": "<one of: FAQ Page | Schema Markup | Wikipedia Citation | Brand Definition Page | Competitor Comparison Page | Press Coverage | LinkedIn Authority Post | AI Brand Page>",
      "title": "<specific page/content title>",
      "why": "<one sentence: which engines are confused about what, and why this fixes it>",
      "effort": "<Low | Medium | High>",
      "impact": "<Low | Medium | High>",
      "quickWin": <true if effort Low and impact High, else false>
    }
  ]
}`
          }]
        });

        let brief;
        try {
          brief = JSON.parse(briefRes.content[0].text.replace(/```json|```/g, "").trim());
        } catch {
          brief = {
            estimatedScoreGain: 10,
            briefSummary: "AI engines lack sufficient brand context to represent this company accurately.",
            priorityActions: [
              { rank: 1, type: "FAQ Page", title: `${company} — Frequently Asked Questions`, why: "AI engines defaulting to generic descriptions due to lack of structured Q&A content.", effort: "Low", impact: "High", quickWin: true },
              { rank: 2, type: "Brand Definition Page", title: `What is ${company}?`, why: "No authoritative definition page for AI crawlers to index.", effort: "Low", impact: "High", quickWin: true },
              { rank: 3, type: "Schema Markup", title: "Organization + Product schema on homepage", why: "Missing structured data prevents AI engines from extracting key facts.", effort: "Medium", impact: "High", quickWin: false },
              { rank: 4, type: "Competitor Comparison Page", title: `${company} vs Competitors`, why: "AI engines unable to accurately position brand in competitive landscape.", effort: "Medium", impact: "Medium", quickWin: false },
              { rank: 5, type: "Wikipedia Citation", title: "Third-party citation in relevant Wikipedia articles", why: "No authoritative external references for AI engines to cite.", effort: "High", impact: "High", quickWin: false }
            ]
          };
        }

        // Log remediation requests for analytics
        try {
          const { appendFileSync, existsSync: fsExists, mkdirSync: fsMkdir } = await import("fs");
          if (!fsExists("./results")) fsMkdir("./results", { recursive: true });
          const row = `"${new Date().toISOString()}","${company}","${url}","${scores.overall || 0}","${brief.estimatedScoreGain}"\n`;
          if (!fsExists("./results/remediation-requests.csv")) {
            appendFileSync("./results/remediation-requests.csv", "Timestamp,Company,URL,AuditScore,EstimatedGain\n");
          }
          appendFileSync("./results/remediation-requests.csv", row);
          console.log(`🤖 Remediation brief generated: ${company} | score:${scores.overall} | est. gain:+${brief.estimatedScoreGain}`);
        } catch (logErr) {
          console.log("Remediation log error:", logErr.message);
        }

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
