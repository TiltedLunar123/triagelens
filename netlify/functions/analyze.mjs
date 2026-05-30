// Serverless proxy for the Claude (Anthropic) analysis provider.
// The browser posts parsed events and findings here; this function injects the
// API key server-side and returns an Enrichment object:
//   { summary: string, recommendations: string[], notes: { [findingId]: string } }
//
// Runs on Netlify Functions (Node 18+). Set ANTHROPIC_API_KEY in the site env.

const ANTHROPIC_URL = 'https://api.anthropic.com/v1/messages'
const DEFAULT_MODEL = 'claude-haiku-4-5'

const SYSTEM_PROMPT = [
  'You are a Tier 1 SOC analyst assistant.',
  'You are given parsed security events and rule-based detections already produced by a detection engine.',
  'Explain the findings clearly and recommend next steps. Be concise and precise.',
  'Do not invent events, hosts, or indicators that are not present in the input.',
  'Respond with JSON only, matching exactly this shape:',
  '{"summary": string, "recommendations": string[], "notes": {"<findingId>": string}}',
].join(' ')

export default async (req) => {
  if (req.method !== 'POST') {
    return json({ error: 'Method not allowed' }, 405)
  }

  let body
  try {
    body = await req.json()
  } catch {
    return json({ error: 'Invalid JSON body.' }, 400)
  }

  // Prefer a bring-your-own-key from the request; fall back to the server env key.
  const apiKey =
    (body && typeof body.apiKey === 'string' && body.apiKey) || process.env.ANTHROPIC_API_KEY
  if (!apiKey) {
    return json(
      {
        error:
          'No Anthropic API key. Set ANTHROPIC_API_KEY on the server, or enter a key in Provider setup.',
      },
      500,
    )
  }

  const userPrompt = buildUserPrompt(body)

  let upstream
  try {
    upstream = await fetch(ANTHROPIC_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model:
          (body && typeof body.model === 'string' && body.model) ||
          process.env.ANTHROPIC_MODEL ||
          DEFAULT_MODEL,
        max_tokens: 1024,
        system: SYSTEM_PROMPT,
        messages: [{ role: 'user', content: userPrompt }],
      }),
    })
  } catch {
    return json({ error: 'Failed to reach the Anthropic API.' }, 502)
  }

  if (!upstream.ok) {
    const detail = await upstream.text().catch(() => '')
    return json(
      { error: `Anthropic API error ${upstream.status}: ${detail.slice(0, 300)}` },
      502,
    )
  }

  const data = await upstream.json()
  const text = data?.content?.[0]?.text ?? ''
  const parsed = parseJsonLoose(text)

  return json(parsed ?? { summary: text }, 200)
}

function buildUserPrompt(body) {
  const findings = Array.isArray(body?.findings) ? body.findings : []
  const events = Array.isArray(body?.events) ? body.events : []
  const payload = {
    riskScore: body?.riskScore,
    severity: body?.severity,
    findings: findings.map((f) => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      description: f.description,
      techniques: (f.techniques || []).map((t) => `${t.id} ${t.name}`),
      evidence: (f.evidence || []).slice(0, 8),
    })),
    eventSample: events.slice(0, 25),
  }
  return `Analyze these detections and events:\n\n${JSON.stringify(payload, null, 2)}`
}

function parseJsonLoose(text) {
  const trimmed = String(text).trim()
  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i)
  const candidate = fenced ? fenced[1] : trimmed
  try {
    return JSON.parse(candidate)
  } catch {
    const start = candidate.indexOf('{')
    const end = candidate.lastIndexOf('}')
    if (start !== -1 && end > start) {
      try {
        return JSON.parse(candidate.slice(start, end + 1))
      } catch {
        return undefined
      }
    }
    return undefined
  }
}

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}
