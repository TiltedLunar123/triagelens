import type { EnrichmentRequest } from './provider'

/**
 * System prompt shared by the local (Ollama) provider. The cloud function keeps
 * its own copy of an equivalent prompt so it stays self-contained; keep the two
 * in sync when you change the output contract.
 */
export const SYSTEM_PROMPT = [
  'You are a Tier 1 SOC analyst assistant.',
  'You are given parsed security events and rule-based detections that were already produced by a detection engine.',
  'Your job is to explain the findings clearly and recommend next steps. Be concise and precise.',
  'Do not invent events, hosts, or indicators that are not present in the input.',
  'Respond with JSON only, matching exactly this shape:',
  '{"summary": string, "recommendations": string[], "notes": {"<findingId>": string}}',
  'The summary is 2-4 sentences. recommendations is an ordered list of concrete actions. notes maps each finding id to a one or two sentence analyst note.',
].join(' ')

/** Build the user message: a compact JSON view of the request for the model. */
export function buildUserPrompt(request: EnrichmentRequest): string {
  const payload = {
    riskScore: request.riskScore,
    severity: request.severity,
    findings: request.findings.map((f) => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      description: f.description,
      techniques: f.techniques.map((t) => `${t.id} ${t.name}`),
      evidence: f.evidence.slice(0, 8),
    })),
    // Cap the event sample so the prompt stays small and cache-friendly.
    eventSample: request.events.slice(0, 25).map((e) => ({
      source: e.source,
      eventId: e.eventId,
      host: e.host,
      user: e.user,
      process: e.process,
      parentProcess: e.parentProcess,
      commandLine: e.commandLine,
      sourceIp: e.sourceIp,
      message: e.message,
    })),
  }
  return `Analyze these detections and events:\n\n${JSON.stringify(payload, null, 2)}`
}
