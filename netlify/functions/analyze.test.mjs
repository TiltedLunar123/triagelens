import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import handler, { buildUserPrompt, parseJsonLoose } from './analyze.mjs'

/** A Request-alike with just the two members the handler touches. */
function post(body) {
  return {
    method: 'POST',
    json: async () => {
      if (body === undefined) throw new SyntaxError('bad json')
      return body
    },
  }
}

/** Stand in for an Anthropic reply carrying one text block. */
function upstreamText(text) {
  return {
    ok: true,
    status: 200,
    json: async () => ({ content: [{ type: 'text', text }] }),
  }
}

const read = async (response) => ({
  status: response.status,
  body: JSON.parse(await response.text()),
})

const MINIMAL = { riskScore: 10, severity: 'low', findings: [], events: [] }

let originalKey
let originalModel

beforeEach(() => {
  originalKey = process.env.ANTHROPIC_API_KEY
  originalModel = process.env.ANTHROPIC_MODEL
  process.env.ANTHROPIC_API_KEY = 'server-key'
  delete process.env.ANTHROPIC_MODEL
  vi.stubGlobal('fetch', vi.fn())
})

afterEach(() => {
  if (originalKey === undefined) delete process.env.ANTHROPIC_API_KEY
  else process.env.ANTHROPIC_API_KEY = originalKey
  if (originalModel === undefined) delete process.env.ANTHROPIC_MODEL
  else process.env.ANTHROPIC_MODEL = originalModel
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('analyze handler', () => {
  it('rejects anything that is not a POST', async () => {
    const { status, body } = await read(await handler({ method: 'GET' }))
    expect(status).toBe(405)
    expect(body.error).toMatch(/not allowed/i)
    expect(fetch).not.toHaveBeenCalled()
  })

  it('rejects a body that will not parse', async () => {
    const { status, body } = await read(await handler(post(undefined)))
    expect(status).toBe(400)
    expect(body.error).toMatch(/invalid json/i)
  })

  it('refuses to call out with no key anywhere', async () => {
    delete process.env.ANTHROPIC_API_KEY
    const { status, body } = await read(await handler(post(MINIMAL)))
    expect(status).toBe(500)
    expect(body.error).toMatch(/no anthropic api key/i)
    expect(fetch).not.toHaveBeenCalled()
  })

  it('prefers the caller key over the server one and forwards the model', async () => {
    fetch.mockResolvedValue(upstreamText('{"summary":"ok"}'))
    await handler(post({ ...MINIMAL, apiKey: 'byo-key', model: 'claude-opus-5' }))

    const [, init] = fetch.mock.calls[0]
    expect(init.headers['x-api-key']).toBe('byo-key')
    expect(JSON.parse(init.body).model).toBe('claude-opus-5')
  })

  it('falls back to ANTHROPIC_MODEL when the caller does not pick one', async () => {
    process.env.ANTHROPIC_MODEL = 'claude-sonnet-5'
    fetch.mockResolvedValue(upstreamText('{"summary":"ok"}'))
    await handler(post(MINIMAL))

    expect(JSON.parse(fetch.mock.calls[0][1].body).model).toBe('claude-sonnet-5')
  })

  it('reports a network failure as a bad gateway', async () => {
    fetch.mockRejectedValue(new Error('ECONNREFUSED'))
    const { status, body } = await read(await handler(post(MINIMAL)))
    expect(status).toBe(502)
    expect(body.error).toMatch(/failed to reach/i)
  })

  it('passes the upstream status and a trimmed detail through', async () => {
    fetch.mockResolvedValue({
      ok: false,
      status: 429,
      text: async () => 'x'.repeat(500),
    })
    const { status, body } = await read(await handler(post(MINIMAL)))
    expect(status).toBe(502)
    expect(body.error).toContain('Anthropic API error 429')
    expect(body.error).toHaveLength('Anthropic API error 429: '.length + 300)
  })

  it('survives an upstream 200 whose body is not JSON', async () => {
    fetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => {
        throw new SyntaxError('Unexpected token <')
      },
    })
    const { status, body } = await read(await handler(post(MINIMAL)))
    expect(status).toBe(502)
    expect(body.error).toMatch(/not json/i)
  })

  it('returns the parsed enrichment when the model behaves', async () => {
    fetch.mockResolvedValue(
      upstreamText(
        '```json\n{"summary":"Two findings","recommendations":["Isolate"],"notes":{"a":"b"}}\n```',
      ),
    )
    const { status, body } = await read(await handler(post(MINIMAL)))
    expect(status).toBe(200)
    expect(body).toEqual({
      summary: 'Two findings',
      recommendations: ['Isolate'],
      notes: { a: 'b' },
    })
  })

  it('wraps unparseable model output as a plain summary', async () => {
    fetch.mockResolvedValue(upstreamText('I could not do that.'))
    const { body } = await read(await handler(post(MINIMAL)))
    expect(body).toEqual({ summary: 'I could not do that.' })
  })

  it('does not pass a bare array through as an enrichment', async () => {
    fetch.mockResolvedValue(upstreamText('[1, 2, 3]'))
    const { body } = await read(await handler(post(MINIMAL)))
    expect(body).toEqual({ summary: '[1, 2, 3]' })
  })

  it('does not pass a bare false through as an enrichment', async () => {
    fetch.mockResolvedValue(upstreamText('false'))
    const { body } = await read(await handler(post(MINIMAL)))
    expect(body).toEqual({ summary: 'false' })
  })

  it('copes with a reply that has no content blocks', async () => {
    fetch.mockResolvedValue({ ok: true, status: 200, json: async () => ({}) })
    const { status, body } = await read(await handler(post(MINIMAL)))
    expect(status).toBe(200)
    expect(body).toEqual({ summary: '' })
  })
})

describe('buildUserPrompt', () => {
  it('caps the event sample at 25 and the evidence at 8', () => {
    const events = Array.from({ length: 40 }, (_, i) => ({ id: `e${i}` }))
    const findings = [
      {
        id: 'r1',
        title: 'Rule one',
        severity: 'high',
        description: 'because',
        techniques: [{ id: 'T1110', name: 'Brute Force' }],
        evidence: Array.from({ length: 20 }, (_, i) => `line ${i}`),
      },
    ]

    const payload = JSON.parse(
      buildUserPrompt({ riskScore: 70, severity: 'high', findings, events }).split(
        '\n\n',
      )[1],
    )

    expect(payload.eventSample).toHaveLength(25)
    expect(payload.findings[0].evidence).toHaveLength(8)
    expect(payload.findings[0].techniques).toEqual(['T1110 Brute Force'])
    expect(payload.riskScore).toBe(70)
  })

  it('tolerates a body with nothing in it', () => {
    const payload = JSON.parse(buildUserPrompt({}).split('\n\n')[1])
    expect(payload.findings).toEqual([])
    expect(payload.eventSample).toEqual([])
  })

  it('tolerates findings with no techniques or evidence', () => {
    const payload = JSON.parse(
      buildUserPrompt({ findings: [{ id: 'r1', title: 'bare' }] }).split('\n\n')[1],
    )
    expect(payload.findings[0].techniques).toEqual([])
    expect(payload.findings[0].evidence).toEqual([])
  })
})

describe('parseJsonLoose', () => {
  it('reads a fenced block', () => {
    expect(parseJsonLoose('```json\n{"a":1}\n```')).toEqual({ a: 1 })
  })

  it('reads a fenced block with no language tag', () => {
    expect(parseJsonLoose('```\n{"a":1}\n```')).toEqual({ a: 1 })
  })

  it('digs an object out of surrounding chatter', () => {
    expect(parseJsonLoose('Sure, here it is: {"a":1} hope that helps')).toEqual({
      a: 1,
    })
  })

  it('gives up on text with no object in it', () => {
    expect(parseJsonLoose('no json here')).toBeUndefined()
  })

  it('gives up when the braces do not contain valid JSON', () => {
    expect(parseJsonLoose('{not: valid, at all}')).toBeUndefined()
  })
})
