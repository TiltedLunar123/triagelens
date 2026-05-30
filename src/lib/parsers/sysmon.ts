import type { NormalizedEvent } from '../../types'
import { asString, baseName, pick } from './util'

/**
 * Parse a Sysmon event (Provider "Microsoft-Windows-Sysmon"), for example an
 * Event ID 1 "Process Create" record exported to JSON.
 */
export function parseSysmon(
  record: Record<string, any>,
  index: number,
): NormalizedEvent {
  const data: Record<string, any> = record.EventData ?? record.event_data ?? {}
  const image = asString(pick(data, 'Image'))
  const commandLine = asString(pick(data, 'CommandLine'))
  const eventId = pick(record, 'EventID', 'event_id', 'Id')

  return {
    id: `sysmon-${eventId ?? 'evt'}-${index}`,
    timestamp: asString(pick(record, 'TimeCreated', 'timestamp', '@timestamp', 'UtcTime')),
    source: 'sysmon',
    eventId: eventId as string | number | undefined,
    host: asString(pick(record, 'Computer', 'host', 'hostname')),
    user: asString(pick(data, 'User')),
    process: baseName(image),
    parentProcess: baseName(asString(pick(data, 'ParentImage'))),
    commandLine,
    message: `Sysmon ${eventId ?? ''}: ${image ?? 'process event'}${
      commandLine ? ` -> ${commandLine}` : ''
    }`.trim(),
    raw: record,
  }
}
