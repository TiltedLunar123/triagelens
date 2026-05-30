import type { NormalizedEvent } from '../../types'
import { asString, baseName, pick } from './util'

/**
 * Parse a Windows Security event (Provider "Microsoft-Windows-Security-Auditing"),
 * for example a 4688 "A new process has been created" record exported to JSON.
 */
export function parseWindowsSecurity(
  record: Record<string, any>,
  index: number,
): NormalizedEvent {
  const data: Record<string, any> = record.EventData ?? record.event_data ?? {}
  const newProcess = asString(pick(data, 'NewProcessName', 'ProcessName', 'Image'))
  const commandLine = asString(pick(data, 'CommandLine', 'ProcessCommandLine'))
  const eventId = pick(record, 'EventID', 'event_id', 'Id')

  return {
    id: `winsec-${eventId ?? 'evt'}-${index}`,
    timestamp: asString(pick(record, 'TimeCreated', 'timestamp', '@timestamp')),
    source: 'windows-security',
    eventId: eventId as string | number | undefined,
    host: asString(pick(record, 'Computer', 'host', 'hostname')),
    user: asString(pick(data, 'SubjectUserName', 'TargetUserName', 'User')),
    process: baseName(newProcess),
    parentProcess: baseName(asString(pick(data, 'ParentProcessName', 'ParentImage'))),
    commandLine,
    message: `Windows Security ${eventId ?? ''}: ${newProcess ?? 'process event'}${
      commandLine ? ` -> ${commandLine}` : ''
    }`.trim(),
    raw: record,
  }
}
