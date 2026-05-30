import type { NormalizedEvent } from '../../types'
import { asString, baseName, pick } from './util'

/**
 * Best-effort parser for arbitrary JSON log records. It maps a range of common
 * field names (SIEM exports, ECS, custom shippers) onto the normalized shape so
 * that detection rules still have something to work with.
 */
export function parseGenericJson(
  record: Record<string, any>,
  index: number,
): NormalizedEvent {
  const process = asString(pick(record, 'process', 'image', 'Image', 'proc'))
  return {
    id: `json-${index}`,
    timestamp: asString(pick(record, 'timestamp', 'TimeCreated', '@timestamp', 'time')),
    source: 'json',
    eventId: pick(record, 'EventID', 'event_id', 'eventId', 'id') as string | number | undefined,
    host: asString(pick(record, 'host', 'Computer', 'hostname', 'agent')),
    user: asString(pick(record, 'user', 'username', 'User', 'account')),
    process: baseName(process),
    parentProcess: baseName(asString(pick(record, 'parent', 'ParentImage', 'parent_process'))),
    commandLine: asString(pick(record, 'command_line', 'CommandLine', 'cmd', 'commandLine')),
    sourceIp: asString(pick(record, 'src_ip', 'source_ip', 'sourceIp', 'srcip')),
    destIp: asString(pick(record, 'dest_ip', 'destination_ip', 'destIp', 'dstip')),
    message: asString(pick(record, 'message', 'msg', 'description')) ?? JSON.stringify(record),
    raw: record,
  }
}
