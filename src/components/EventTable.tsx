import type { NormalizedEvent } from '../types'

export function EventTable({ events }: { events: NormalizedEvent[] }) {
  if (events.length === 0) {
    return <p className="muted">No events parsed.</p>
  }

  return (
    <details>
      <summary>{events.length} parsed event(s)</summary>
      <table className="events-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Source</th>
            <th>Host</th>
            <th>User</th>
            <th>Process</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.id}>
              <td className="mono">{e.timestamp ?? '-'}</td>
              <td>{e.source}</td>
              <td>{e.host ?? '-'}</td>
              <td>{e.user ?? '-'}</td>
              <td className="mono">{e.process ?? '-'}</td>
              <td className="mono">{e.commandLine ?? e.message}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </details>
  )
}
