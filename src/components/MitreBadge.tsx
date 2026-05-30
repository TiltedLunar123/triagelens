import type { MitreTechnique } from '../types'

export function MitreBadge({ technique }: { technique: MitreTechnique }) {
  return (
    <a
      className="badge"
      href={technique.url}
      target="_blank"
      rel="noreferrer"
      title={`${technique.tactic}: ${technique.name}`}
    >
      {technique.id} {technique.name}
    </a>
  )
}
