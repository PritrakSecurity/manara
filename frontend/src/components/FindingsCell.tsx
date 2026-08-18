import { Badge } from './common/Badge';

// FindingView mirrors the privacy-safe finding projection returned by the API
// (backend/internal/api/findings.go). It deliberately excludes any raw content,
// matched secret values, or provider payloads.
export interface FindingView {
  type: string;
  detector: string;
  evidence_strength: string;
  hard_evidence: boolean;
  status: string;
  shadow_only: boolean;
}

function evidenceLabel(f: FindingView): string {
  if (f.shadow_only) return 'Shadow Only';
  if (f.hard_evidence) return 'Hard Evidence';
  return 'Contextual';
}

interface FindingsCellProps {
  findings?: FindingView[];
}

// FindingsCell renders a finding list with an evidence badge. Shadow-only
// findings are clearly labelled so analysts know AI did not change the
// enforcement decision.
export function FindingsCell({ findings }: FindingsCellProps) {
  if (!findings || findings.length === 0) {
    return <span className="text-xs text-gray-400">—</span>;
  }
  return (
    <div className="flex flex-col gap-1.5">
      {findings.map((f, i) => (
        <div key={i} className="flex items-center gap-2">
          <Badge variant="evidence" size="sm" label={evidenceLabel(f)} />
          <span className="text-xs font-medium text-gray-800">{f.type}</span>
          <span className="text-xs text-gray-400">· {f.detector}</span>
        </div>
      ))}
    </div>
  );
}

export default FindingsCell;
