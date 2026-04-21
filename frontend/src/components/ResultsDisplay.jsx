import React from 'react';

const SEV = {
  critical: { color: '#ef4444', glow: 'glow-critical', bar: 'sev-bar-critical', bg: 'bg-sev-critical-dim' },
  high:     { color: '#f97316', glow: 'glow-high',     bar: 'sev-bar-high',     bg: 'bg-sev-high-dim' },
  medium:   { color: '#eab308', glow: 'glow-medium',   bar: 'sev-bar-medium',   bg: 'bg-sev-medium-dim' },
  low:      { color: '#22c55e', glow: 'glow-low',      bar: 'sev-bar-low',      bg: 'bg-sev-low-dim' },
};

function VulnCard({ vuln, index }) {
  const s = SEV[vuln.severity] || SEV.medium;

  return (
    <div
      className={`glass ${s.glow} animate-fade-up overflow-hidden`}
      style={{ animationDelay: `${index * 0.07}s` }}
    >
      {/* Severity accent bar */}
      <div className={`sev-bar ${s.bar}`} />

      <div className="p-5">
        {/* Header row */}
        <div className="flex items-start justify-between gap-3 mb-3">
          <h3
            className="text-sm font-bold tracking-wide uppercase"
            style={{ color: s.color }}
          >
            {vuln.type?.replace(/_/g, ' ')}
          </h3>
          <span
            className="shrink-0 text-[0.65rem] font-bold uppercase tracking-wider px-2.5 py-1 rounded-md"
            style={{
              color: s.color,
              background: `${s.color}15`,
              border: `1px solid ${s.color}30`,
            }}
          >
            {vuln.severity}
          </span>
        </div>

        {/* Meta chips */}
        <div className="flex gap-3 mb-3">
          <span className="text-xs text-zinc-500 font-mono">
            ln:{vuln.line || '—'}
          </span>
          <span className="text-xs text-zinc-500 font-mono">
            {vuln.confidence}% conf
          </span>
        </div>

        {/* Description */}
        <p className="text-[0.8rem] leading-relaxed text-zinc-400 mb-4">
          {vuln.description}
        </p>

        {/* Fix recommendation */}
        {vuln.fix && (
          <div className="rounded-lg p-3.5 border"
            style={{
              background: 'rgba(34, 197, 94, 0.04)',
              borderColor: 'rgba(34, 197, 94, 0.12)',
            }}
          >
            <span className="text-[0.65rem] font-bold uppercase tracking-wider text-emerald-500 block mb-1">
              Fix
            </span>
            <p className="text-[0.78rem] leading-relaxed text-zinc-400">
              {vuln.fix}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

export default function ResultsDisplay({ result }) {
  const vulns = result.vulnerabilities || [];

  if (vulns.length === 0) {
    return (
      <div className="glass p-12 text-center animate-fade-in">
        <div className="text-5xl mb-4">🛡️</div>
        <h2 className="text-lg font-bold text-emerald-400 mb-1">Clean Contract</h2>
        <p className="text-sm text-zinc-500">No vulnerabilities detected. Follows security best practices.</p>
      </div>
    );
  }

  // Manual masonry: split cards into columns
  const cols = 2;
  const columns = Array.from({ length: cols }, () => []);
  vulns.forEach((v, i) => columns[i % cols].push({ ...v, _idx: i }));

  return (
    <div className="masonry-grid">
      {columns.map((col, ci) => (
        <div key={ci} className="masonry-column">
          {col.map((vuln) => (
            <VulnCard key={vuln._idx} vuln={vuln} index={vuln._idx} />
          ))}
        </div>
      ))}
    </div>
  );
}
