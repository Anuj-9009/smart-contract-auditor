import React from 'react';

const SAMPLES = [
  { id: 'reentrancy_vulnerable', name: 'Reentrancy', tag: 'critical', icon: '⚡' },
  { id: 'access_control_flaw',  name: 'Access Control', tag: 'high', icon: '🔓' },
  { id: 'multiple_vulnerabilities', name: 'Multi-Vuln Auction', tag: 'critical', icon: '🎯' },
  { id: 'defi_vulnerable',      name: 'DeFi Lending', tag: 'high', icon: '💎' },
  { id: 'safe_contract',        name: 'Safe (OZ)', tag: 'safe', icon: '✓' },
];

const TAG_STYLES = {
  critical: { color: '#ef4444', bg: 'rgba(239,68,68,0.08)', border: 'rgba(239,68,68,0.2)' },
  high:     { color: '#f97316', bg: 'rgba(249,115,22,0.08)', border: 'rgba(249,115,22,0.2)' },
  safe:     { color: '#22c55e', bg: 'rgba(34,197,94,0.08)',  border: 'rgba(34,197,94,0.2)' },
};

export default function SampleSelector({ onSelect, disabled }) {
  return (
    <div className="flex flex-col gap-2">
      {SAMPLES.map((s) => {
        const t = TAG_STYLES[s.tag] || TAG_STYLES.high;
        return (
          <button
            key={s.id}
            onClick={() => onSelect(s.id)}
            disabled={disabled}
            className="glass flex items-center gap-3 px-4 py-3 text-left w-full
                       transition-all duration-200 hover:translate-x-1 disabled:opacity-40"
          >
            <span className="text-base shrink-0 w-6 text-center">{s.icon}</span>
            <span className="text-sm font-medium text-zinc-300 flex-1">{s.name}</span>
            <span
              className="text-[0.6rem] font-bold uppercase tracking-wider px-2 py-0.5 rounded"
              style={{ color: t.color, background: t.bg, border: `1px solid ${t.border}` }}
            >
              {s.tag}
            </span>
          </button>
        );
      })}
    </div>
  );
}
