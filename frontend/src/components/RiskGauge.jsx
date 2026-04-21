import React from 'react';

export default function RiskGauge({ score, criticalCount, highCount, mediumCount, lowCount }) {
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  let color = '#22c55e';
  let label = 'LOW';
  if (score >= 75) { color = '#ef4444'; label = 'CRITICAL'; }
  else if (score >= 50) { color = '#f97316'; label = 'HIGH'; }
  else if (score >= 25) { color = '#eab308'; label = 'MEDIUM'; }

  const badges = [
    { count: criticalCount, label: 'Critical', color: '#ef4444' },
    { count: highCount, label: 'High', color: '#f97316' },
    { count: mediumCount, label: 'Medium', color: '#eab308' },
    { count: lowCount, label: 'Low', color: '#22c55e' },
  ].filter(b => b.count > 0);

  return (
    <div className="glass p-6 animate-fade-up">
      <div className="flex items-center gap-6">
        {/* Ring */}
        <div className="relative shrink-0" style={{ width: 120, height: 120 }}>
          <svg width="120" height="120" viewBox="0 0 120 120" style={{ transform: 'rotate(-90deg)' }}>
            <circle className="risk-ring-bg" cx="60" cy="60" r={radius} />
            <circle
              className="risk-ring-fill"
              cx="60" cy="60" r={radius}
              stroke={color}
              strokeDasharray={circumference}
              strokeDashoffset={offset}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-3xl font-black" style={{ color }}>{score}</span>
            <span className="text-[0.6rem] uppercase tracking-widest text-zinc-500 mt-0.5">Risk</span>
          </div>
        </div>

        {/* Info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2.5 mb-3">
            <span
              className="text-[0.65rem] font-bold uppercase tracking-wider px-2.5 py-1 rounded-md"
              style={{
                color,
                background: `${color}15`,
                border: `1px solid ${color}30`,
              }}
            >
              {label} Risk
            </span>
          </div>

          {badges.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {badges.map((b) => (
                <span
                  key={b.label}
                  className="text-[0.7rem] font-semibold px-2 py-0.5 rounded"
                  style={{
                    color: b.color,
                    background: `${b.color}10`,
                    border: `1px solid ${b.color}20`,
                  }}
                >
                  {b.count} {b.label}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-xs text-zinc-500">No issues found</p>
          )}
        </div>
      </div>
    </div>
  );
}
