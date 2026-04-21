import React, { useState, useEffect } from 'react';
import { auditContract, getSampleContract, getStats, getHistory, healthCheck } from './api';
import ResultsDisplay from './components/ResultsDisplay';
import RiskGauge from './components/RiskGauge';
import SampleSelector from './components/SampleSelector';

export default function App() {
  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [showReport, setShowReport] = useState(false);
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [health, setHealth] = useState(null);
  const [tab, setTab] = useState('samples');

  useEffect(() => {
    healthCheck().then(setHealth);
    getStats().then(setStats).catch(() => {});
    getHistory(6).then(d => setHistory(d.audits || [])).catch(() => {});
  }, []);

  const refresh = () => {
    getStats().then(setStats).catch(() => {});
    getHistory(6).then(d => setHistory(d.audits || [])).catch(() => {});
  };

  const handleAudit = async () => {
    if (!code.trim()) return;
    setLoading(true);
    setResult(null);
    setShowReport(false);
    try {
      const data = await auditContract(code);
      setResult(data);
      refresh();
    } catch (err) {
      alert('Audit failed: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSample = async (id) => {
    try {
      const data = await getSampleContract(id);
      setCode(data.code);
      setResult(null);
    } catch { /* ignore */ }
  };

  const lines = code.split('\n').length;

  return (
    <div className="min-h-screen">
      {/* ═══ Header ═══════════════════════════════════════════ */}
      <header className="sticky top-0 z-50 border-b border-zinc-800/60"
        style={{ background: 'rgba(9, 9, 11, 0.85)', backdropFilter: 'blur(12px)' }}>
        <div className="max-w-[1440px] mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3.5">
            <div className="w-9 h-9 rounded-lg flex items-center justify-center text-base
                            bg-gradient-to-br from-indigo-500 to-violet-600 shadow-lg shadow-indigo-500/20">
              🛡️
            </div>
            <div>
              <h1 className="text-sm font-bold tracking-tight text-zinc-100">
                Contract Auditor
              </h1>
              <p className="text-[0.6rem] uppercase tracking-[0.15em] text-zinc-600 font-medium">
                AI Security Analysis
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {health && (
              <span className="text-[0.65rem] text-zinc-600 font-mono hidden sm:block">
                {health.llm_provider !== 'none' ? health.llm_provider : 'patterns'}
              </span>
            )}
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-zinc-900/80 border border-zinc-800/60">
              <span className={`w-1.5 h-1.5 rounded-full ${health ? 'bg-emerald-500' : 'bg-amber-500'}`}
                style={{ boxShadow: health ? '0 0 6px rgba(34,197,94,0.5)' : '0 0 6px rgba(245,158,11,0.5)' }}
              />
              <span className="text-[0.68rem] text-zinc-500">
                {health ? 'Online' : '...'}
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* ═══ Main Grid ════════════════════════════════════════ */}
      <main className="max-w-[1440px] mx-auto px-6 py-7">
        <div className="grid grid-cols-1 lg:grid-cols-[1fr_340px] gap-6 items-start">

          {/* ── Left: Editor + Results ── */}
          <div className="space-y-6">

            {/* Code Editor */}
            <div className="glass p-6 animate-fade-up">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2.5">
                  <span className="text-xs">📝</span>
                  <span className="text-sm font-semibold text-zinc-200">Solidity Source</span>
                </div>
                <span className="text-[0.68rem] font-mono text-zinc-600">{lines} lines</span>
              </div>

              <textarea
                id="code-editor"
                className="code-input"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder={`// paste your contract here

pragma solidity ^0.8.0;

contract Example {
    mapping(address => uint256) public balances;
    
    function withdraw() external {
        uint256 amt = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}`}
                disabled={loading}
                spellCheck={false}
              />

              <div className="flex items-center justify-between mt-4 gap-3">
                <button
                  onClick={() => { setCode(''); setResult(null); }}
                  disabled={loading || !code}
                  className="text-[0.75rem] text-zinc-600 hover:text-zinc-400 transition-colors
                             disabled:opacity-30 cursor-pointer disabled:cursor-default"
                >
                  Clear
                </button>

                <button
                  id="audit-button"
                  onClick={handleAudit}
                  disabled={loading || !code.trim()}
                  className="px-6 py-3 rounded-xl text-sm font-bold text-white cursor-pointer
                             bg-gradient-to-r from-indigo-600 to-violet-600
                             hover:from-indigo-500 hover:to-violet-500
                             disabled:opacity-40 disabled:cursor-default
                             transition-all duration-300
                             shadow-lg shadow-indigo-500/20 hover:shadow-indigo-500/30"
                  style={loading ? {} : {}}
                >
                  {loading ? (
                    <span className="flex items-center gap-2.5">
                      <span className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full"
                        style={{ animation: 'spin 0.6s linear infinite' }} />
                      Analyzing...
                    </span>
                  ) : (
                    'Run Audit'
                  )}
                </button>
              </div>
            </div>

            {/* Results */}
            {result && (
              <div className="space-y-6 animate-fade-in">
                <RiskGauge
                  score={result.risk_score}
                  criticalCount={result.critical_count}
                  highCount={result.high_count}
                  mediumCount={result.medium_count}
                  lowCount={result.low_count}
                />

                {/* Engine info chip */}
                <div className="flex items-center justify-between">
                  <h2 className="text-sm font-semibold text-zinc-300">
                    {result.total_found > 0
                      ? `${result.total_found} vulnerabilities`
                      : 'No issues found'}
                  </h2>
                  <span className="text-[0.63rem] font-mono text-zinc-600">
                    {result.llm_provider !== 'none'
                      ? `${result.llm_provider} + patterns`
                      : 'pattern analysis'}
                  </span>
                </div>

                <ResultsDisplay result={result} />

                {/* Standards */}
                {result.standards_used?.length > 0 && (
                  <div className="glass p-5 animate-fade-up">
                    <span className="text-xs font-semibold text-zinc-400 block mb-3">
                      Security Standards Detected
                    </span>
                    <div className="flex flex-wrap gap-2">
                      {result.standards_used.map((s, i) => (
                        <span key={i}
                          className="text-[0.7rem] font-medium text-emerald-500 px-2.5 py-1 rounded-md"
                          style={{
                            background: 'rgba(34,197,94,0.06)',
                            border: '1px solid rgba(34,197,94,0.15)',
                          }}
                        >
                          ✓ {s}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Full report toggle */}
                <div className="glass overflow-hidden animate-fade-up">
                  <button
                    onClick={() => setShowReport(!showReport)}
                    className="w-full px-5 py-3.5 text-left text-[0.78rem] font-medium text-zinc-500
                               hover:text-zinc-300 transition-colors cursor-pointer"
                  >
                    {showReport ? '▾ Hide Report' : '▸ Full Report'}
                  </button>
                  {showReport && (
                    <div className="px-5 pb-5 max-h-[400px] overflow-y-auto">
                      <pre className="text-[0.72rem] leading-relaxed text-zinc-500 font-mono whitespace-pre-wrap">
                        {result.report}
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* ── Right: Sidebar ── */}
          <div className="space-y-5">

            {/* Stats */}
            {stats && (
              <div className="glass p-5 animate-fade-up" style={{ animationDelay: '0.1s' }}>
                <span className="text-xs font-semibold text-zinc-500 block mb-3.5">Stats</span>
                <div className="grid grid-cols-2 gap-3">
                  {[
                    { v: stats.total_audits, l: 'Audits' },
                    { v: stats.total_vulnerabilities, l: 'Vulns' },
                    { v: stats.critical_count, l: 'Critical', c: '#ef4444' },
                    { v: stats.high_count, l: 'High', c: '#f97316' },
                  ].map((s, i) => (
                    <div key={i} className="text-center py-3 rounded-lg bg-zinc-900/50 border border-zinc-800/40">
                      <div className="text-xl font-black"
                        style={{ color: s.c || '#818cf8' }}>{s.v}</div>
                      <div className="text-[0.6rem] uppercase tracking-wider text-zinc-600 mt-0.5">{s.l}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Tabs: Samples / History */}
            <div className="glass overflow-hidden animate-fade-up" style={{ animationDelay: '0.15s' }}>
              <div className="flex border-b border-zinc-800/60">
                {['samples', 'history'].map((t) => (
                  <button
                    key={t}
                    onClick={() => setTab(t)}
                    className={`flex-1 py-3 text-[0.72rem] font-semibold uppercase tracking-wider
                               transition-colors cursor-pointer
                               ${tab === t
                                 ? 'text-indigo-400 border-b-2 border-indigo-500'
                                 : 'text-zinc-600 hover:text-zinc-400'}`}
                  >
                    {t === 'samples' ? '⚡ Samples' : '📜 History'}
                  </button>
                ))}
              </div>

              <div className="p-4">
                {tab === 'samples' && (
                  <SampleSelector onSelect={handleSample} disabled={loading} />
                )}
                {tab === 'history' && (
                  history.length === 0 ? (
                    <p className="text-[0.75rem] text-zinc-600 text-center py-6">No audits yet</p>
                  ) : (
                    <div className="flex flex-col gap-2">
                      {history.map((h) => (
                        <div key={h.job_id}
                          className="flex items-center justify-between px-3.5 py-2.5 rounded-lg
                                     bg-zinc-900/40 border border-zinc-800/40"
                        >
                          <div className="min-w-0">
                            <div className="text-[0.78rem] font-medium text-zinc-300 truncate">
                              {h.contract_name || `#${h.job_id}`}
                            </div>
                            <div className="text-[0.6rem] text-zinc-600 font-mono">
                              {h.total_vulnerabilities} vulns
                            </div>
                          </div>
                          <span className="text-sm font-bold shrink-0 ml-3"
                            style={{
                              color: h.risk_score >= 75 ? '#ef4444'
                                : h.risk_score >= 50 ? '#f97316'
                                : h.risk_score >= 25 ? '#eab308'
                                : '#22c55e',
                            }}
                          >
                            {h.risk_score}
                          </span>
                        </div>
                      ))}
                    </div>
                  )
                )}
              </div>
            </div>

            {/* Coverage */}
            <div className="glass p-5 animate-fade-up" style={{ animationDelay: '0.2s' }}>
              <span className="text-xs font-semibold text-zinc-500 block mb-3">Detection Coverage</span>
              <div className="space-y-1.5 text-[0.72rem] text-zinc-500 font-mono">
                {[
                  ['critical', 'Reentrancy'],
                  ['critical', 'Selfdestruct'],
                  ['high', 'Access Control'],
                  ['high', 'Unchecked Calls'],
                  ['high', 'tx.origin'],
                  ['high', 'Delegatecall'],
                  ['medium', 'Timestamps'],
                  ['medium', 'Assembly'],
                  ['low', 'Floating Pragma'],
                ].map(([sev, name], i) => (
                  <div key={i} className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full shrink-0"
                      style={{
                        background:
                          sev === 'critical' ? '#ef4444' :
                          sev === 'high' ? '#f97316' :
                          sev === 'medium' ? '#eab308' : '#22c55e',
                      }}
                    />
                    {name}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
