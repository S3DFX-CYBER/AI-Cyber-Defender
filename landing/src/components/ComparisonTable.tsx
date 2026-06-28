import React from 'react';

interface RowData {
  capability: string;
  icon: React.ReactNode;
  keyword: 'yes' | 'no' | 'partial';
  ruleBased: 'yes' | 'no' | 'partial';
  tenet: 'yes' | 'no' | 'partial';
}

const ShieldIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4"/><path d="M10 10h4"/></svg>
);
const CircuitIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></svg>
);
const ScannerIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/><path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/><circle cx="12" cy="12" r="3"/><path d="M12 9v-2"/><path d="M12 17v2"/><path d="M15 12h2"/><path d="M9 12H7"/></svg>
);
const RobotIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="10" rx="2"/><circle cx="12" cy="5" r="2"/><path d="M12 7v4"/><line x1="8" y1="16" x2="8" y2="16"/><line x1="16" y1="16" x2="16" y2="16"/></svg>
);
const GridIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/></svg>
);
const LinkIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
);

const ROWS: RowData[] = [
  { capability: 'Zero-latency Heuristic Scans', icon: <ShieldIcon/>, keyword: 'yes', ruleBased: 'yes', tenet: 'yes' },
  { capability: 'Context-aware ML Signature Scan', icon: <CircuitIcon/>, keyword: 'no', ruleBased: 'no', tenet: 'yes' },
  { capability: 'Multi-session Jailbreak Tracking', icon: <ScannerIcon/>, keyword: 'no', ruleBased: 'partial', tenet: 'yes' },
  { capability: 'Adaptive Self-learning Classification', icon: <RobotIcon/>, keyword: 'no', ruleBased: 'no', tenet: 'yes' },
  { capability: 'Dynamic Payload Sanitization', icon: <GridIcon/>, keyword: 'partial', ruleBased: 'partial', tenet: 'yes' },
  { capability: 'Cross-LLM Portability', icon: <LinkIcon/>, keyword: 'no', ruleBased: 'yes', tenet: 'yes' }
];

export default function ComparisonTable() {
  const renderIcon = (val: 'yes' | 'no' | 'partial') => {
    if (val === 'yes') {
      return (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#15803D' }}>
          <svg width="14" height="14" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="10 3 4.5 8.5 2 6" />
          </svg>
          <span style={{ fontSize: '12px', fontWeight: 600 }}>Full</span>
        </span>
      );
    } else if (val === 'no') {
      return (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#EF4444' }}>
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <line x1="10" y1="2" x2="2" y2="10" />
            <line x1="2" y1="2" x2="10" y2="10" />
          </svg>
          <span style={{ fontSize: '12px', fontWeight: 600 }}>None</span>
        </span>
      );
    } else {
      return (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#F59E0B' }}>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26" />
          </svg>
          <span style={{ fontSize: '12px', fontWeight: 600 }}>Partial</span>
        </span>
      );
    }
  };

  return (
    <section className="section" id="compare" aria-label="Feature Comparison">
      <div className="container">
        <div style={{ marginBottom: 40 }}>
          <div className="eyebrow">Comparison</div>
          <h2 className="section-title">Elevate security <span className="grad">beyond filters</span></h2>
          <p className="section-sub">Standard filters block regular words or fail under slightly obfuscated inputs. TENET AI provides true stateful semantic shielding.</p>
        </div>

        <div className="compare-wrap" style={{ background: '#FFFFFF', border: '1px solid #F1F5F9', borderRadius: '12px', boxShadow: '0 4px 20px rgba(0,0,0,0.03)' }}>
          <table className="compare-table" style={{ borderCollapse: 'collapse', width: '100%' }}>
            <thead>
              <tr>
                <th scope="col" style={{ width: '37%', color: '#A855F7' }}>CAPABILITY</th>
                <th scope="col" className="text-center" style={{ width: '21%', color: '#A855F7' }}>
                  <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
                    <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#A855F7' }} />
                    KEYWORD FILTERS
                  </div>
                </th>
                <th scope="col" className="text-center" style={{ width: '21%', color: '#A855F7' }}>
                  <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
                    <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#EC4899' }} />
                    RULE-BASED TOOLS
                  </div>
                </th>
                <th scope="col" className="text-center" style={{ width: '21%', color: '#A855F7', background: '#FAF5FF', borderLeft: '1px solid #F3E8FF', borderRight: '1px solid #F3E8FF', borderTop: '1px solid #F3E8FF', borderRadius: '12px 12px 0 0' }}>
                  <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
                    <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#F59E0B' }} />
                    TENET AI FIREWALL
                  </div>
                </th>
              </tr>
            </thead>
            <tbody>
              {ROWS.map((row, idx) => (
                <tr key={idx} style={{ background: '#FFFFFF', borderTop: '1px solid #F8FAFC' }}>
                  <td style={{ border: 'none' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '16px', color: '#0F172A', fontWeight: 500, fontSize: '13px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: '36px', height: '36px', borderRadius: '10px', background: '#F3E8FF', color: '#A855F7', flexShrink: 0 }}>
                        {row.icon}
                      </div>
                      {row.capability}
                    </div>
                  </td>
                  <td className="text-center" style={{ borderTop: '1px solid #F8FAFC' }}>{renderIcon(row.keyword)}</td>
                  <td className="text-center" style={{ borderTop: '1px solid #F8FAFC' }}>{renderIcon(row.ruleBased)}</td>
                  <td className="text-center" style={{ background: '#FAF5FF', borderLeft: '1px solid #F3E8FF', borderRight: '1px solid #F3E8FF', borderTop: '1px solid #F3E8FF' }}>
                    {renderIcon(row.tenet)}
                  </td>
                </tr>
              ))}

              {/* Summary progress bar row */}
              <tr className="compare-summary-row" style={{ background: '#FFFFFF', borderTop: '1px solid #F8FAFC' }}>
                <td style={{ color: '#0F172A', fontWeight: 700, fontSize: '14px', padding: '24px', border: 'none' }}>Overall Protection Rating</td>
                <td className="text-center" style={{ borderTop: '1px solid #F8FAFC' }}>
                  <div className="progress-bar" title="1 out of 3 rating" style={{ justifyContent: 'center', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <div style={{ width: '24px', height: '4px', borderRadius: '2px', background: '#EF4444' }} />
                    <div style={{ width: '24px', height: '4px', borderRadius: '2px', background: '#E2E8F0' }} />
                    <div style={{ width: '24px', height: '4px', borderRadius: '2px', background: '#E2E8F0' }} />
                    <span style={{ marginLeft: '8px', fontSize: '12px', fontFamily: 'var(--mono)', color: '#64748B', fontWeight: 600 }}>Weak</span>
                  </div>
                </td>
                <td className="text-center" style={{ borderTop: '1px solid #F8FAFC' }}>
                  <div className="progress-bar" title="2 out of 3 rating" style={{ justifyContent: 'center', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <div style={{ width: '24px', height: '4px', borderRadius: '2px', background: '#F59E0B' }} />
                    <div style={{ width: '24px', height: '4px', borderRadius: '2px', background: '#F59E0B' }} />
                    <div style={{ width: '24px', height: '4px', borderRadius: '2px', background: '#E2E8F0' }} />
                    <span style={{ marginLeft: '8px', fontSize: '12px', fontFamily: 'var(--mono)', color: '#64748B', fontWeight: 600 }}>Medium</span>
                  </div>
                </td>
                <td className="text-center" style={{ background: '#FAF5FF', borderLeft: '1px solid #F3E8FF', borderRight: '1px solid #F3E8FF', borderTop: '1px solid #F3E8FF', borderBottom: '1px solid #F3E8FF', borderRadius: '0 0 12px 12px' }}>
                  <div className="progress-bar" title="3 out of 3 rating" style={{ justifyContent: 'center', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <div style={{ width: '24px', height: '4px', borderRadius: '2px', background: '#22C55E' }} />
                    <div style={{ width: '24px', height: '4px', borderRadius: '2px', background: '#22C55E' }} />
                    <div style={{ width: '24px', height: '4px', borderRadius: '2px', background: '#22C55E' }} />
                    <span style={{ marginLeft: '8px', fontSize: '12px', fontFamily: 'var(--mono)', color: '#15803D', fontWeight: 600 }}>Maximum</span>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}
