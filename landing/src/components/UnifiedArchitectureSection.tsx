import React from 'react';

export default function UnifiedArchitectureSection() {
  return (
    <section className="section section-alt" id="pipeline" aria-label="System Architecture and Pipeline">
      <div className="container">
        <div style={{ marginBottom: 48 }}>
          <div className="eyebrow" style={{ color: 'var(--purple)' }}>System Topology</div>
          <h2 className="section-title" style={{ color: '#0F172A' }}>Decentralized, high-performance <span style={{ color: '#A855F7' }}>middleware topology</span></h2>
          <p className="section-sub" style={{ color: '#64748B' }}>TENET AI coordinates safety actions directly inside your cluster using parallel detection engines.</p>
        </div>

        {/* TOPOLOGY DIAGRAM */}
        <div className="arch-diagram-card">
          <div style={{ minWidth: '950px', position: 'relative', padding: '0 40px' }}>
            <svg 
              width="100%" 
              viewBox="0 0 1080 500" 
              fill="none" 
              xmlns="http://www.w3.org/2000/svg" 
              style={{ overflow: 'visible' }}
              role="img"
              aria-labelledby="system-topology-title system-topology-desc"
            >
              <title id="system-topology-title">TENET AI system topology and decision pipeline</title>
              <desc id="system-topology-desc">
                Requests flow from application inputs into TENET SDK, through parallel detection engines block, flag, sanitize, or allow.
              </desc>
              <defs>
                <style dangerouslySetInnerHTML={{ __html: `
                  .dash-line {
                    stroke: #CBD5E1;
                    stroke-width: 2;
                    stroke-dasharray: 6 6;
                    fill: none;
                    animation: dashAnim 20s linear infinite;
                  }
                  .dash-line.python { stroke: #A855F7; }
                  .dash-line.node { stroke: #F59E0B; }
                  .dash-line.docker { stroke: #3B82F6; }
                  .dash-line.cloud { stroke: #EC4899; }
                  .dash-line.block { stroke: #EF4444; }
                  .dash-line.flag { stroke: #F59E0B; }
                  .dash-line.sanitize { stroke: #EAB308; }
                  .dash-line.allow { stroke: #22C55E; }
                  @keyframes dashAnim {
                    to { stroke-dashoffset: -1000; }
                  }
                  .step-label { font-family: var(--font); font-size: 13px; font-weight: 700; fill: #A855F7; letter-spacing: 0.05em; }
                  .step-title { font-family: var(--font); font-size: 16px; font-weight: 800; fill: #0F172A; }
                `}} />
              </defs>

              {/* STEP LABELS */}
              {/* Step 1 */}
              <g transform="translate(340, 30)">
                <text className="step-label" x="0" y="0" textAnchor="middle">STEP 1</text>
                <text className="step-title" x="0" y="20" textAnchor="middle">Intercept</text>
                <foreignObject x="-80" y="30" width="160" height="80">
                  <div xmlns="http://www.w3.org/1999/xhtml" style={{ fontSize: '11px', color: '#64748B', textAlign: 'center', lineHeight: 1.5 }}>
                    Middleware captures all outbound prompts before they reach any LLM API endpoint.
                  </div>
                </foreignObject>
              </g>
              
              {/* Step 2 */}
              <g transform="translate(575, 30)">
                <text className="step-label" x="0" y="0" textAnchor="middle">STEP 2</text>
                <text className="step-title" x="0" y="20" textAnchor="middle">Analyze</text>
                <foreignObject x="-90" y="30" width="180" height="80">
                  <div xmlns="http://www.w3.org/1999/xhtml" style={{ fontSize: '11px', color: '#64748B', textAlign: 'center', lineHeight: 1.5 }}>
                    Heuristic rules, ML classifier, and behavioral engine run in parallel for full-spectrum coverage.
                  </div>
                </foreignObject>
              </g>

              {/* Step 3 */}
              <g transform="translate(960, 30)">
                <text className="step-label" x="0" y="0" textAnchor="middle">STEP 3</text>
                <text className="step-title" x="0" y="20" textAnchor="middle">Decide</text>
                <foreignObject x="-90" y="30" width="180" height="80">
                  <div xmlns="http://www.w3.org/1999/xhtml" style={{ fontSize: '11px', color: '#64748B', textAlign: 'center', lineHeight: 1.5 }}>
                    Policy engine issues a verdict — Block / Sanitize / Flag / Allow — within the 10ms budget.
                  </div>
                </foreignObject>
              </g>

              <g transform="translate(0, 70)">
              {/* CONNECTING LINES */}
              {/* Inputs to Middleware */}
              <path className="dash-line python" d="M 210 100 C 250 100, 250 220, 280 220" />
              <path className="dash-line node" d="M 210 180 C 250 180, 250 230, 280 230" />
              <path className="dash-line docker" d="M 210 260 C 250 260, 250 240, 280 240" />
              <path className="dash-line cloud" d="M 210 340 C 250 340, 250 250, 280 250" />

              {/* Middleware to Engines */}
              <path className="dash-line" d="M 400 235 C 440 235, 440 130, 480 130" stroke="#A855F7" />
              <path className="dash-line" d="M 400 235 L 480 235" stroke="#A855F7" />
              <path className="dash-line" d="M 400 235 C 440 235, 440 340, 480 340" stroke="#A855F7" />

              {/* Engines to Policy */}
              <path className="dash-line" d="M 670 130 C 710 130, 710 235, 760 235" stroke="#A855F7" />
              <path className="dash-line" d="M 670 235 L 760 235" stroke="#A855F7" />
              <path className="dash-line" d="M 670 340 C 710 340, 710 235, 760 235" stroke="#A855F7" />

              {/* Policy to Outputs */}
              <path className="dash-line block" d="M 820 235 C 850 235, 850 100, 880 100" />
              <path className="dash-line flag" d="M 820 235 C 850 235, 850 190, 880 190" />
              <path className="dash-line sanitize" d="M 820 235 C 850 235, 850 280, 880 280" />
              <path className="dash-line allow" d="M 820 235 C 850 235, 850 370, 880 370" />

              {/* BLOCKS */}
              {/* Inputs */}
              <g transform="translate(20, 70)">
                <rect width="190" height="60" rx="8" fill="#FFFFFF" stroke="#E2E8F0" strokeWidth="1.5" />
                <rect x="15" y="15" width="30" height="30" rx="6" fill="#F3E8FF" />
                <svg x="20" y="20" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#A855F7" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                <text x="60" y="30" fill="#0F172A" fontSize="13" fontWeight="700">Python App</text>
                <text x="60" y="46" fill="#64748B" fontSize="11">Python</text>
              </g>

              <g transform="translate(20, 150)">
                <rect width="190" height="60" rx="8" fill="#FFFFFF" stroke="#E2E8F0" strokeWidth="1.5" />
                <rect x="15" y="15" width="30" height="30" rx="6" fill="#DCFCE7" />
                <svg x="20" y="20" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#22C55E" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>
                <text x="60" y="30" fill="#0F172A" fontSize="13" fontWeight="700">Node.js App</text>
                <text x="60" y="46" fill="#64748B" fontSize="11">Node.js</text>
              </g>

              <g transform="translate(20, 230)">
                <rect width="190" height="60" rx="8" fill="#FFFFFF" stroke="#E2E8F0" strokeWidth="1.5" />
                <rect x="15" y="15" width="30" height="30" rx="6" fill="#DBEAFE" />
                <svg x="20" y="20" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#3B82F6" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/></svg>
                <text x="60" y="30" fill="#0F172A" fontSize="13" fontWeight="700">Docker Image</text>
                <text x="60" y="46" fill="#64748B" fontSize="11">Self-hosted REST API</text>
              </g>

              <g transform="translate(20, 310)">
                <rect width="190" height="60" rx="8" fill="#FFFFFF" stroke="#E2E8F0" strokeWidth="1.5" />
                <rect x="15" y="15" width="30" height="30" rx="6" fill="#FEF3C7" />
                <svg x="20" y="20" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#F59E0B" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z"/></svg>
                <text x="60" y="30" fill="#0F172A" fontSize="13" fontWeight="700">Cloud Templates</text>
                <text x="60" y="46" fill="#64748B" fontSize="11">Infrastructure-as-code</text>
              </g>

              {/* TENET SDK (Middleware) */}
              <g transform="translate(280, 160)">
                <rect width="120" height="150" rx="12" fill="#FAF5FF" stroke="#D8B4FE" strokeWidth="2" />
                <rect x="40" y="20" width="40" height="40" rx="8" fill="#FFFFFF" stroke="#E9D5FF" strokeWidth="1.5" />
                <svg x="48" y="28" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#A855F7" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>
                <text x="60" y="85" textAnchor="middle" fill="#0F172A" fontSize="13" fontWeight="700">TENET SDK</text>
                <text x="60" y="105" textAnchor="middle" fill="#64748B" fontSize="11">Core Proxy Layer</text>
                <rect x="15" y="120" width="90" height="20" rx="10" fill="#F3E8FF" />
                <text x="60" y="134" textAnchor="middle" fill="#A855F7" fontSize="10" fontWeight="700">&lt;10ms latency</text>
              </g>

              {/* PARALLEL ENGINES DASHED BOX */}
              <rect x="450" y="70" width="250" height="330" rx="16" fill="none" stroke="#E2E8F0" strokeWidth="1.5" strokeDasharray="8 8" />
              <text x="575" y="90" textAnchor="middle" fill="#A855F7" fontSize="11" fontWeight="700" letterSpacing="0.05em">PARALLEL DETECTION ENGINES</text>

              {/* Engines */}
              <g transform="translate(480, 100)">
                <rect width="190" height="60" rx="8" fill="#FFFFFF" stroke="#E2E8F0" strokeWidth="1.5" />
                <svg x="15" y="15" width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#22C55E" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
                <text x="55" y="30" fill="#0F172A" fontSize="13" fontWeight="700">Heuristics Engine</text>
                <text x="55" y="46" fill="#64748B" fontSize="11">Known signatures</text>
              </g>

              <g transform="translate(480, 205)">
                <rect width="190" height="60" rx="8" fill="#FAF5FF" stroke="#D8B4FE" strokeWidth="1.5" />
                <svg x="15" y="15" width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#A855F7" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2v20"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>
                <text x="55" y="30" fill="#0F172A" fontSize="13" fontWeight="700">ML Classifier</text>
                <text x="55" y="46" fill="#64748B" fontSize="11">Adversarial matching</text>
              </g>

              <g transform="translate(480, 310)">
                <rect width="190" height="60" rx="8" fill="#FFFFFF" stroke="#E2E8F0" strokeWidth="1.5" />
                <svg x="15" y="15" width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#3B82F6" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
                <text x="55" y="30" fill="#0F172A" fontSize="13" fontWeight="700">Behavioral tracker</text>
                <text x="55" y="46" fill="#64748B" fontSize="11">Cross-session chains</text>
              </g>

              {/* Policy Diamond */}
              <g transform="translate(770, 235)">
                <polygon points="50,0 100,50 50,100 0,50" fill="#FAF5FF" stroke="#E2E8F0" strokeWidth="1.5" transform="translate(-50, -50)" />
                <svg x="-12" y="-22" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#A855F7" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                <text x="0" y="15" textAnchor="middle" fill="#0F172A" fontSize="13" fontWeight="700">Policy</text>
                <text x="0" y="28" textAnchor="middle" fill="#0F172A" fontSize="13" fontWeight="700">Engine</text>
              </g>

              {/* OUTPUTS */}
              <g transform="translate(880, 70)">
                <rect width="160" height="60" rx="8" fill="#FEF2F2" stroke="#EF4444" strokeWidth="1.5" />
                <svg x="10" y="15" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#EF4444" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
                <text x="40" y="28" fill="#EF4444" fontSize="13" fontWeight="800">BLOCK (403)</text>
                <text x="40" y="44" fill="#64748B" fontSize="11">Heuristic block</text>
              </g>

              <g transform="translate(880, 160)">
                <rect width="160" height="60" rx="8" fill="#FFFBEB" stroke="#FBBF24" strokeWidth="1.5" />
                <svg x="10" y="15" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#F59E0B" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/></svg>
                <text x="40" y="28" fill="#F59E0B" fontSize="13" fontWeight="800">FLAG</text>
                <text x="40" y="44" fill="#64748B" fontSize="11">Flag for review</text>
              </g>

              <g transform="translate(880, 250)">
                <rect width="160" height="60" rx="8" fill="#FFFBEB" stroke="#FDE047" strokeWidth="1.5" />
                <svg x="10" y="15" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#EAB308" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>
                <text x="40" y="28" fill="#EAB308" fontSize="13" fontWeight="800">SANITIZE</text>
                <text x="40" y="44" fill="#64748B" fontSize="11">Modify &amp; remove risk</text>
              </g>

              <g transform="translate(880, 340)">
                <rect width="160" height="60" rx="8" fill="#F0FDF4" stroke="#22C55E" strokeWidth="1.5" />
                <svg x="10" y="15" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#22C55E" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                <text x="40" y="28" fill="#22C55E" fontSize="13" fontWeight="800">ALLOW</text>
                <text x="40" y="44" fill="#64748B" fontSize="11">Forward to LLM</text>
              </g>

              </g>

            </svg>
          </div>

          {/* BOTTOM PIPELINE SECTION: STEP 4 LEARN (COMPACT) */}
          <div className="arch-bottom-bar">
            
            <div style={{ flexShrink: 0, display: 'flex', flexDirection: 'column', gap: '2px' }}>
              <div style={{ fontSize: '11px', fontWeight: 800, color: '#A855F7', letterSpacing: '0.05em', textTransform: 'uppercase' }}>STEP 4</div>
              <h3 style={{ fontSize: '18px', fontWeight: 800, color: '#0F172A', margin: 0, display: 'flex', alignItems: 'center', gap: '6px' }}>
                Learn
                <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#A855F7' }} />
              </h3>
              <p style={{ fontSize: '11px', color: '#64748B', lineHeight: 1.5, margin: '6px 0 0 0', maxWidth: '160px' }}>
                Analyst feedback and shared threat intelligence continuously improve detection accuracy.
              </p>
            </div>

            <div className="arch-bottom-divider" />

            <div className="arch-step4-grid">
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                <div style={{ color: '#A855F7', marginTop: '2px' }}><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg></div>
                <div>
                  <h4 style={{ fontSize: '12px', fontWeight: 700, color: '#0F172A', margin: '0 0 2px 0' }}>Threat Intel</h4>
                  <p style={{ fontSize: '11px', color: '#64748B', lineHeight: 1.4, margin: 0 }}>New patterns recorded</p>
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                <div style={{ color: '#A855F7', marginTop: '2px' }}><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 7 13.5 15.5 8.5 10.5 2 17"/><polyline points="16 7 22 7 22 13"/></svg></div>
                <div>
                  <h4 style={{ fontSize: '12px', fontWeight: 700, color: '#0F172A', margin: '0 0 2px 0' }}>Retraining</h4>
                  <p style={{ fontSize: '11px', color: '#64748B', lineHeight: 1.4, margin: 0 }}>Continuous accuracy</p>
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                <div style={{ color: '#A855F7', marginTop: '2px' }}><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg></div>
                <div>
                  <h4 style={{ fontSize: '12px', fontWeight: 700, color: '#0F172A', margin: '0 0 2px 0' }}>Analyst Feedback</h4>
                  <p style={{ fontSize: '11px', color: '#64748B', lineHeight: 1.4, margin: 0 }}>Fine-tune rules</p>
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                <div style={{ color: '#A855F7', marginTop: '2px' }}><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg></div>
                <div>
                  <h4 style={{ fontSize: '12px', fontWeight: 700, color: '#0F172A', margin: '0 0 2px 0' }}>Stronger Tomorrow</h4>
                  <p style={{ fontSize: '11px', color: '#64748B', lineHeight: 1.4, margin: 0 }}>Smart interactions</p>
                </div>
              </div>
            </div>
          </div>
        </div>

      </div>
    </section>
  );
}
