import React, { useState, useEffect, useRef } from 'react';

interface InstallItem {
  icon: React.ReactNode;
  plat: string;
  title: string;
  sub: string;
  cmd: string;
  feats: string[];
}

const INSTALLS: InstallItem[] = [
  {
    icon: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 2c5.522 0 10 2.2 10 4.9v9.2c0 2.7-4.478 4.9-10 4.9s-10-2.2-10-4.9V6.9C2 4.2 6.478 2 12 2z" />
        <path d="M22 6.9c0 2.7-4.478 4.9-10 4.9S2 9.6 2 6.9" />
        <path d="M2 11.5c0 2.7 4.478 4.9 10 4.9s10-2.2 10-4.9" />
      </svg>
    ),
    plat: 'Python',
    title: 'Python SDK',
    sub: 'Async-first middleware for Python apps',
    cmd: 'pip install tenet-ai',
    feats: ['FastAPI / Django / Flask', 'LangChain & LlamaIndex', 'Full async/await support', 'Complete type hints']
  },
  {
    icon: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="21 16 12 21 3 16 3 8 12 3 21 8 21 16" />
        <polyline points="3 8 12 13 21 8" />
        <line x1="12" y1="13" x2="12" y2="21" />
      </svg>
    ),
    plat: 'Node.js',
    title: 'Node.js Package',
    sub: 'TypeScript-native NPM package',
    cmd: 'npm install @tenet-ai/sdk',
    feats: ['Express / Next.js middleware', 'Cloudflare Workers support', 'TypeScript out of the box', 'Edge runtime compatible']
  },
  {
    icon: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="2" y="10" width="20" height="8" rx="2" />
        <line x1="6" y1="10" x2="6" y2="18" />
        <line x1="10" y1="10" x2="10" y2="18" />
        <line x1="14" y1="10" x2="14" y2="18" />
        <line x1="18" y1="10" x2="18" y2="18" />
        <path d="M6 6h4v4H6z" fill="currentColor" opacity="0.3" />
        <path d="M14 6h4v4h-4z" fill="currentColor" opacity="0.3" />
      </svg>
    ),
    plat: 'Docker',
    title: 'Docker Image',
    sub: 'Self-hosted REST API + SOC dashboard',
    cmd: 'docker pull tenetai/core',
    feats: ['One-command deployment', 'SOC dashboard included', 'Prometheus + Grafana ready', 'PostgreSQL + Redis bundled']
  },
  {
    icon: (
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z" />
      </svg>
    ),
    plat: 'Cloud',
    title: 'Cloud Templates',
    sub: 'Infrastructure-as-code for all major clouds',
    cmd: 'helm install tenet-ai ./chart',
    feats: ['AWS Lambda layer', 'Azure Functions extension', 'GCP Cloud Run template', 'Kubernetes Helm chart']
  }
];

function FadeUp({ children, delay = 0 }: { children: React.ReactNode; delay?: number }) {
  const ref = useRef<HTMLDivElement>(null);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting) {
        setVisible(true);
        observer.disconnect();
      }
    }, { threshold: 0.05 });

    if (ref.current) {
      observer.observe(ref.current);
    }
    return () => observer.disconnect();
  }, []);

  return (
    <div
      ref={ref}
      style={{
        opacity: visible ? 1 : 0,
        transform: visible ? 'none' : 'translateY(16px)',
        transition: `opacity 0.5s ${delay}s ease-out, transform 0.5s ${delay}s ease-out`
      }}
    >
      {children}
    </div>
  );
}

export default function InstallSection() {
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  const handleCopy = (cmd: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedCmd(cmd);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  const renderCodeForPlatform = (plat: string) => {
    if (plat === 'Python') {
      return (
        <code style={{ fontFamily: 'var(--mono)' }}>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>1</span><span><span className="cc"># 1. Install</span> <span className="ck">import</span> <span className="cy">tenet_ai</span></span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>2</span><span><span className="cc"># 2. Initialize</span> <span>tenet</span> = tenet_ai.<span className="cf">Client</span>(<span>api_key</span>=<span className="cs">"your-key"</span>)</span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>3</span><span><span className="cc"># 3. Intercept before any LLM call</span></span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>4</span><span>user_input = <span className="cs">"Summarize the latest earnings report."</span></span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>5</span><span>result = tenet.<span className="cf">check</span>(prompt=user_input, user_id=<span className="cs">"u-123"</span>)</span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>6</span><span><span className="ck">if</span> result.blocked:</span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>7</span><span>{'    '}<span className="ck">return</span> <span className="cs">"⛔ Blocked"</span>  <span className="cc"># &lt;5ms</span></span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>8</span><span></span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>9</span><span><span className="cc"># 4. Safe - call any LLM normally</span></span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>10</span><span><span className="cc"># OpenAI</span></span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>11</span><span>response = openai.<span className="cf">chat</span>(user_input)</span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>12</span><span></span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>13</span><span><span className="cc"># Claude</span></span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>14</span><span>response = anthropic.<span className="cf">message</span>(user_input)</span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>15</span><span></span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>16</span><span><span className="cc"># Local</span></span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>17</span><span>response = ollama.<span className="cf">generate</span>(user_input)</span></div>
        </code>
      );
    } else if (plat === 'Node.js') {
      return (
        <code style={{ fontFamily: 'var(--mono)' }}>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>1</span><span><span className="ck">import</span> {'{ TenetClient }'} <span className="ck">from</span> <span className="cs">'@tenet-ai/sdk'</span>;</span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>2</span><span></span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>3</span><span><span className="ck">const</span> tenet = <span className="ck">new</span> <span className="cf">TenetClient</span>({'{'} apiKey: <span className="cs">'your-key'</span> {'}'});</span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>4</span><span></span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>5</span><span><span className="cc">// Intercept as express middleware</span></span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>6</span><span>app.<span className="cf">post</span>(<span className="cs">'/chat'</span>, <span className="ck">async</span> (req, res) =&gt; {'{'}</span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>7</span><span>{'  '}<span className="ck">const</span> result = <span className="ck">await</span> tenet.<span className="cf">check</span>(req.body.prompt);</span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>8</span><span></span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>9</span><span>{'  '}<span className="ck">if</span> (result.blocked) {'{'}</span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>10</span><span>{'    '}<span className="ck">return</span> res.<span className="cf">status</span>(403).<span className="cf">json</span>({'{'} error: <span className="cs">'⛔ Blocked'</span> {'}'});</span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>11</span><span>{'  }'}</span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>12</span><span></span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>13</span><span>{'  '}<span className="cc">// Safe to call OpenAI / Anthropic</span></span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>14</span><span>{'  '}<span className="ck">const</span> llmResponse = <span className="ck">await</span> openai.<span className="cf">createChatCompletion</span>({'...'});</span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>15</span><span>{'  '}res.<span className="cf">json</span>(llmResponse.data);</span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>16</span><span>{'}'});</span></div>
        </code>
      );
    } else {
      return (
        <code style={{ fontFamily: 'var(--mono)' }}>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>1</span><span><span className="cc"># General CLI deployment</span></span></div>
          <div style={{ display: 'flex' }}><span style={{ opacity: 0.3, width: '32px', userSelect: 'none' }}>2</span><span>$ {plat === 'Docker' ? 'docker pull tenetai/core' : 'helm install tenet-ai ./chart'}</span></div>
        </code>
      );
    }
  };

  const selectedInstall = INSTALLS[selectedIndex];

  return (
    <section className="section" id="download" aria-label="Installation Instructions">
      <div className="container">
        <div className="install-layout-grid">
          
          {/* LEFT COLUMN: Tabs */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            <FadeUp>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '10.5px', fontFamily: 'var(--mono)', color: '#A855F7', letterSpacing: '0.14em', textTransform: 'uppercase', marginBottom: '14px', fontWeight: 600 }}>
                  <div style={{ width: '18px', height: '2px', background: '#A855F7' }}></div>
                  GET STARTED
                </div>
                <h2 className="section-title" style={{ fontSize: '42px', marginBottom: '16px' }}>
                  Install in <span style={{ color: '#A855F7' }}>minutes</span>
                </h2>
                <p className="section-sub" style={{ fontSize: '15px', color: '#64748B', maxWidth: '400px', margin: 0 }}>
                  One additional API call. Zero changes to your LLM integration.
                </p>
              </div>
            </FadeUp>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {INSTALLS.map((d, i) => {
                const isSelected = selectedIndex === i;
                return (
                  <FadeUp key={i} delay={i * 0.05}>
                    <div 
                      onClick={() => setSelectedIndex(i)}
                      className={`install-tab-card ${isSelected ? 'selected' : ''}`}
                    >
                      <div style={{ width: '48px', height: '48px', borderRadius: '12px', background: isSelected ? '#FFFFFF' : '#F8FAFC', display: 'flex', alignItems: 'center', justifyContent: 'center', color: isSelected ? '#22C55E' : '#A855F7', marginRight: '20px', flexShrink: 0, boxShadow: isSelected ? '0 2px 4px rgba(0,0,0,0.02)' : 'none' }}>
                        {d.icon}
                      </div>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: '16px', fontWeight: 800, color: '#0F172A', marginBottom: '4px' }}>{d.title}</div>
                        <div style={{ fontSize: '13px', color: '#64748B' }}>{d.sub}</div>
                        {isSelected && (
                          <div style={{ marginTop: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                            <div 
                              onClick={(e) => { e.stopPropagation(); handleCopy(d.cmd); }}
                              style={{ 
                                display: 'flex', 
                                alignItems: 'center', 
                                background: '#111827', 
                                padding: '10px 16px', 
                                borderRadius: '8px', 
                                fontFamily: 'var(--mono)', 
                                fontSize: '13px', 
                                color: 'var(--cyan)',
                                cursor: 'pointer',
                                justifyContent: 'space-between',
                                border: '1px solid #1E293B'
                              }}
                              title="Click to copy command"
                            >
                              <div style={{ display: 'flex', gap: '8px' }}>
                                <span style={{ color: '#64748B' }}>$</span>
                                <span>{d.cmd}</span>
                              </div>
                              <span style={{ fontSize: '11px', color: '#94A3B8' }}>
                                {copiedCmd === d.cmd ? 'Copied!' : 'Copy'}
                              </span>
                            </div>

                            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '4px' }}>
                              {d.feats.map((f, j) => (
                                <div key={j} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: '#475569', fontWeight: 500 }}>
                                  <div style={{ width: '5px', height: '5px', borderRadius: '50%', background: '#A855F7' }} />
                                  {f}
                                </div>
                              ))}
                            </div>
                            
                            <a 
                              href="https://github.com/TENET-DEV-AI/TENET-AI" 
                              target="_blank" 
                              rel="noreferrer" 
                              className="btn btn-outline btn-sm" 
                              style={{ width: 'fit-content', marginTop: '8px', padding: '6px 16px', fontSize: '12px' }}
                            >
                              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ marginRight: '6px' }}><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                              Download Source
                            </a>
                          </div>
                        )}
                      </div>
                      <div style={{ padding: '4px 8px', borderRadius: '4px', background: '#F3E8FF', color: '#A855F7', fontSize: '11px', fontWeight: 700, marginRight: '16px', marginTop: isSelected ? '4px' : '0' }}>
                        {d.plat}
                      </div>
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={isSelected ? '#A855F7' : '#CBD5E1'} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ marginTop: isSelected ? '4px' : '0' }}>
                        <polyline points="9 18 15 12 9 6"/>
                      </svg>
                    </div>
                  </FadeUp>
                );
              })}
            </div>
            
            <FadeUp delay={0.2}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: '#64748B', marginTop: '8px' }}>
                <div style={{ width: '18px', height: '18px', borderRadius: '50%', background: '#A855F7', color: '#FFFFFF', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '11px', fontWeight: 'bold' }}>?</div>
                Need help choosing? <a href="#" style={{ color: '#A855F7', textDecoration: 'none', fontWeight: 600 }}>View documentation →</a>
              </div>
            </FadeUp>
          </div>

          {/* RIGHT COLUMN: Code Block Window */}
          <FadeUp delay={0.1}>
            <div style={{ border: '1px solid #E2E8F0', borderRadius: '16px', background: '#FFFFFF', overflow: 'hidden', boxShadow: '0 12px 32px rgba(0,0,0,0.04)', display: 'flex', flexDirection: 'column' }}>
              
              <div style={{ padding: '24px', borderBottom: '1px solid #E2E8F0', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '15px', fontWeight: 700, color: '#0F172A' }}>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#A855F7" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
                  Integration example
                </div>
                <div style={{ padding: '4px 10px', borderRadius: '6px', background: '#F3E8FF', color: '#A855F7', fontSize: '11px', fontWeight: 700 }}>
                  {selectedInstall.plat}
                </div>
              </div>

              <div style={{ padding: '24px', background: '#FFFFFF' }}>
                <div className="code-block" style={{ margin: 0, borderRadius: '12px', background: '#111827' }}>
                  <div className="code-head" style={{ padding: '16px 20px', borderBottom: '1px solid rgba(255,255,255,0.05)', display: 'flex', alignItems: 'center' }}>
                    <div style={{ display: 'flex', gap: '8px', marginRight: '24px' }}>
                      <div className="code-dot2" style={{ background: '#EF4444' }} />
                      <div className="code-dot2" style={{ background: '#F59E0B' }} />
                      <div className="code-dot2" style={{ background: '#22C55E' }} />
                    </div>
                    <span className="code-file" style={{ color: '#94A3B8', fontSize: '13px', fontFamily: 'var(--mono)', flex: 1 }}>integration_example.{selectedInstall.plat === 'Python' ? 'py' : selectedInstall.plat === 'Node.js' ? 'ts' : 'sh'}</span>
                    <div onClick={() => handleCopy(selectedInstall.cmd)} style={{ cursor: 'pointer', color: '#94A3B8' }} title="Copy integration code">
                      {copiedCmd ? <span style={{fontSize: '11px'}}>Copied!</span> : <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>}
                    </div>
                  </div>
                  <pre className="code-body" style={{ padding: '24px', fontSize: '13px', lineHeight: 1.7, margin: 0, overflowX: 'auto', background: '#111827', color: '#F8FAFC' }}>
                    {renderCodeForPlatform(selectedInstall.plat)}
                  </pre>
                </div>
              </div>

              <div style={{ padding: '20px 24px', borderTop: '1px solid #E2E8F0', display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: '#FFFFFF' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: '#64748B' }}>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#A855F7" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                  Average overhead: <span style={{ color: '#A855F7', fontWeight: 600 }}>&lt;10ms</span> per request
                </div>
                <a href="#" style={{ color: '#A855F7', fontSize: '13px', fontWeight: 600, textDecoration: 'none' }}>Learn more →</a>
              </div>

            </div>
          </FadeUp>
          
        </div>
      </div>
    </section>
  );
}
