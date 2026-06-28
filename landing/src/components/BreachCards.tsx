import React, { useState, useEffect, useRef } from 'react';

interface ThreatItem {
  id: number;
  date: string;
  type: string;
  title: string;
  sev: string;
  sc: string; // severity text color
  sb: string; // severity bg color
  stat: string;
  sl: string;
  desc: string;
  resp: string;
  lc: string; // left border color
}

const THREATS: ThreatItem[] = [
  {
    id: 1,
    date: 'FEB 2026',
    type: 'JAILBREAK',
    title: 'Mexican Government AI Breach',
    sev: 'CRITICAL',
    sc: 'var(--red)',
    sb: 'var(--red-dim)',
    stat: '195M',
    sl: 'Records',
    desc: 'Attacker chained jailbreak prompts through Claude to exfiltrate government records across 47 federal agencies. Role-play injection bypassed standard content filters over multiple sessions.',
    resp: "Detected 'act as elite hacker' + role-play chain. Blocked at 4ms. Session fingerprinted and terminated.",
    lc: 'var(--red)'
  },
  {
    id: 2,
    date: 'JAN 2026',
    type: 'PROMPT INJECTION',
    title: 'Fortune 500 Chatbot Compromise',
    sev: 'HIGH',
    sc: 'var(--amber)',
    sb: 'var(--amber-dim)',
    stat: '$4.2M',
    sl: 'Loss',
    desc: 'Customer chatbot exploited via iterative prompt injection exposing internal pricing models and PII across 47 payload variations.',
    resp: 'Detected structural similarity across 47 attempts. Auto-blocked after threshold. Risk score elevated progressively.',
    lc: 'var(--amber)'
  },
  {
    id: 3,
    date: 'DEC 2025',
    type: 'JAILBREAK',
    title: 'Healthcare Enterprise Breach',
    sev: 'HIGH',
    sc: 'var(--amber)',
    sb: 'var(--amber-dim)',
    stat: 'HIPAA',
    sl: 'Violation',
    desc: 'Internal clinical AI jailbroken via DAN mode granting unrestricted access to patient record queries across a hospital network.',
    resp: 'Blocked jailbreak on attempt #1. Behavioral fingerprint added to shared threat feed in real-time.',
    lc: 'var(--amber)'
  },
  {
    id: 4,
    date: 'NOV 2025',
    type: 'IP EXTRACTION',
    title: 'Corporate Algorithm Exfiltration',
    sev: 'MEDIUM',
    sc: 'var(--purple)',
    sb: 'var(--purple-dim)',
    stat: '12',
    sl: 'Sessions',
    desc: 'Nation-state actor used 12 sessions of multi-turn context manipulation to gradually extract proprietary encryption algorithms from a coding assistant.',
    resp: 'ML model detected anomaly at session 4. Full 12-session attack chain reconstructed for forensics.',
    lc: 'var(--purple)'
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

const getThreatIcon = (id: number) => {
  switch(id) {
    case 1: return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="3" y1="22" x2="21" y2="22"/><line x1="6" y1="18" x2="6" y2="11"/><line x1="10" y1="18" x2="10" y2="11"/><line x1="14" y1="18" x2="14" y2="11"/><line x1="18" y1="18" x2="18" y2="11"/><polygon points="12 2 20 7 4 7"/></svg>;
    case 2: return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="10" rx="2"/><circle cx="12" cy="5" r="2"/><path d="M12 7v4"/><line x1="8" y1="16" x2="8.01" y2="16"/><line x1="16" y1="16" x2="16.01" y2="16"/></svg>;
    case 3: return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>;
    case 4: return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>;
    default: return null;
  }
};

export default function BreachCards() {
  const [expandedIds, setExpandedIds] = useState<number[]>([1]); // First card expanded by default
  const spineRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting && spineRef.current) {
        spineRef.current.style.height = '100%';
        observer.disconnect();
      }
    }, { threshold: 0.05 });

    if (containerRef.current) {
      observer.observe(containerRef.current);
    }

    return () => observer.disconnect();
  }, []);

  const toggleExpand = (id: number) => {
    setExpandedIds(prev =>
      prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
    );
  };

  return (
    <section className="section" id="threats" aria-label="Threat Intel Case Studies">
      <div className="container" ref={containerRef}>
        <FadeUp>
          <div style={{ marginBottom: 40 }}>
            <div className="eyebrow">Threat Intelligence</div>
            <h2 className="section-title">Real breaches. <span className="grad">Real prevention.</span></h2>
            <p className="section-sub">These incidents happened. The attack vectors are documented. TENET AI's pipeline would have blocked each one.</p>
          </div>
        </FadeUp>

        <div className="threat-list-wrap">
          {/* Vertical timeline spine */}
          <div 
            className="timeline-spine" 
            ref={spineRef} 
            style={{ 
              transition: 'height 1.2s cubic-bezier(0.4, 0, 0.2, 1)', 
              height: '0%' 
            }} 
          />

          <div className="threat-list">
            {THREATS.map((t, i) => {
              const isExpanded = expandedIds.includes(t.id);
              return (
                <FadeUp key={t.id} delay={i * 0.07}>
                  <div style={{ position: 'relative' }}>
                    {/* Timeline node dot */}
                    <div 
                      className="timeline-node" 
                      style={{ 
                        borderColor: t.lc, 
                        boxShadow: `0 0 8px ${t.lc}` 
                      }} 
                    />

                    <div className="threat" style={{ borderLeftColor: t.lc }}>
                      <div className="threat-meta">
                        <span className="threat-date">{t.date}</span>
                        <span className="threat-sev" style={{ color: t.sc, background: t.sb }}>
                          • {t.sev}
                        </span>
                        <span className="threat-type">{t.type}</span>
                      </div>

                      <div>
                        <div className="threat-title" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <span style={{ color: t.sc, display: 'flex', alignItems: 'center' }}>
                            {getThreatIcon(t.id)}
                          </span>
                          {t.title}
                        </div>
                        <div className="threat-desc">{t.desc}</div>
                        
                        {/* Interactive toggle header */}
                        <button
                          className="threat-resp-toggle"
                          onClick={() => toggleExpand(t.id)}
                          aria-expanded={isExpanded}
                          aria-controls={`threat-resp-${t.id}`}
                        >
                          <svg className={`threat-resp-arrow ${isExpanded ? 'expanded' : ''}`} width="8" height="8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round" style={{ marginRight: '6px' }}>
                            <polyline points="9 18 15 12 9 6" />
                          </svg>
                          <span className="threat-resp-lbl" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ verticalAlign: 'middle' }}>
                              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                            </svg>
                            TENET AI RESPONSE
                          </span>
                        </button>

                        {/* Expandable content panel */}
                        <div 
                          id={`threat-resp-${t.id}`} 
                          className={`threat-resp-content ${isExpanded ? 'expanded' : ''}`}
                        >
                          <div className="threat-resp-text">
                            {t.resp}
                          </div>
                        </div>
                      </div>

                      <div className="threat-num">
                        <div className="threat-num-val" style={{ color: t.sc }}>{t.stat}</div>
                        <div className="threat-num-lbl">{t.sl}</div>
                      </div>
                    </div>
                  </div>
                </FadeUp>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
}
