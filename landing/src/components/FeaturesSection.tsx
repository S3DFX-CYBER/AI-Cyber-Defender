import React, { useState, useEffect, useRef } from 'react';

interface FeatureItem {
  icon: React.ReactNode;
  bg: string;
  title: string;
  desc: string;
  tags: { l: string; c: string }[];
}

const FEATURES: FeatureItem[] = [
  {
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="11" cy="11" r="8" />
        <line x1="21" y1="21" x2="16.65" y2="16.65" />
        <line x1="8" y1="11" x2="14" y2="11" />
      </svg>
    ),
    bg: 'var(--cyan-dim)',
    title: 'Heuristic Detection',
    desc: 'Zero-config pattern matching for known attack signatures — prompt injection, jailbreaks, role manipulation out of the box.',
    tags: [{ l: '<5ms', c: 'cyan' }, { l: 'zero-config', c: 'dim' }]
  },
  {
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z" />
        <path d="M12 6v12" />
        <path d="M8 10h8" />
        <circle cx="12" cy="6" r="1" fill="currentColor" />
        <circle cx="12" cy="18" r="1" fill="currentColor" />
        <circle cx="8" cy="10" r="1" fill="currentColor" />
        <circle cx="16" cy="10" r="1" fill="currentColor" />
      </svg>
    ),
    bg: 'var(--purple-dim)',
    title: 'ML-Based Analysis',
    desc: 'Trained classifier achieving >90% accuracy on adversarial datasets. Continuously improves from analyst feedback.',
    tags: [{ l: '>90% accuracy', c: 'purple' }, { l: 'adaptive', c: 'dim' }]
  },
  {
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7z" />
        <circle cx="12" cy="12" r="3" />
        <path d="M12 5V3" />
        <path d="M12 21v-2" />
        <path d="M19 12h2" />
        <path d="M3 12h2" />
      </svg>
    ),
    bg: 'var(--amber-dim)',
    title: 'Behavioral Analysis',
    desc: 'Cross-session pattern tracking detects coordinated attacks and multi-turn manipulation chains that single-shot models miss.',
    tags: [{ l: 'cross-session', c: 'amber' }, { l: 'anomaly detection', c: 'dim' }]
  },
  {
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <path d="m13 10-3 3h2v3l3-3h-2z" fill="currentColor" />
      </svg>
    ),
    bg: 'var(--green-dim)',
    title: 'Real-Time Policy Engine',
    desc: 'Block, sanitize, flag, or allow — configurable rules execute in under 10ms total overhead with zero LLM integration changes.',
    tags: [{ l: '<10ms', c: 'green' }, { l: 'configurable', c: 'dim' }]
  },
  {
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="3" width="18" height="18" rx="2" />
        <path d="M21 12H3" />
        <path d="M12 3v18" />
        <circle cx="7.5" cy="7.5" r="1.5" fill="currentColor" />
        <circle cx="16.5" cy="16.5" r="1.5" fill="currentColor" />
      </svg>
    ),
    bg: 'var(--cyan-dim)',
    title: 'SOC Dashboard',
    desc: 'Live threat feeds, attack timelines, risk score trends, and analyst workflows. Audit-ready for compliance teams.',
    tags: [{ l: 'real-time', c: 'cyan' }, { l: 'SOC-ready', c: 'dim' }]
  },
  {
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="2" y="8" width="16" height="8" rx="2" />
        <path d="M6 12h4" />
        <path d="M18 10h2a2 2 0 0 1 2 2v0a2 2 0 0 1-2 2h-2" />
        <line x1="2" y1="10" x2="2" y2="14" />
      </svg>
    ),
    bg: 'var(--purple-dim)',
    title: 'Universal Integration',
    desc: 'LLM-agnostic middleware for OpenAI, Anthropic, Cohere, Ollama, and any local model. One API call in your existing stack.',
    tags: [{ l: 'any LLM', c: 'purple' }, { l: 'one API call', c: 'dim' }]
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

export default function FeaturesSection() {
  const tagCss = (c: string) => {
    switch (c) {
      case 'cyan':
        return {
          color: 'var(--cyan)',
          background: 'var(--cyan-dim)',
          borderColor: 'rgba(0, 229, 255, 0.2)'
        };
      case 'purple':
        return {
          color: 'var(--purple)',
          background: 'var(--purple-dim)',
          borderColor: 'rgba(180, 127, 255, 0.2)'
        };
      case 'amber':
        return {
          color: 'var(--amber)',
          background: 'var(--amber-dim)',
          borderColor: 'rgba(255, 184, 0, 0.2)'
        };
      case 'green':
        return {
          color: 'var(--green)',
          background: 'var(--green-dim)',
          borderColor: 'rgba(0, 255, 136, 0.2)'
        };
      default:
        return {
          color: 'var(--text3)',
          background: 'var(--surface3)',
          borderColor: 'var(--border)'
        };
    }
  };

  return (
    <section className="section section-alt" id="features" aria-label="Product Capabilities">
      <div className="container">
        <FadeUp>
          <div style={{ marginBottom: 40 }}>
            <div className="eyebrow">Capabilities</div>
            <h2 className="section-title">Everything to <span className="grad">secure your AI</span></h2>
          </div>
        </FadeUp>

        <div className="feat-grid">
          {FEATURES.map((f, i) => (
            <FadeUp key={i} delay={i * 0.07}>
              <div className="feat-card">
                <div className="feat-icon" style={{ background: f.bg, color: 'var(--cyan)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  {f.icon}
                </div>
                <div className="feat-title">{f.title}</div>
                <div className="feat-desc">{f.desc}</div>
                <div className="feat-tags">
                  {f.tags.map((t, j) => (
                    <span key={j} className="tag" style={tagCss(t.c)}>
                      {t.l}
                    </span>
                  ))}
                </div>
              </div>
            </FadeUp>
          ))}
        </div>
      </div>
    </section>
  );
}
