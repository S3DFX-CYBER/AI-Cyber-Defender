import React, { useState, useEffect, useRef } from 'react';

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

export default function CtaSection() {
  const handleScrollToDownload = (e: React.MouseEvent<HTMLAnchorElement>) => {
    e.preventDefault();
    const el = document.getElementById('download');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <section className="cta" aria-label="Call to Action">
      <div className="cta-glow" />
      <div className="container">
        <FadeUp>
          <h2 className="cta-title">
            Start protecting your<br /><span className="grad">AI applications today</span>
          </h2>
          <p className="cta-sub">Self-hosted. Open source. Zero vendor lock-in.</p>
          
          <div className="cta-btns">
            <a href="#download" className="btn btn-primary btn-xl" onClick={handleScrollToDownload} style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
                <polyline points="7 10 12 15 17 10" />
                <line x1="12" y1="15" x2="12" y2="3" />
              </svg>
              Download SDK
            </a>
            <a 
              href="https://github.com/TENET-DEV-AI/TENET-AI" 
              target="_blank" 
              rel="noreferrer" 
              className="btn btn-outline btn-xl"
              style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}
            >
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" />
              </svg>
              View on GitHub
            </a>
          </div>

          <div className="cta-chips">
            {["MIT Licensed", "Self-hosted option", "Any LLM provider", "No usage telemetry"].map((chip, i) => (
              <span key={i} className="cta-chip">
                {chip}
              </span>
            ))}
          </div>
        </FadeUp>
      </div>
    </section>
  );
}
