import React from 'react';
import TenetLogo from './TenetLogo';
import TerminalPanel from './TerminalPanel';

export default function Hero() {
  const handleScrollToDownload = (e: React.MouseEvent<HTMLAnchorElement>) => {
    e.preventDefault();
    const el = document.getElementById('download');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <section className="hero" id="home">
      {/* 3-layer background system */}
      <div className="hero-dots hero-enter-bg" />
      <div className="hero-scanlines hero-enter-bg" />
      <div className="hero-glow1 hero-enter-bg" />
      
      <div className="container">
        <div className="hero-inner">
          {/* Left Column */}
          <div className="hero-content">
            {/* Announcement badge above headline */}
            <div className="hero-announcement hero-enter-logo" style={{ 
              display: 'inline-flex', 
              alignItems: 'center', 
              gap: '10px', 
              padding: '4px 14px 4px 4px', 
              borderRadius: '999px', 
              border: '1px solid #F0EBFE', 
              background: '#FFFFFF',
              marginBottom: '24px',
              fontSize: '12.5px',
              color: '#475569',
              fontWeight: 500,
              boxShadow: '0 2px 10px rgba(0,0,0,0.02)'
            }}>
              <span style={{
                background: 'var(--purple)',
                color: '#FFFFFF',
                padding: '4px 10px',
                borderRadius: '999px',
                fontWeight: 700,
                fontSize: '10.5px',
                letterSpacing: '0.02em'
              }}>
                NEW
              </span>
              <span>LLM Security Middleware · Open Source</span>
            </div>

            {/* Headline with firewall bottom border and cursor */}
            <h1 className="hero-title hero-enter-headline">
              The <span className="grad fw-firewall">Firewall</span> for your AI
              <span className="hero-cursor">|</span>
            </h1>

            <p className="hero-desc hero-enter-sub">
              TENET AI sits between your application and any LLM — detecting prompt injection, jailbreaks, and data extraction in real-time with under 10ms overhead.
            </p>

            <div className="hero-actions hero-enter-cta1">
              <a href="#download" className="btn btn-primary btn-xl" onClick={handleScrollToDownload}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
                  <polyline points="7 10 12 15 17 10" />
                  <line x1="12" y1="15" x2="12" y2="3" />
                </svg>
                Get Started Free
              </a>
              <a 
                href="https://github.com/TENET-DEV-AI/TENET-AI" 
                target="_blank" 
                rel="noreferrer" 
                className="btn btn-outline btn-xl hero-enter-cta2"
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" />
                </svg>
                View on GitHub
              </a>
            </div>

            {/* Trust pills with check SVG icons */}
            <div className="hero-pills hero-enter-pills">
              {[
                'MIT Licensed',
                'Self-hosted',
                '<10ms overhead',
                'OWASP LLM Top 10'
              ].map((p, i) => (
                <span key={i} className="hero-pill">
                  <svg 
                    className="hero-pill-check" 
                    width="12" 
                    height="12" 
                    viewBox="0 0 12 12" 
                    fill="none" 
                    stroke="var(--cyan)" 
                    strokeWidth="2.5" 
                    strokeLinecap="round" 
                    strokeLinejoin="round"
                    style={{ marginRight: '6px' }}
                  >
                    <polyline points="10 3 4.5 8.5 2 6" />
                  </svg>
                  {p}
                </span>
              ))}
            </div>
          </div>

          {/* Right Column: Live Terminal Visualizer */}
          <TerminalPanel />
        </div>
      </div>
    </section>
  );
}
