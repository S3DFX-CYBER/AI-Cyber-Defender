import React, { useState, useEffect } from 'react';
import TenetLogo from './TenetLogo';

export default function Footer() {
  const [showBackToTop, setShowBackToTop] = useState(false);
  const [announcement, setAnnouncement] = useState('');

  useEffect(() => {
    const handleScroll = () => {
      if (window.scrollY > 500) {
        setShowBackToTop(true);
      } else {
        setShowBackToTop(false);
      }
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
    setAnnouncement('Scrolled back to top of the page.');
    setTimeout(() => setAnnouncement(''), 1000);
  };

  const handleLinkClick = (e: React.MouseEvent<HTMLAnchorElement>, id: string) => {
    e.preventDefault();
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <footer className="footer" aria-label="Page Footer">
      <div className="container">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '20px' }}>
          <div className="footer-brand">
            <TenetLogo size={24} />
            <span className="footer-name">TENET AI Dev</span>
          </div>

          <div style={{ display: 'flex', gap: '24px', flexWrap: 'wrap' }}>
            <a href="https://github.com/TENET-DEV-AI/TENET-AI" target="_blank" rel="noreferrer" className="footer-link" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" />
              </svg>
              GitHub
            </a>
            <a href="#download" className="footer-link" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }} onClick={(e) => {
              e.preventDefault();
              document.getElementById('download')?.scrollIntoView({ behavior: 'smooth' });
            }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
                <polyline points="7 10 12 15 17 10" />
                <line x1="12" y1="15" x2="12" y2="3" />
              </svg>
              Download
            </a>
            <a href="https://github.com/TENET-DEV-AI/TENET-AI/blob/main/CONTRIBUTING.md" target="_blank" rel="noreferrer" className="footer-link">Contributing</a>
            <a href="https://github.com/TENET-DEV-AI/TENET-AI/blob/main/SECURITY.md" target="_blank" rel="noreferrer" className="footer-link">Security</a>
            <a href="#" className="footer-link" onClick={(e) => e.preventDefault()}>Privacy Policy</a>
            <a href="mailto:saviodsouza8a@gmail.com" className="footer-link">Contact</a>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '20px', flexWrap: 'wrap' }}>
            <a href="#home" className="footer-secured" onClick={(e) => handleLinkClick(e, 'home')} style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ color: 'var(--cyan)' }}>
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              Protected by TENET AI
            </a>
            <span className="footer-copy">Built by Savio D'souza · &copy; 2026 MIT</span>
          </div>
        </div>
      </div>

      {/* Back to top button with screen-reader announcement */}
      <button
        className={`back-to-top ${showBackToTop ? 'visible' : ''}`}
        onClick={scrollToTop}
        aria-label="Back to top of the page"
        title="Scroll to top"
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="18 15 12 9 6 15" />
        </svg>
      </button>

      {/* SR announcement for accessibility */}
      <div className="sr-only" aria-live="polite" style={{ position: 'absolute', width: '1px', height: '1px', padding: 0, margin: '-1px', overflow: 'hidden', clip: 'rect(0, 0, 0, 0)', border: 0 }}>
        {announcement}
      </div>
    </footer>
  );
}
