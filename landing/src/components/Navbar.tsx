import React, { useState, useEffect, useCallback } from 'react';
import TenetLogo from './TenetLogo';

interface NavItem {
  id: string;
  label: string;
  icon: React.ReactNode;
}

export default function Navbar() {
  const [activeSection, setActiveSection] = useState('home');
  const [stars, setStars] = useState('7');
  const [forks, setForks] = useState('10');
  const [menuOpen, setMenuOpen] = useState(false);

  // Close menu on Escape key
  const handleEscape = useCallback((e: KeyboardEvent) => {
    if (e.key === 'Escape' && menuOpen) {
      setMenuOpen(false);
    }
  }, [menuOpen]);

  useEffect(() => {
    window.addEventListener('keydown', handleEscape);
    return () => window.removeEventListener('keydown', handleEscape);
  }, [handleEscape]);

  // Lock body scroll when menu is open
  useEffect(() => {
    if (menuOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
    return () => { document.body.style.overflow = ''; };
  }, [menuOpen]);

  useEffect(() => {
    // Fetch GitHub repository statistics
    fetch('https://api.github.com/repos/TENET-DEV-AI/TENET-AI')
      .then(res => res.json())
      .then(data => {
        if (data.stargazers_count !== undefined) {
          const s = data.stargazers_count;
          setStars(s >= 1000 ? (s / 1000).toFixed(1) + 'k' : String(s));
        }
        if (data.forks_count !== undefined) {
          const f = data.forks_count;
          setForks(f >= 1000 ? (f / 1000).toFixed(1) + 'k' : String(f));
        }
      })
      .catch(() => {});

    // Active Section Tracking via IntersectionObserver
    const sections = ['home', 'pipeline', 'features', 'demo', 'compare', 'architecture', 'threats', 'download'];
    const observers = sections.map(id => {
      const el = document.getElementById(id);
      if (!el) return null;
      const obs = new IntersectionObserver(([entry]) => {
        if (entry.isIntersecting) {
          setActiveSection(id);
        }
      }, { threshold: 0.25 });
      obs.observe(el);
      return { obs, el };
    });

    return () => {
      observers.forEach(o => {
        if (o) o.obs.unobserve(o.el);
      });
    };
  }, []);

  const navItems: NavItem[] = [
    {
      id: 'home',
      label: 'Dashboard',
      icon: (
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
        </svg>
      )
    },
    {
      id: 'pipeline',
      label: 'Pipeline',
      icon: (
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <rect x="2" y="2" width="6" height="6" rx="1" />
          <rect x="16" y="2" width="6" height="6" rx="1" />
          <rect x="9" y="16" width="6" height="6" rx="1" />
          <path d="M5 8v4h14V8" />
          <path d="M12 12v4" />
        </svg>
      )
    },
    {
      id: 'features',
      label: 'Features',
      icon: (
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <rect x="3" y="3" width="7" height="7" />
          <rect x="14" y="3" width="7" height="7" />
          <rect x="14" y="14" width="7" height="7" />
          <rect x="3" y="14" width="7" height="7" />
        </svg>
      )
    },
    {
      id: 'demo',
      label: 'Sandbox',
      icon: (
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="4 17 10 11 4 5" />
          <line x1="12" y1="19" x2="20" y2="19" />
        </svg>
      )
    },
    {
      id: 'compare',
      label: 'Comparison',
      icon: (
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <line x1="18" y1="20" x2="18" y2="10" />
          <line x1="12" y1="20" x2="12" y2="4" />
          <line x1="6" y1="20" x2="6" y2="14" />
        </svg>
      )
    },
    {
      id: 'threats',
      label: 'Case Studies',
      icon: (
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
      )
    },
    {
      id: 'download',
      label: 'Install',
      icon: (
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
          <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
          <polyline points="7 10 12 15 17 10" />
          <line x1="12" y1="15" x2="12" y2="3" />
        </svg>
      )
    }
  ];

  const handleLinkClick = (e: React.MouseEvent<HTMLAnchorElement>, id: string) => {
    e.preventDefault();
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
      setActiveSection(id);
    }
    setMenuOpen(false);
  };

  return (
    <>
      <header className="topbar">
        <a href="#home" className="brand" onClick={(e) => handleLinkClick(e, 'home')}>
          <div className="brand-logo">
            <TenetLogo size={28} />
          </div>
          <span className="brand-name">TENET AI Dev</span>
          <span className="brand-badge">v0.1</span>
        </a>

        {/* Desktop Navigation */}
        <nav className="nav">
          {navItems.map(item => (
            <a
              key={item.id}
              href={`#${item.id}`}
              className={`nav-link ${activeSection === item.id ? 'active' : ''}`}
              onClick={(e) => handleLinkClick(e, item.id)}
            >
              {item.icon}
              {item.label}
            </a>
          ))}
        </nav>

        <div className="topbar-right">
          <div className="live-badge" aria-label="System status online">
            <div className="dot" />
            LIVE
          </div>

          <a
            href="https://github.com/TENET-DEV-AI/TENET-AI"
            target="_blank"
            rel="noreferrer"
            className="btn btn-ghost btn-sm github-stars-btn"
            aria-label="GitHub Stars"
          >
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ marginRight: '4px' }}>
              <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
            </svg>
            {stars}
          </a>

          <a
            href="https://github.com/TENET-DEV-AI/TENET-AI/fork"
            target="_blank"
            rel="noreferrer"
            className="btn btn-ghost btn-sm github-forks-btn"
            aria-label="GitHub Forks"
          >
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ marginRight: '4px' }}>
              <circle cx="12" cy="18" r="3" />
              <circle cx="6" cy="6" r="3" />
              <circle cx="18" cy="6" r="3" />
              <path d="M18 9v2c0 .6-.4 1-1 1H7c-.6 0-1-.4-1-1V9" />
              <path d="M12 12v3" />
            </svg>
            {forks}
          </a>

          <a href="#download" className="btn btn-primary btn-sm" onClick={(e) => handleLinkClick(e, 'download')}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
              <polyline points="7 10 12 15 17 10" />
              <line x1="12" y1="15" x2="12" y2="3" />
            </svg>
            Download
          </a>

          {/* Hamburger Button — visible only on mobile/tablet via CSS */}
          <button
            className="hamburger-btn"
            onClick={() => setMenuOpen(!menuOpen)}
            aria-expanded={menuOpen}
            aria-controls="mobile-menu"
            aria-label={menuOpen ? 'Close navigation menu' : 'Open navigation menu'}
          >
            <span className={`hamburger-icon ${menuOpen ? 'open' : ''}`}>
              <span />
              <span />
              <span />
            </span>
          </button>
        </div>
      </header>

      {/* Mobile Menu Overlay */}
      <div
        className={`mobile-overlay ${menuOpen ? 'visible' : ''}`}
        onClick={() => setMenuOpen(false)}
        aria-hidden="true"
      />
      <nav
        id="mobile-menu"
        className={`mobile-menu ${menuOpen ? 'open' : ''}`}
        aria-label="Mobile navigation"
      >
        <div className="mobile-menu-links">
          {navItems.map(item => (
            <a
              key={item.id}
              href={`#${item.id}`}
              className={`mobile-menu-link ${activeSection === item.id ? 'active' : ''}`}
              onClick={(e) => handleLinkClick(e, item.id)}
            >
              <span className="mobile-menu-icon">{item.icon}</span>
              {item.label}
            </a>
          ))}
        </div>

        <div className="mobile-menu-footer">
          <div className="mobile-menu-github">
            <a
              href="https://github.com/TENET-DEV-AI/TENET-AI"
              target="_blank"
              rel="noreferrer"
              className="btn btn-ghost btn-sm"
            >
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
              </svg>
              {stars} Stars
            </a>
            <a
              href="https://github.com/TENET-DEV-AI/TENET-AI/fork"
              target="_blank"
              rel="noreferrer"
              className="btn btn-ghost btn-sm"
            >
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="18" r="3" />
                <circle cx="6" cy="6" r="3" />
                <circle cx="18" cy="6" r="3" />
                <path d="M18 9v2c0 .6-.4 1-1 1H7c-.6 0-1-.4-1-1V9" />
                <path d="M12 12v3" />
              </svg>
              {forks} Forks
            </a>
          </div>
          <a
            href="#download"
            className="btn btn-primary btn-md mobile-menu-cta"
            onClick={(e) => handleLinkClick(e, 'download')}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
              <polyline points="7 10 12 15 17 10" />
              <line x1="12" y1="15" x2="12" y2="3" />
            </svg>
            Download TENET AI
          </a>
        </div>
      </nav>
    </>
  );
}
