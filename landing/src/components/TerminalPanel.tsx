import React, { useState, useEffect } from 'react';

interface LogEntry {
  id?: string;
  tag: string;
  tc: string; // text color
  tb: string; // background color
  msg: string;
  src: string;
}

const LOGS: LogEntry[] = [
  { tag: 'BLOCKED', tc: 'var(--red)', tb: 'var(--red-dim)', msg: 'prompt_injection · ignore_instructions', src: 'api.prod' },
  { tag: 'ALLOWED', tc: 'var(--green)', tb: 'var(--green-dim)', msg: 'normal_query · risk_score:0.02', src: 'chat.app' },
  { tag: 'LEARNING', tc: 'var(--text2)', tb: 'var(--surface3)', msg: 'threat database synchronized · version:2.4.1', src: 'daemon.sys' },
  { tag: 'BLOCKED', tc: 'var(--red)', tb: 'var(--red-dim)', msg: 'jailbreak · DAN_mode variant', src: 'agt.01' },
  { tag: 'FLAGGED', tc: 'var(--amber)', tb: 'var(--amber-dim)', msg: 'data_extraction · system_prompt probe', src: 'api.dev' },
  { tag: 'LEARNING', tc: 'var(--text2)', tb: 'var(--surface3)', msg: 'ML model updated · anomaly vectors weights computed', src: 'model.sys' },
  { tag: 'BLOCKED', tc: 'var(--red)', tb: 'var(--red-dim)', msg: 'role_manipulation · persona_override', src: 'embed.01' },
  { tag: 'ALLOWED', tc: 'var(--green)', tb: 'var(--green-dim)', msg: 'normal_query · risk_score:0.01', src: 'chat.app' }
];

export default function TerminalPanel() {
  const [lines, setLines] = useState<LogEntry[]>(() =>
    LOGS.slice(0, 4).map((log, i) => ({ ...log, id: `log-init-${i}` }))
  );
  const [idx, setIdx] = useState(4);
  const [flashRed, setFlashRed] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [bars, setBars] = useState([78, 14, 6, 2]); // distribution percentages
  const [stats, setStats] = useState({ blocked: 2847, flagged: 341, allowed: 98700 });
  const [mounted, setMounted] = useState(false);

  // Trigger bar width animations on mount
  useEffect(() => {
    const t = setTimeout(() => {
      setMounted(true);
    }, 100);
    return () => clearTimeout(t);
  }, []);

  useEffect(() => {
    const interval = setInterval(() => {
      if (document.hidden) return; // Prevent background tab issues
      
      // 1. Start processing animation for 300ms
      setIsProcessing(true);
      
      setTimeout(() => {
        setIsProcessing(false);
        const nextLog: LogEntry = {
          ...LOGS[idx % LOGS.length],
          id: `log-append-${idx}`
        };
        
        // 2. Add next log line (newest at top)
        setLines(prev => [nextLog, ...prev].slice(0, 4));
        setIdx(i => i + 1);

        // 3. Flash border if blocked and update stats
        if (nextLog.tag === 'BLOCKED') {
          setFlashRed(true);
          setStats(s => ({ ...s, blocked: s.blocked + 1 }));
          setTimeout(() => setFlashRed(false), 600);
        } else if (nextLog.tag === 'FLAGGED') {
          setStats(s => ({ ...s, flagged: s.flagged + 1 }));
        } else if (nextLog.tag === 'ALLOWED') {
          setStats(s => ({ ...s, allowed: s.allowed + 1 }));
        }

        // 4. Slightly randomize threat distribution bars on new entries to simulate activity
        setBars(prev => {
          const shift = Math.floor(Math.random() * 3) - 1; // -1, 0, 1
          const newPrompt = Math.max(70, Math.min(90, prev[0] + shift));
          const newJailbreak = Math.max(5, Math.min(20, prev[1] - shift));
          return [newPrompt, newJailbreak, prev[2], prev[3]];
        });

      }, 300);

    }, 1400); // 1.4s feed interval

    return () => clearInterval(interval);
  }, [idx]);

  const now = new Date();
  const formatTime = (offsetSeconds: number) => {
    const d = new Date(now.getTime() - offsetSeconds * 1000);
    return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`;
  };

  return (
    <div className="hero-enter-terminal" style={{ minWidth: 0, display: 'flex', flexDirection: 'column', gap: '16px' }}>      {/* Dashboard Summary stats */}
      <div className="p-stats" style={{ gap: '16px' }}>
        
        {/* Blocked */}
        <div className="p-stat" style={{ background: '#FFFFFF', border: '1px solid #F0EBFE', borderRadius: '16px', padding: '20px 16px', display: 'flex', alignItems: 'center', gap: '14px', boxShadow: '0 4px 14px rgba(0,0,0,0.03)' }}>
          <div style={{ width: '52px', height: '52px', borderRadius: '12px', background: '#FCE7F3', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="var(--red)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <path d="M12 8v4"/><path d="M12 16h.01"/>
            </svg>
          </div>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: '28px', fontWeight: 700, color: 'var(--red)', lineHeight: 1 }}>{stats.blocked.toLocaleString()}</div>
            <div style={{ fontSize: '11.5px', color: '#64748B', fontWeight: 600, marginTop: '5px', textTransform: 'uppercase', letterSpacing: '0.05em', whiteSpace: 'nowrap' }}>Blocked</div>
            <div style={{ fontSize: '10px', color: 'var(--red)', marginTop: '5px', fontWeight: 500, whiteSpace: 'nowrap' }}>+12% vs last 24h</div>
          </div>
        </div>

        {/* Flagged */}
        <div className="p-stat" style={{ background: '#FFFFFF', border: '1px solid #F0EBFE', borderRadius: '16px', padding: '20px 16px', display: 'flex', alignItems: 'center', gap: '14px', boxShadow: '0 4px 14px rgba(0,0,0,0.03)' }}>
          <div style={{ width: '52px', height: '52px', borderRadius: '12px', background: '#FFF7ED', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="var(--amber)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/>
            </svg>
          </div>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: '28px', fontWeight: 700, color: 'var(--amber)', lineHeight: 1 }}>{stats.flagged.toLocaleString()}</div>
            <div style={{ fontSize: '11.5px', color: '#64748B', fontWeight: 600, marginTop: '5px', textTransform: 'uppercase', letterSpacing: '0.05em', whiteSpace: 'nowrap' }}>Flagged</div>
            <div style={{ fontSize: '10px', color: 'var(--amber)', marginTop: '5px', fontWeight: 500, whiteSpace: 'nowrap' }}>-5% vs last 24h</div>
          </div>
        </div>

        {/* Allowed */}
        <div className="p-stat" style={{ background: '#FFFFFF', border: '1px solid #F0EBFE', borderRadius: '16px', padding: '20px 16px', display: 'flex', alignItems: 'center', gap: '14px', boxShadow: '0 4px 14px rgba(0,0,0,0.03)' }}>
          <div style={{ width: '52px', height: '52px', borderRadius: '12px', background: '#F3E8FF', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="var(--purple)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
            </svg>
          </div>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: '28px', fontWeight: 700, color: 'var(--purple)', lineHeight: 1 }}>{(stats.allowed / 1000).toFixed(1)}k</div>
            <div style={{ fontSize: '11.5px', color: '#64748B', fontWeight: 600, marginTop: '5px', textTransform: 'uppercase', letterSpacing: '0.05em', whiteSpace: 'nowrap' }}>Allowed</div>
            <div style={{ fontSize: '10px', color: 'var(--purple)', marginTop: '5px', fontWeight: 500, whiteSpace: 'nowrap' }}>+8% vs last 24h</div>
          </div>
        </div>

      </div>

      <div className={`preview ${flashRed ? 'flash-red' : ''}`} style={{ width: '100%', minWidth: 0, overflow: 'hidden' }}>
        <div className="preview-bar">
          <div className="preview-dot" style={{ background: '#FF5F56' }} />
          <div className="preview-dot" style={{ background: '#FFBD2E' }} />
          <div className="preview-dot" style={{ background: '#27C93F' }} />
          <span className="preview-title">tenet‑ai — live‑security‑log</span>
          
          {isProcessing && (
            <span className="preview-processing">
              ANALYZING
            </span>
          )}

          <div className="preview-live">
            <div className="dot" style={{ background: 'var(--green)' }} />
            LIVE
          </div>
        </div>

        <div className="preview-body" style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }}>
          {/* Terminal log window */}
          <div className="p-log" aria-live="polite" style={{ minWidth: 0, overflow: 'hidden' }}>
            {lines.map((line, i) => (
              <div 
                key={line.id || i} 
                className="p-log-row" 
                style={{ opacity: 1 - i * 0.2 }}
              >
                <span className="p-log-time">{formatTime(i * 2)}</span>
                <span 
                  className="p-log-tag" 
                  style={{ 
                    color: line.tc, 
                    background: line.tb,
border: `1px solid color-mix(in srgb, ${line.tc} 12%, transparent)`,
                  }}
                >
                  {line.tag}
                </span>
                <span className="p-log-msg" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{line.msg}</span>
                <span style={{ color: 'var(--text3)', fontSize: '9.5px', fontFamily: 'var(--mono)' }}>
                  {line.src}
                </span>
              </div>
            ))}
          </div>

          {/* Attack Type Distribution bars */}
          <div className="p-bars">
            <div className="p-bar-head">Attack Type Distribution</div>
            {[
              { label: 'Prompt Injection', val: bars[0], color: 'var(--red)' },
              { label: 'Jailbreak', val: bars[1], color: 'var(--amber)' },
              { label: 'Data Extraction', val: bars[2], color: 'var(--purple)' },
              { label: 'Role Manip.', val: bars[3], color: 'var(--cyan)' }
            ].map((bar, i) => (
              <div key={i} className="p-bar-row">
                <span className="p-bar-lbl">{bar.label}</span>
                <div className="p-bar-track">
                  <div 
                    className="p-bar-fill" 
                    style={{ width: mounted ? `${bar.val}%` : '0%', background: bar.color }} 
                  />
                </div>
                <span className="p-bar-val">{bar.val}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
