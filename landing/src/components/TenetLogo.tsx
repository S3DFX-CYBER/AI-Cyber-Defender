import React from 'react';

export default function TenetLogo({ size = 32 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 80 80" fill="none">
      <defs>
        <linearGradient id="tg1" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#00e5ff" />
          <stop offset="100%" stopColor="#0099cc" />
        </linearGradient>
        <linearGradient id="tg2" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#00aadd" />
          <stop offset="100%" stopColor="#006699" />
        </linearGradient>
      </defs>
      {/* Outer cube outline */}
      <path d="M40 6 L72 22 L72 58 L40 74 L8 58 L8 22 Z" fill="none" stroke="url(#tg1)" strokeWidth="1.5" opacity="0.6" />
      {/* Top face */}
      <path d="M40 6 L72 22 L40 38 L8 22 Z" fill="rgba(0,229,255,0.12)" stroke="url(#tg1)" strokeWidth="1.5" />
      {/* Right face */}
      <path d="M72 22 L72 58 L40 74 L40 38 Z" fill="rgba(0,153,204,0.08)" stroke="url(#tg2)" strokeWidth="1.5" />
      {/* Left face */}
      <path d="M8 22 L40 38 L40 74 L8 58 Z" fill="rgba(0,100,150,0.06)" stroke="url(#tg2)" strokeWidth="1.2" />
      {/* Inner geometric pattern - top */}
      <path d="M40 14 L64 26 L40 38 L16 26 Z" fill="none" stroke="rgba(0,229,255,0.35)" strokeWidth="1" />
      {/* Inner lines */}
      <line x1="40" y1="6" x2="40" y2="74" stroke="url(#tg1)" strokeWidth="0.8" opacity="0.4" />
      <line x1="8" y1="22" x2="72" y2="58" stroke="url(#tg1)" strokeWidth="0.8" opacity="0.3" />
      <line x1="72" y1="22" x2="8" y2="58" stroke="url(#tg1)" strokeWidth="0.8" opacity="0.3" />
      {/* Inner cube detail */}
      <path d="M40 22 L56 30 L56 46 L40 54 L24 46 L24 30 Z" fill="none" stroke="rgba(0,229,255,0.5)" strokeWidth="1.2" />
      <path d="M40 22 L56 30 L40 38 L24 30 Z" fill="rgba(0,229,255,0.1)" stroke="rgba(0,229,255,0.5)" strokeWidth="1" />
      {/* Center dot */}
      <circle cx="40" cy="38" r="3.5" fill="#00e5ff" opacity="0.9" />
      {/* Corner dots */}
      {[[40,6],[72,22],[72,58],[40,74],[8,58],[8,22]].map(([cx,cy],i)=>(
        <circle key={i} cx={cx} cy={cy} r="2.5" fill="#00e5ff" opacity="0.65" />
      ))}
      {/* Mid dots */}
      {[[56,30],[56,46],[40,54],[24,46],[24,30],[40,22]].map(([cx,cy],i)=>(
        <circle key={i} cx={cx} cy={cy} r="1.5" fill="#00e5ff" opacity="0.4" />
      ))}
    </svg>
  );
}
