import React, { useState, useEffect, useRef } from 'react';

interface StatItemProps {
  target: number;
  label: string;
  sub: string;
  color: string;
  suffix?: string;
  prefix?: string;
  decimals?: number;
  trend: string; // SVG path data for sparkline
}

function AnimNum({ target, duration = 1500, decimals = 0 }: { target: number; duration?: number; decimals?: number }) {
  const [val, setVal] = useState(0);
  const ref = useRef<HTMLDivElement>(null);
  const started = useRef(false);

  useEffect(() => {
    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting && !started.current) {
        started.current = true;
        let startTimestamp: number | null = null;
        const step = (timestamp: number) => {
          if (!startTimestamp) startTimestamp = timestamp;
          const progress = Math.min((timestamp - startTimestamp) / duration, 1);
          // Cubic ease-out
          const easeProgress = 1 - Math.pow(1 - progress, 3);
          setVal(easeProgress * target);
          if (progress < 1) {
            window.requestAnimationFrame(step);
          }
        };
        window.requestAnimationFrame(step);
      }
    }, { threshold: 0.1 });

    if (ref.current) {
      observer.observe(ref.current);
    }
    return () => observer.disconnect();
  }, [target, duration]);

  return <span ref={ref}>{val.toFixed(decimals)}</span>;
}

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

export default function StatsSection() {
  const stats: StatItemProps[] = [
    {
      target: 99.1,
      decimals: 1,
      suffix: '%',
      label: 'Accuracy Rate',
      sub: 'adversarial test set',
      color: 'var(--green)',
      trend: 'M0 15 Q 15 5, 30 12 T 60 2'
    },
    {
      target: 10,
      prefix: '<',
      suffix: 'ms',
      label: 'Latency overhead',
      sub: 'heuristic engine',
      color: 'var(--cyan)',
      trend: 'M0 2 Q 15 18, 30 10 T 60 18'
    },
    {
      target: 2.8,
      decimals: 1,
      suffix: 'M+',
      label: 'Prompts scanned',
      sub: 'across connected nodes',
      color: 'var(--purple)',
      trend: 'M0 18 L 15 12 L 30 5 L 45 2 L 60 0'
    },
    {
      target: 4,
      label: 'Attack classes',
      sub: 'blocked out-of-box',
      color: 'var(--amber)',
      trend: 'M0 10 H 15 V 5 H 30 V 2 H 45 H 60'
    },
    {
      target: 12,
      suffix: '+',
      label: 'LLM providers',
      sub: 'native integrations',
      color: 'var(--amber)',
      trend: 'M0 15 C 10 5, 20 5, 30 10 C 40 15, 50 15, 60 5'
    }
  ];

  return (
    <section className="stats-strip" aria-label="Key Performance Indicators">
      <div className="container">
        <div className="stats-grid">
          {stats.map((stat, i) => (
            <FadeUp key={i} delay={i * 0.07}>
              <div className="stat-block">
                <div className="stat-val" style={{ color: stat.color }}>
                  {stat.prefix}
                  <AnimNum target={stat.target} decimals={stat.decimals} />
                  {stat.suffix}
                </div>
                <div className="stat-lbl">{stat.label}</div>
                <div className="stat-sub">{stat.sub}</div>
                <svg className="stat-sparkline" width="60" height="20" viewBox="0 0 60 20" fill="none">
                  <path
                    d={stat.trend}
                    stroke={stat.color}
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </div>
            </FadeUp>
          ))}
        </div>
      </div>
    </section>
  );
}
