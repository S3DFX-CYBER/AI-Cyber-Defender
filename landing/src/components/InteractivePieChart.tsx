import React from 'react';

interface InteractivePieChartProps {
  activeId: string;
  onHover: (id: string | null) => void;
  onClick: (id: string) => void;
}

const SLICES = [
  { id: 'injection', color: '#A855F7', colorDark: '#7E22CE', percent: 92, visualPercent: 65 },
  { id: 'jailbreak', color: '#EC4899', colorDark: '#BE185D', percent: 7, visualPercent: 20 },
  { id: 'extraction', color: '#3B82F6', colorDark: '#1D4ED8', percent: 1, visualPercent: 10 },
  { id: 'role_manip', color: '#F59E0B', colorDark: '#B45309', percent: 0.4, visualPercent: 5 }
];

export default function InteractivePieChart({ activeId, onHover, onClick }: InteractivePieChartProps) {
  const LAYERS = 60;
  const R = 60;
  const C = 2 * Math.PI * R;

  let currentAngle = 180;

  const slicesWithAngles = SLICES.map(slice => {
    const strokeLen = Math.max(0, (slice.visualPercent / 100) * C - 3.5);
    const angle = currentAngle;
    currentAngle += (slice.visualPercent / 100) * 360;
    return { ...slice, strokeLen, angle };
  });

  return (
    <div style={{
      width: '320px',
      height: '320px',
      perspective: '1200px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      pointerEvents: 'none'
    }}>
      <div style={{
        position: 'relative',
        width: '260px',
        height: '260px',
        transformStyle: 'preserve-3d',
        transform: 'rotateX(55deg) rotateZ(-40deg)'
      }}>
        {slicesWithAngles.map((slice) => {
          const isActive = activeId === slice.id;
          return (
            <div
              key={slice.id}
              style={{
                position: 'absolute',
                inset: 0,
                transformStyle: 'preserve-3d',
                transition: 'transform 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275)',
                transform: isActive ? 'translateZ(6px) scale(1.02)' : 'translateZ(0px) scale(1)',
                pointerEvents: 'none'
              }}
            >
              {Array.from({ length: LAYERS }).map((_, i) => {
                const isTop = i === LAYERS - 1;
                return (
                  <svg
                    key={i}
                    viewBox="0 0 180 180"
                    style={{
                      position: 'absolute',
                      inset: 0,
                      width: '100%',
                      height: '100%',
                      transform: `translateZ(${i * 0.8}px)`,
                      overflow: 'visible',
                      filter: isTop && isActive ? `drop-shadow(0 0 16px ${slice.color}66)` : 'none'
                    }}
                  >
                    <circle
                      cx="90"
                      cy="90"
                      r={R}
                      fill="none"
                      stroke={isTop ? slice.color : slice.colorDark}
                      strokeWidth="56"
                      strokeDasharray={`${slice.strokeLen} 1000`}
                      transform={`rotate(${slice.angle}, 90, 90)`}
                      strokeLinecap="butt"
                      onMouseEnter={isTop ? () => onHover(slice.id) : undefined}
                      onMouseLeave={isTop ? () => onHover(null) : undefined}
                      onClick={isTop ? () => onClick(slice.id) : undefined}
                      style={{
                        transition: 'all 0.3s',
                        pointerEvents: isTop ? 'visibleStroke' : 'none',
                        cursor: isTop ? 'pointer' : 'default'
                      }}
                    />
                  </svg>
                );
              })}
            </div>
          );
        })}
      </div>
    </div>
  );
}
