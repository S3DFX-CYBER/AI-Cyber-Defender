import type { ReactNode } from 'react';

interface ChartCardProps {
  title: string;
  description: string;
  children: ReactNode;
  headerExtra?: ReactNode;
  className?: string;
}

export function ChartCard({ title, description, children, headerExtra, className = '' }: ChartCardProps) {
  const slug = title.replace(/\s+/g, '-').toLowerCase();
  const titleId = `chart-title-${slug}`;
  const descId = `chart-desc-${slug}`;

  return (
    <section
      className={`chart-container ${className}`}
      aria-labelledby={titleId}
      aria-describedby={descId}
    >
      <div className="chart-header">
        <div>
          <h3 id={titleId}>{title}</h3>
          <p id={descId} className="chart-sr-summary">
            {description}
          </p>
        </div>
        {headerExtra}
      </div>
      {children}
    </section>
  );
}
