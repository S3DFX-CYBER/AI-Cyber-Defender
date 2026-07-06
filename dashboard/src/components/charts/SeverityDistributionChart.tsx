import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell,
  PieChart, Pie, Legend,
} from 'recharts';
import type { ChartFilterAction } from '../../types/security';
import type { NamedCount } from '../../utils/chartAggregations';
import { SEVERITY_COLORS } from '../../constants/charts';
import { ChartCard } from './ChartCard';
import { CHART_TOOLTIP_PROPS, formatPercentTooltip } from './chartTooltipProps';

interface Props {
  data: NamedCount[];
  onFilter: (action: ChartFilterAction) => void;
}

function summaryText(data: NamedCount[]): string {
  if (data.length === 0) return 'No severity data available.';
  return data.map(d => `${d.name}: ${d.value}`).join(', ');
}

export function SeverityDistributionChart({ data, onFilter }: Props) {
  const total = data.reduce((s, d) => s + d.value, 0);

  return (
    <ChartCard
      title="Severity Distribution"
      description={`Distribution of detections by severity level. ${summaryText(data)}. Click a segment or bar to filter by severity.`}
      headerExtra={
        <span className="chart-hint">Bar + donut views</span>
      }
    >
      <div className="severity-charts">
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#27272a" vertical={false} />
            <XAxis dataKey="name" stroke="#a1a1aa" />
            <YAxis stroke="#a1a1aa" allowDecimals={false} />
            <Tooltip
              {...CHART_TOOLTIP_PROPS}
              cursor={{ fill: 'rgba(59, 130, 246, 0.1)' }}
              formatter={(value) => formatPercentTooltip(value, 'Count', total)}
            />
            <Bar
              dataKey="value"
              radius={[4, 4, 0, 0]}
              cursor="pointer"
              onClick={(_e, index) => {
                const item = data[index];
                if (item) onFilter({ verdict: item.key });
              }}
            >
              {data.map(entry => (
                <Cell key={entry.key} fill={SEVERITY_COLORS[entry.key] ?? '#999999'} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>

        <ResponsiveContainer width="100%" height={220}>
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              innerRadius={45}
              outerRadius={70}
              paddingAngle={4}
              cursor="pointer"
              onClick={(_data, index) => {
                const item = data[index];
                if (item) onFilter({ verdict: item.key });
              }}
            >
              {data.map(entry => (
                <Cell
                  key={entry.key}
                  fill={SEVERITY_COLORS[entry.key] ?? '#999999'}
                  stroke="#141417"
                  strokeWidth={2}
                />
              ))}
            </Pie>
            <Tooltip
              {...CHART_TOOLTIP_PROPS}
              formatter={(value, name) => formatPercentTooltip(value, String(name), total)}
            />
            <Legend
              verticalAlign="bottom"
              formatter={(value: string) => <span style={{ color: '#a1a1aa', fontSize: 12 }}>{value}</span>}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </ChartCard>
  );
}
