import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

export interface SecurityEvent {
  event_id: string;
  timestamp: string;
  source_type: string;
  source_id: string;
  model: string;
  prompt: string;
  verdict: 'benign' | 'suspicious' | 'malicious';
  risk_score: number;
  blocked: boolean;
}

interface ExportContext {
  search?: string;
}

function buildSuffix(context?: ExportContext): string {
  const parts: string[] = [];
  if (context?.search) {
    parts.push(`search-${context.search.replace(/\s+/g, '-').slice(0, 20)}`);
  }
  parts.push(new Date().toISOString().replace(/[:.]/g, '-'));
  return parts.join('_');
}

function download(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 100);
}

function csvEscape(value: unknown): string {
  if (value === null || value === undefined) return '';
  const str = String(value);
  return /[",\n]/.test(str) ? `"${str.replace(/"/g, '""')}"` : str;
}

export function exportEventsToCSV(events: SecurityEvent[], context?: ExportContext) {
  if (events.length === 0) return;

  const headers: (keyof SecurityEvent)[] = [
    'event_id', 'timestamp', 'source_type', 'source_id',
    'model', 'verdict', 'risk_score', 'blocked', 'prompt',
  ];

  const rows = events.map(e => headers.map(h => csvEscape(e[h])).join(','));
  const csv = [headers.join(','), ...rows].join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  download(blob, `tenet_events_${buildSuffix(context)}.csv`);
}

export function exportEventsToJSON(events: SecurityEvent[], context?: ExportContext) {
  const payload = {
    exported_at: new Date().toISOString(),
    filter: context ?? null,
    count: events.length,
    events,
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  download(blob, `tenet_events_${buildSuffix(context)}.json`);
}

interface SummaryStats {
  total: number;
  blocked: number;
  malicious: number;
  suspicious: number;
  benign: number;
  avgRiskScore: number;
}

function computeStats(events: SecurityEvent[]): SummaryStats {
  const total = events.length;
  const blocked = events.filter(e => e.blocked).length;
  const malicious = events.filter(e => e.verdict === 'malicious').length;
  const suspicious = events.filter(e => e.verdict === 'suspicious').length;
  const benign = events.filter(e => e.verdict === 'benign').length;
  const avgRiskScore = total === 0
    ? 0
    : events.reduce((sum, e) => sum + (e.risk_score || 0), 0) / total;

  return { total, blocked, malicious, suspicious, benign, avgRiskScore };
}

export function exportEventsToPDF(events: SecurityEvent[], context?: ExportContext) {
  const doc = new jsPDF();
  const stats = computeStats(events);

  doc.setFontSize(18);
  doc.text('TENET AI - SOC Threat Report', 14, 18);

  doc.setFontSize(10);
  doc.setTextColor(100);
  doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 26);

  if (context?.search) {
    doc.text(`Search filter: "${context.search}"`, 14, 32);
  }

  doc.setFontSize(13);
  doc.setTextColor(0);
  doc.text('Summary', 14, 42);

  doc.setFontSize(10);
  const lines = [
    `Total events: ${stats.total}`,
    `Blocked: ${stats.blocked}`,
    `Malicious: ${stats.malicious}`,
    `Suspicious: ${stats.suspicious}`,
    `Benign: ${stats.benign}`,
    `Average risk score: ${stats.avgRiskScore.toFixed(2)}`,
  ];
  lines.forEach((line, i) => doc.text(line, 14, 50 + i * 6));

  const tableStartY = 50 + lines.length * 6 + 8;
  const MAX_ROWS = 200;
  const tableEvents = events.slice(0, MAX_ROWS);

  doc.setFontSize(13);
  doc.text('Recent Events', 14, tableStartY);

  autoTable(doc, {
    startY: tableStartY + 4,
    head: [['Timestamp', 'Source', 'Model', 'Verdict', 'Risk', 'Action']],
    body: tableEvents.map(e => [
      new Date(e.timestamp).toLocaleString(),
      `${e.source_type}/${e.source_id}`,
      e.model,
      e.verdict,
      (typeof e.risk_score === 'number' && !isNaN(e.risk_score) ? e.risk_score.toFixed(2) : '0.00'),
      e.blocked ? 'Blocked' : 'Allowed',
    ]),
    theme: 'striped',
    styles: { fontSize: 8 },
  });

  if (events.length > MAX_ROWS) {
    // @ts-expect-error injected by autoTable
    const finalY = doc.lastAutoTable.finalY + 8;
    doc.setFontSize(9);
    doc.setTextColor(120);
    doc.text(
      `Showing first ${MAX_ROWS} of ${events.length} events. Use CSV/JSON export for full data.`,
      14, finalY
    );
  }

  doc.save(`tenet_soc_report_${buildSuffix(context)}.pdf`);
}


