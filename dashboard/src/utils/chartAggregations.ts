import type { SecurityEvent, TimeRange } from '../types/security';
import { DAYS_OF_WEEK, threatTypeLabel } from '../constants/charts';

export interface NamedCount {
  name: string;
  value: number;
  key: string;
}

export interface TimeBucket {
  label: string;
  count: number;
  dateFrom: string;
  dateTo: string;
  hourFrom?: string;
  hourTo?: string;
}

export interface HeatmapCell {
  day: number;
  dayLabel: string;
  hour: number;
  hourLabel: string;
  count: number;
}

function inferThreatType(event: SecurityEvent): string {
  if (event.threat_type) return event.threat_type;
  if (event.verdict === 'benign') return 'benign';
  const prompt = event.prompt?.toLowerCase() ?? '';
  if (/ignore.*rules|dan\b|jailbreak/i.test(prompt)) return 'jailbreak';
  if (/bypass|inject|system prompt/i.test(prompt)) return 'prompt_injection';
  if (/extract|leak|password|credential/i.test(prompt)) return 'data_extraction';
  if (/phish|credential|login page/i.test(prompt)) return 'phishing';
  if (/you are now|role|pretend/i.test(prompt)) return 'role_manipulation';
  return 'unknown';
}

export function withThreatType(events: SecurityEvent[]): (SecurityEvent & { resolvedThreatType: string })[] {
  return events.map(e => ({ ...e, resolvedThreatType: inferThreatType(e) }));
}

export function aggregateThreatTypes(events: SecurityEvent[]): NamedCount[] {
  const counts = new Map<string, number>();
  withThreatType(events).forEach(e => {
    counts.set(e.resolvedThreatType, (counts.get(e.resolvedThreatType) ?? 0) + 1);
  });
  return [...counts.entries()]
    .map(([key, value]) => ({ key, name: threatTypeLabel(key), value }))
    .sort((a, b) => b.value - a.value);
}

export function aggregateSeverity(events: SecurityEvent[]): NamedCount[] {
  const order: SecurityEvent['verdict'][] = ['malicious', 'suspicious', 'benign'];
  const counts = new Map<string, number>();
  events.forEach(e => counts.set(e.verdict, (counts.get(e.verdict) ?? 0) + 1));
  return order
    .filter(v => (counts.get(v) ?? 0) > 0)
    .map(key => ({
      key,
      name: key.charAt(0).toUpperCase() + key.slice(1),
      value: counts.get(key) ?? 0,
    }));
}

export function aggregateAttackVectors(events: SecurityEvent[], limit = 8): NamedCount[] {
  return aggregateThreatTypes(events)
    .filter(t => t.key !== 'benign' && t.key !== 'unknown')
    .slice(0, limit);
}

function startOfHour(d: Date): Date {
  return new Date(d.getFullYear(), d.getMonth(), d.getDate(), d.getHours(), 0, 0, 0);
}

function startOfDay(d: Date): Date {
  return new Date(d.getFullYear(), d.getMonth(), d.getDate(), 0, 0, 0, 0);
}

function startOfWeek(d: Date): Date {
  const day = d.getDay();
  const diff = d.getDate() - day;
  return new Date(d.getFullYear(), d.getMonth(), diff, 0, 0, 0, 0);
}

function toDateInput(d: Date): string {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

/** Local date+hour key — avoids UTC ISO mismatches when bucketing hourly data. */
function hourlyBucketKey(d: Date): string {
  return `${toDateInput(d)}T${String(d.getHours()).padStart(2, '0')}`;
}

export function parseEventTimestamp(timestamp: string): Date | null {
  const ts = new Date(timestamp);
  return Number.isNaN(ts.getTime()) ? null : ts;
}

const CHART_LOCALE = 'en-US';

function formatHourLabel(d: Date): string {
  return d.toLocaleTimeString(CHART_LOCALE, { hour: '2-digit', minute: '2-digit', hour12: false });
}

function formatDayLabel(d: Date): string {
  return d.toLocaleDateString(CHART_LOCALE, { weekday: 'short', month: 'short', day: 'numeric' });
}

function formatShortDate(d: Date): string {
  return d.toLocaleDateString(CHART_LOCALE, { month: 'short', day: 'numeric' });
}

/** Anchor buckets to the newest event so historical/filtered data is not dropped. */
function resolveTimeAnchor(events: SecurityEvent[], fallback: Date): Date {
  let maxMs = -Infinity;
  for (const e of events) {
    const ts = parseEventTimestamp(e.timestamp);
    if (ts) maxMs = Math.max(maxMs, ts.getTime());
  }
  return maxMs !== -Infinity ? new Date(maxMs) : fallback;
}

export function aggregateDetectionsOverTime(
  events: SecurityEvent[],
  range: TimeRange,
  referenceDate: Date = new Date(),
): TimeBucket[] {
  if (events.length === 0) return [];

  const now = resolveTimeAnchor(events, referenceDate);
  const buckets = new Map<string, TimeBucket>();

  const ensureBucket = (
    key: string,
    label: string,
    from: Date,
    to: Date,
    hours?: { from: number; to: number },
  ) => {
    if (!buckets.has(key)) {
      buckets.set(key, {
        label,
        count: 0,
        dateFrom: toDateInput(from),
        dateTo: toDateInput(to),
        ...(hours && {
          hourFrom: String(hours.from),
          hourTo: String(hours.to),
        }),
      });
    }
    return buckets.get(key)!;
  };

  if (range === 'hourly') {
    for (let i = 23; i >= 0; i--) {
      const start = new Date(now);
      start.setHours(now.getHours() - i, 0, 0, 0);
      const end = new Date(start);
      end.setHours(start.getHours(), 59, 59, 999);
      const key = hourlyBucketKey(start);
      ensureBucket(
        key,
        formatHourLabel(start),
        start,
        end,
        { from: start.getHours(), to: end.getHours() },
      );
    }
    events.forEach(e => {
      const ts = parseEventTimestamp(e.timestamp);
      if (!ts) return;
      const key = hourlyBucketKey(startOfHour(ts));
      if (buckets.has(key)) buckets.get(key)!.count += 1;
    });
  } else if (range === 'daily') {
    for (let i = 6; i >= 0; i--) {
      const start = new Date(now);
      start.setDate(now.getDate() - i);
      const from = startOfDay(start);
      const to = new Date(from);
      to.setHours(23, 59, 59, 999);
      const key = toDateInput(from);
      ensureBucket(key, formatDayLabel(from), from, to);
    }
    events.forEach(e => {
      const ts = parseEventTimestamp(e.timestamp);
      if (!ts) return;
      const key = toDateInput(startOfDay(ts));
      if (buckets.has(key)) buckets.get(key)!.count += 1;
    });
  } else {
    for (let i = 3; i >= 0; i--) {
      const start = new Date(now);
      start.setDate(now.getDate() - i * 7);
      const from = startOfWeek(start);
      const to = new Date(from);
      to.setDate(from.getDate() + 6);
      to.setHours(23, 59, 59, 999);
      const key = toDateInput(from);
      ensureBucket(
        key,
        `${formatShortDate(from)} – ${formatShortDate(to)}`,
        from,
        to
      );
    }
    events.forEach(e => {
      const ts = parseEventTimestamp(e.timestamp);
      if (!ts) return;
      const key = toDateInput(startOfWeek(ts));
      if (buckets.has(key)) buckets.get(key)!.count += 1;
    });
  }

  return [...buckets.values()];
}

export function aggregateHeatmap(events: SecurityEvent[]): HeatmapCell[] {
  const grid = new Map<string, number>();

  events.forEach(e => {
    const ts = parseEventTimestamp(e.timestamp);
    if (!ts) return;
    const day = ts.getDay();
    const hour = ts.getHours();
    const key = `${day}-${hour}`;
    grid.set(key, (grid.get(key) ?? 0) + 1);
  });

  const cells: HeatmapCell[] = [];
  for (let day = 0; day < 7; day++) {
    for (let hour = 0; hour < 24; hour++) {
      cells.push({
        day,
        dayLabel: DAYS_OF_WEEK[day],
        hour,
        hourLabel: `${hour.toString().padStart(2, '0')}:00`,
        count: grid.get(`${day}-${hour}`) ?? 0,
      });
    }
  }
  return cells;
}

export function heatmapMaxCount(cells: HeatmapCell[]): number {
  return Math.max(1, ...cells.map(c => c.count));
}
