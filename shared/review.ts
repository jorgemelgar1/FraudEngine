// Review-queue logic that is not specific to either client.
//
// Everything here is pure: no Supabase client, no Tauri, no React. That is the
// condition for living at the repo root — the web app cannot import from
// desktop/ (.vercelignore excludes it), and the desktop cannot import from the
// Next app, so anything either one needs has to be dependency-free or it ends
// up copied and then drifts.
//
// It drifted before. This logic lived only in desktop/src/lib/findings.ts, so
// the browser queue could not say "visto 3 veces desde el 8 sep", could not
// tell a re-opened finding from a new one, and had no country tag — while the
// desktop showed all three from the same rows.
//
// Data ACCESS stays in each app (the desktop holds a Supabase client directly;
// the web goes through /api/findings), because those genuinely differ. Only the
// reading of the data is shared.

// ── Country ──────────────────────────────────────────────────────────────────

// Normalized country name (what analyze.py stores in currency_source) -> the
// code ops uses. Mirrors runner/config.py:COUNTRIES; an unmapped country
// returns null rather than a guess, exactly as the currency logic does.
const COUNTRY_CODES: Record<string, string> = {
  'panama': 'PA',
  'el salvador': 'SV',
  'guatemala': 'GT',
};

export function countryCodeOf(currencySource: string | null | undefined): string | null {
  if (!currencySource) return null;
  return COUNTRY_CODES[currencySource.trim().toLowerCase()] || null;
}

// ── Re-opened findings ───────────────────────────────────────────────────────

export type ReopenInfo = {
  rejectedAt: string;
  rejectedBy: string | null;
  reason: string | null;
};

// The shape a finding must have for reopenInfo to read it. Deliberately
// minimal — both clients carry far more, and naming only what is used keeps
// this from becoming a second copy of the row type.
export type ReviewedRow = {
  reviewed_at?: string | null;
  reviewed_by_email?: string | null;
  review_notes?: string | null;
};

// Pulls the most recent automatic re-opening out of review_notes.
//
// reopen_finding APPENDS with ' | ', so a finding re-opened twice carries both
// entries and the last one is the current story. A human Undo overwrites the
// column instead — but it also clears reviewed_at, so those rows never reach
// here.
// Anchored on "UTC:" rather than on the first colon, because the timestamp
// migration 0010 writes is `YYYY-MM-DD HH24:MI` — it CONTAINS a colon. Cutting
// at the first one turned "…14:00 UTC: el puntaje subió de 45 a 90" into a
// reason that read "00 UTC: el puntaje subió de 45 a 90".
// tests/test_reopen_note_contract.py pins this against the SQL.
const REOPEN_RE = /^Reabierto autom[áa]ticamente .*?UTC:\s*(.+)$/;

// The note ends with "(puntaje anterior 45, ahora 90)", which just restates
// what the sentence before it already said. Dropped: the current score is on
// the row anyway.
const TRAILING_SCORES = /\s*\(puntaje anterior[^)]*\)\s*$/;

export function reopenInfo(f: ReviewedRow): ReopenInfo | null {
  if (!f.reviewed_at) return null;
  let reason: string | null = null;
  for (const part of (f.review_notes || '').split(' | ').reverse()) {
    const m = part.trim().match(REOPEN_RE);
    if (m) {
      reason = m[1].replace(TRAILING_SCORES, '').trim();
      break;
    }
  }
  return {
    rejectedAt: f.reviewed_at,
    rejectedBy: f.reviewed_by_email || null,
    reason,
  };
}

// ── Ageing ───────────────────────────────────────────────────────────────────

// A pending finding older than this has been sitting in the queue rather than
// being worked. Not a failure — a prompt. Deposits go out daily, so anything
// still unreviewed after two days has outlived the decision it was meant to
// inform.
export const STALE_AFTER_HOURS = 48;

export function hoursSince(iso: string | null | undefined): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return (Date.now() - t) / 36e5;
}

export function isStalePending(firstSeenAt: string | null | undefined): boolean {
  const h = hoursSince(firstSeenAt);
  return h != null && h >= STALE_AFTER_HOURS;
}

// ── Formatting ───────────────────────────────────────────────────────────────

export function fmtAge(iso: string | null | undefined): string {
  const h = hoursSince(iso);
  if (h == null) return '—';
  if (h < 1) return 'hace minutos';
  if (h < 24) return `hace ${Math.floor(h)} h`;
  const d = Math.floor(h / 24);
  return d === 1 ? 'hace 1 día' : `hace ${d} días`;
}

export function fmtDay(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString('es', { day: 'numeric', month: 'short' });
}

export function fmtCurrency(n: number | null | undefined, code: string | null | undefined): string {
  if (n == null) return '—';
  // Rows written before the 2026-09 currency fix carry 'UNKNOWN' (migration
  // 0009): the engine could not tell GTQ from USD, so claiming either would
  // be a guess. Show the amount without asserting a currency.
  if (!code || code === 'UNKNOWN') {
    return `${n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })} (sin moneda)`;
  }
  try {
    return n.toLocaleString('en-US', { style: 'currency', currency: code, maximumFractionDigits: 0 });
  } catch {
    // An ISO code we don't recognise — a country mapped server-side but not
    // known to Intl. Render the number and the raw code rather than crashing.
    return `${code} ${n.toLocaleString('en-US', { maximumFractionDigits: 0 })}`;
  }
}

// ── Reading a finding's payload ──────────────────────────────────────────────

// The payload is the engine's own finding object. These readers are tolerant
// by design: rows written by older engine versions are missing fields, and a
// review queue that throws on a six-week-old row is worse than one that says
// less about it.

export function seenLine(timesSeen: number | null | undefined, firstSeenAt: string | null | undefined): string {
  const n = timesSeen ?? 1;
  if (n > 1 && firstSeenAt) return `visto ${n} veces desde el ${fmtDay(firstSeenAt)}`;
  if (n > 1) return `visto ${n} veces`;
  return 'primera detección';
}

// How much of the merchant's book a finding actually implicates. Returns ''
// when the payload predates the scoping fields (2026-09), so older rows render
// exactly as they did rather than claiming a scope nobody computed.
export function exposureScope(payload: Record<string, unknown> | null | undefined): string {
  const p = (payload || {}) as {
    suspicious_settled_count?: unknown;
    suspicious_transaction_count?: unknown;
    total_transactions?: unknown;
  };
  const settled = Number(p.suspicious_settled_count ?? NaN);
  const suspicious = Number(p.suspicious_transaction_count ?? NaN);
  const total = Number(p.total_transactions ?? NaN);
  if (!Number.isFinite(suspicious) || !Number.isFinite(total) || total <= 0) return '';

  if (Number.isFinite(settled) && settled > 0) {
    const s = settled === 1 ? '' : 's';
    return `${settled} cargo${s} sospechoso${s} liquidado${s}, de ${suspicious} transacciones marcadas (el merchant tiene ${total})`;
  }
  return `ningún cargo sospechoso se liquidó · ${suspicious} de ${total} transacciones marcadas`;
}

// One-line stand-in for the exposure figure on zero-settlement findings,
// pulled from the detector's own `metrics` block.
export function zeroSettlementSummary(payload: Record<string, unknown> | null | undefined): string {
  const m = (payload as { metrics?: Record<string, unknown> } | null)?.metrics;
  if (!m) return 'Sin exposición (nada se liquidó)';
  const attempts = Number(m.attempts ?? 0);
  const cards = Number(m.distinct_cards ?? 0);
  const ips = Number(m.distinct_ips ?? 0);
  return `${attempts} intentos · ${cards} tarjetas · ${ips} IP`;
}

// The evidence rows a finding quotes. Since 2026-09 these are the transactions
// that actually triggered it, which is what makes showing them worth the space.
export function evidenceOf(payload: Record<string, unknown> | null | undefined): Array<Record<string, unknown>> {
  const e = (payload as { evidence?: unknown } | null)?.evidence;
  return Array.isArray(e) ? (e as Array<Record<string, unknown>>) : [];
}
