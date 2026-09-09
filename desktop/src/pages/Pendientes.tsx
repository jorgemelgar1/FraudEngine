import { useCallback, useEffect, useMemo, useState } from 'react';
import type { Session } from '@supabase/supabase-js';

import {
  listPending, reviewFindings, reopenInfo, countryCodeOf,
  REVIEW_REASONS, type PendingFinding, type ReviewReason,
} from '../lib/findings';
import { describePattern, rankPatterns, verdictFor, actionFor } from '../lib/patterns';
import { isNetworkError } from '../lib/offline';
import { OfflineState } from '../components/OfflineState';

// ── Formatting ───────────────────────────────────────────────────────────────

const fmtCurrency = (n: number | null, code: string | null) => {
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
};

const fmtDay = (iso: string | null | undefined) => {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString('es', { day: 'numeric', month: 'short' });
};

function hoursSince(iso: string | null | undefined): number | null {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return null;
  return (Date.now() - t) / 3_600_000;
}

/** "hace 3 días". The number that makes a queue get drained. */
function fmtAge(iso: string | null | undefined): string {
  const h = hoursSince(iso);
  if (h === null) return '';
  if (h < 1) return 'recién';
  if (h < 24) return `hace ${Math.round(h)} h`;
  return `hace ${Math.round(h / 24)} día${Math.round(h / 24) === 1 ? '' : 's'}`;
}

// Two days without a decision is when a queue starts rotting. Not an SLA, just
// the point where the row should start asking for attention.
const STALE_HOURS = 48;

function isStale(f: PendingFinding): boolean {
  const h = hoursSince(f.first_seen_at);
  return h !== null && h > STALE_HOURS;
}

/**
 * Volume context, built here rather than taken from `description_es`.
 *
 * The engine's description opens with "47 transacciones (23 REJECTED, 4
 * SUCCEEDED)" and then concatenates every pattern sentence after it. We show
 * the patterns individually, so reusing that string would print each
 * explanation twice — once in the paragraph and once beside its own tag.
 */
function volumeLine(payload: Record<string, unknown>): string | null {
  const total = Number(payload?.total_transactions ?? 0);
  if (!total) return null;
  const rejected = Number(payload?.rejected_count ?? 0);
  const succeeded = Number(payload?.succeeded_count ?? 0);
  return `${total} transacciones · ${rejected} rechazadas · ${succeeded} exitosas`;
}

// One-line stand-in for the exposure figure on zero-settlement findings,
// pulled from the detector's own `metrics` block in the payload. Returns a
// generic line if the payload predates the metrics block or is shaped
// unexpectedly — this is display-only, so it must never throw.
function zeroSettlementSummary(payload: Record<string, unknown>): string {
  const m = (payload as { metrics?: Record<string, unknown> })?.metrics;
  if (!m) return 'Sin exposición (nada se liquidó)';
  const attempts = Number(m.attempts ?? 0);
  const cards = Number(m.distinct_cards ?? 0);
  const ips = Number(m.distinct_ips ?? 0);
  return `${attempts} intentos · ${cards} tarjetas · ${ips} IP`;
}

// ── Page ─────────────────────────────────────────────────────────────────────

export function Pendientes({
  session, online, onChanged,
}: {
  session: Session;
  online: boolean;
  // Fires after every successful decision so the header badge refreshes.
  onChanged: () => void;
}) {
  const [findings, setFindings] = useState<PendingFinding[] | null>(null);
  // Total pending, ignoring the query limit. Kept so the screen can SAY it is
  // showing a subset instead of silently pretending the rest do not exist.
  const [total, setTotal] = useState(0);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [country, setCountry] = useState<string>('all');
  // Which finding is mid-dismissal. Null means nobody is being asked why.
  const [dismissing, setDismissing] = useState<string | null>(null);
  const [offline, setOffline] = useState(false);

  const load = useCallback(async () => {
    if (!online) {
      setOffline(true);
      setFindings(null);
      return;
    }
    setError('');
    setOffline(false);
    try {
      const page = await listPending();
      setFindings(page.rows);
      setTotal(page.total);
    } catch (e) {
      if (isNetworkError(e)) {
        setOffline(true);
        setFindings(null);
      } else {
        setError(e instanceof Error ? e.message : String(e));
      }
    }
  }, [online]);

  useEffect(() => { load(); }, [load]);

  async function decide(
    action: 'accept' | 'reject',
    ids: string[],
    reason?: ReviewReason,
    note?: string,
  ) {
    if (ids.length === 0) return;
    setBusy(prev => new Set(prev).add(ids[0]));
    try {
      const results = await reviewFindings(
        ids, action, session.user.id, session.user.email!, reason, note,
      );
      // Drop only the rows that succeeded; failed ones stay so the user can
      // retry without reloading the whole list.
      const ok = new Set(results.filter(r => r.ok).map(r => r.id));
      setFindings(prev => (prev || []).filter(f => !ok.has(f.id)));
      setTotal(t => Math.max(0, t - ok.size));
      const failed = results.filter(r => !r.ok);
      setError(failed.length
        ? `No se pudo procesar: ${failed[0].error || failed[0].id}`
        : '');
      setDismissing(null);
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(prev => {
        const next = new Set(prev);
        ids.forEach(id => next.delete(id));
        return next;
      });
    }
  }

  function toggle(id: string) {
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  // Countries present in the queue, so the filter never offers an empty one.
  const countries = useMemo(() => {
    const seen = new Map<string, number>();
    for (const f of findings || []) {
      const c = countryCodeOf(f.analysis_runs?.currency_source);
      if (c) seen.set(c, (seen.get(c) || 0) + 1);
    }
    return [...seen.entries()].sort((a, b) => b[1] - a[1]);
  }, [findings]);

  const visible = useMemo(() => {
    const rows = (findings || []).filter(f =>
      country === 'all' || countryCodeOf(f.analysis_runs?.currency_source) === country);
    // Worst first, and among equal scores the most money at stake. Grouping by
    // upload made sense when a person uploaded one file a day; with the runner
    // producing eight it just scattered the queue across headers.
    return rows.sort((a, b) =>
      (b.risk_score - a.risk_score)
      || ((b.chargeback_exposure_usd || 0) - (a.chargeback_exposure_usd || 0)));
  }, [findings, country]);

  const staleCount = visible.filter(isStale).length;
  const atRisk = visible.reduce((s, f) => s + (f.chargeback_exposure_usd || 0), 0);

  if (offline) {
    return <OfflineState title="Revisiones pendientes" onRetry={load} disabled={!online} />;
  }

  return (
    <main className="main">
      <div className="card">
        <div className="queue-head">
          <div>
            <h2 style={{ margin: 0 }}>
              {findings === null
                ? 'Cargando…'
                : total === 0
                  ? 'No hay comercios por revisar'
                  : `Tienes ${total} comercio${total === 1 ? '' : 's'} por revisar`}
            </h2>
            {findings !== null && total > 0 && (
              <p className="muted small" style={{ margin: '.3rem 0 0' }}>
                {staleCount > 0 && (
                  <span className="stale-note">
                    {staleCount} lleva{staleCount === 1 ? '' : 'n'} más de 2 días esperando ·{' '}
                  </span>
                )}
                {atRisk > 0 && `${fmtCurrency(atRisk, 'USD')} en riesgo estimado`}
              </p>
            )}
          </div>
        </div>

        {countries.length > 1 && (
          <div className="chip-filters">
            <FilterChip on={country === 'all'} onClick={() => setCountry('all')}>
              Todos {findings?.length ?? 0}
            </FilterChip>
            {countries.map(([code, n]) => (
              <FilterChip key={code} on={country === code} onClick={() => setCountry(code)}>
                {code} {n}
              </FilterChip>
            ))}
          </div>
        )}

        <p className="muted small" style={{ marginBottom: 0 }}>
          Cada comercio necesita una decisión: <strong>confirmar fraude</strong>{' '}
          lo agrega a la watchlist, <strong>no es fraude</strong> lo descarta
          como falso positivo y guarda el motivo.
        </p>

        {/* Past the query limit the list is a subset. Saying so beats the
            header badge quietly disagreeing with what is on screen. */}
        {findings !== null && total > findings.length && (
          <div className="error-banner" style={{ marginTop: '1rem' }}>
            Mostrando {findings.length} de {total} pendientes, los de mayor
            riesgo primero. Revisa algunos para ver el resto.
          </div>
        )}
        {error && <div className="error-banner" style={{ marginTop: '1rem' }}>{error}</div>}
        {findings !== null && total === 0 && (
          <p className="success-banner" style={{ marginTop: '1rem' }}>
            La cola está vacía. El runner sigue analizando cada hora.
          </p>
        )}
      </div>

      {visible.length > 0 && (
        <div className="card queue-list">
          {visible.map(f => (
            <QueueRow
              key={f.id}
              f={f}
              open={expanded.has(f.id)}
              busy={busy.has(f.id)}
              dismissing={dismissing === f.id}
              onToggle={() => toggle(f.id)}
              onConfirm={() => decide('accept', [f.id])}
              onStartDismiss={() => setDismissing(f.id)}
              onCancelDismiss={() => setDismissing(null)}
              onDismiss={(reason, note) => decide('reject', [f.id], reason, note)}
            />
          ))}
        </div>
      )}
    </main>
  );
}

// ── One merchant ─────────────────────────────────────────────────────────────

function QueueRow({
  f, open, busy, dismissing,
  onToggle, onConfirm, onStartDismiss, onCancelDismiss, onDismiss,
}: {
  f: PendingFinding;
  open: boolean;
  busy: boolean;
  dismissing: boolean;
  onToggle: () => void;
  onConfirm: () => void;
  onStartDismiss: () => void;
  onCancelDismiss: () => void;
  onDismiss: (reason: ReviewReason, note: string) => void;
}) {
  const reopened = reopenInfo(f);
  const country = countryCodeOf(f.analysis_runs?.currency_source);
  const seen = f.times_seen ?? 1;
  const stale = isStale(f);
  const zero = f.section === 'zero_settlement';
  const patterns = rankPatterns(f.fingerprints || []);
  const action = actionFor(f.action_code);
  const evidence = ((f.payload as any)?.evidence || []) as Array<Record<string, unknown>>;
  const volume = volumeLine(f.payload);

  return (
    <div className={`qrow ${open ? 'open' : ''} ${reopened ? 'reopened' : ''}`}>
      <button className="qrow-head" onClick={onToggle} aria-expanded={open}>
        <span className={`qscore ${f.risk_score >= 80 ? 'hot' : ''}`}>{f.risk_score}</span>
        <span className="qmain">
          <span className="qname">
            {f.company_name}
            {country && <span className="tag country">{country}</span>}
            {reopened && <span className="tag reopened-chip">volvió</span>}
          </span>
          <span className="qverdict">
            {verdictFor(f.finding_type)}
            {' · '}
            {seen > 1
              ? `visto ${seen} veces desde el ${fmtDay(f.first_seen_at)}`
              : 'primera detección'}
          </span>
        </span>
        <span className="qright">
          <span className="qamt">
            {zero
              ? <span className="muted small">sin liquidación</span>
              : fmtCurrency(f.chargeback_exposure_usd, f.chargeback_exposure_currency)}
          </span>
          <span className={`qage ${stale ? 'stale' : ''}`}>{fmtAge(f.first_seen_at)}</span>
        </span>
        <span className="qcaret" aria-hidden="true">{open ? '▾' : '▸'}</span>
      </button>

      {open && (
        <div className="qbody">
          {/* The runner re-opens a dismissed finding when it comes back
              materially worse, and records why. Until now that reason was
              written and never shown, so a re-opened finding looked brand new
              and could be dismissed again on reasoning that had stopped being
              true. Slack now sends people straight to this screen. */}
          {reopened && (
            <div className="reopen-banner">
              <div className="reopen-title">⟳ Ya se revisó antes</div>
              <div>
                Descartado
                {reopened.rejectedBy ? ` por ${reopened.rejectedBy}` : ''}
                {' '}el {fmtDay(reopened.rejectedAt)}
                {reopened.reason
                  ? <> · volvió porque <strong>{reopened.reason}</strong>.</>
                  : ' · volvió a la cola.'}
              </div>
            </div>
          )}

          {volume && <div className="qvolume">{volume}</div>}
          {zero && <div className="qvolume">{zeroSettlementSummary(f.payload)}</div>}

          {/* One sentence per pattern, strongest first. The engine writes the
              same explanations but joins them into a single paragraph with no
              link back to the tags — see lib/patterns.ts. */}
          <div className="qwhy">
            {patterns.map(code => {
              const p = describePattern(code);
              return (
                <div className="qwhy-item" key={code}>
                  <span className="qwhy-tag">{p.label}</span>
                  <span className="qwhy-txt">{p.explain}</span>
                </div>
              );
            })}
          </div>

          {action && (
            <div className="qreco"><strong>Acción recomendada:</strong> {action}</div>
          )}

          {evidence.length > 0 && (
            <details className="qevidence">
              <summary>Ver transacciones ({evidence.length} de ejemplo)</summary>
              <ul className="evidence-list">
                {evidence.map((e, i) => (
                  <li key={i}>
                    {String(e.transaction_id || '?')} · {String(e.status || '')}
                    {e.card_bin ? ` · ${String(e.card_bin)}-${String(e.card_last_digits ?? '')}` : ''}
                    {e.timestamp ? ` · ${String(e.timestamp).slice(0, 19).replace('T', ' ')}` : ''}
                  </li>
                ))}
              </ul>
            </details>
          )}

          {dismissing ? (
            <DismissForm
              company={f.company_name}
              busy={busy}
              onCancel={onCancelDismiss}
              onSubmit={onDismiss}
            />
          ) : (
            <div className="qactions">
              <button className="btn danger" disabled={busy} onClick={onConfirm}>
                Confirmar fraude
              </button>
              <button className="btn ghost" disabled={busy} onClick={onStartDismiss}>
                No es fraude
              </button>
              <span className="muted small qsource">
                {f.analysis_runs?.source === 'auto'
                  ? 'Detectado por el runner'
                  : `Subido por ${f.analysis_runs?.run_by_email || 'alguien'}`}
                {' · '}{fmtDay(f.analysis_runs?.run_at)}
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Asking why ───────────────────────────────────────────────────────────────

function DismissForm({
  company, busy, onCancel, onSubmit,
}: {
  company: string;
  busy: boolean;
  onCancel: () => void;
  onSubmit: (reason: ReviewReason, note: string) => void;
}) {
  const [reason, setReason] = useState<ReviewReason | null>(null);
  const [note, setNote] = useState('');

  return (
    <div className="dismiss">
      <div className="dismiss-title">{company} — ¿por qué no es fraude?</div>
      <div className="muted small" style={{ marginBottom: '.6rem' }}>
        Se guarda con tu nombre. Sirve para medir en qué se equivoca el motor.
      </div>
      <div className="chip-filters">
        {REVIEW_REASONS.map(r => (
          <FilterChip key={r.value} on={reason === r.value} onClick={() => setReason(r.value)}>
            {r.label}
          </FilterChip>
        ))}
      </div>
      <input
        className="dismiss-note"
        placeholder="Nota opcional…"
        value={note}
        maxLength={300}
        onChange={e => setNote(e.target.value)}
      />
      <div className="qactions">
        <button
          className="btn"
          disabled={busy || !reason}
          onClick={() => reason && onSubmit(reason, note.trim())}
          title={reason ? undefined : 'Elige un motivo primero'}
        >
          {busy ? 'Guardando…' : 'Guardar y descartar'}
        </button>
        <button className="btn ghost" disabled={busy} onClick={onCancel}>
          Cancelar
        </button>
      </div>
    </div>
  );
}

function FilterChip({
  on, onClick, children,
}: {
  on: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button className={`chip-filter ${on ? 'on' : ''}`} onClick={onClick}>
      {children}
    </button>
  );
}
