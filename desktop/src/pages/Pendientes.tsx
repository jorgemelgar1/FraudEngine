import { useCallback, useEffect, useState } from 'react';
import type { Session } from '@supabase/supabase-js';

import {
  listPending, reviewFindings, reopenInfo, countryCodeOf,
  type PendingFinding,
} from '../lib/findings';
import { isNetworkError } from '../lib/offline';
import { OfflineState } from '../components/OfflineState';

type RunGroup = {
  run_id: string;
  run_at: string;
  run_by_email: string;
  csv_filename: string | null;
  csv_date_start: string | null;
  csv_date_end: string | null;
  source: string | null;
  findings: PendingFinding[];
};

const fmtCurrency = (n: number | null, code: string | null) => {
  if (n == null) return '—';
  // Rows written before the 2026-09 currency fix carry 'UNKNOWN' (migration
  // 0009): the engine could not tell GTQ from USD, so claiming either would
  // be a guess. Show the amount without asserting a currency.
  if (!code || code === 'UNKNOWN') {
    return `${n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })} (sin moneda)`;
  }
  try {
    return n.toLocaleString('en-US', { style: 'currency', currency: code });
  } catch {
    // An ISO code we don't recognise - a country mapped server-side but not
    // known to Intl. Render the number and the raw code rather than crashing.
    return `${code} ${n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  }
};

const fmtDay = (iso: string | null | undefined) => {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString('es', { day: 'numeric', month: 'short' });
};

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

export function Pendientes({
  session, online, onChanged,
}: {
  session: Session;
  online: boolean;
  // Fires after every successful accept/reject so the header badge refreshes.
  onChanged: () => void;
}) {
  const [findings, setFindings] = useState<PendingFinding[] | null>(null);
  // Total pending, ignoring the query limit. Kept so the screen can SAY it is
  // showing a subset instead of silently pretending the rest do not exist.
  const [total, setTotal] = useState(0);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  // Set when a fetch fails with a network error. Separate from `!online`
  // because the OS-level online signal isn't 100% reliable — sometimes the
  // page can be "online" per the OS but Supabase is still unreachable
  // (DNS hiccup, captive portal, etc.). Either flag triggers the offline UI.
  const [offline, setOffline] = useState(false);

  const load = useCallback(async () => {
    // Short-circuit if the OS already knows we're disconnected — no point
    // making a fetch that's guaranteed to fail and stall the UI for ~5s
    // waiting on a timeout.
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

  // Auto-load on mount and whenever `online` changes — so flipping back
  // online silently refetches without the user having to click anywhere.
  useEffect(() => { load(); }, [load]);

  async function review(action: 'accept' | 'reject', findingIds: string[]) {
    if (findingIds.length === 0) return;
    setBusy(prev => {
      const next = new Set(prev);
      findingIds.forEach(id => next.add(id));
      return next;
    });
    try {
      const results = await reviewFindings(
        findingIds, action, session.user.id, session.user.email!,
      );
      // Drop only the rows that succeeded; failed ones stay in pending so
      // the user can retry without re-loading the whole list.
      const okIds = new Set(results.filter(r => r.ok).map(r => r.id));
      setFindings(prev => (prev || []).filter(f => !okIds.has(f.id)));
      const errors = results.filter(r => !r.ok);
      if (errors.length > 0) {
        setError(`Algunos hallazgos no se pudieron procesar: ${errors[0].error || errors[0].id}`);
      } else {
        setError('');
      }
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(prev => {
        const next = new Set(prev);
        findingIds.forEach(id => next.delete(id));
        return next;
      });
    }
  }

  function toggleExpanded(id: string) {
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  // Group findings by run so bulk actions are scoped to a single CSV upload.
  const groups: RunGroup[] = (() => {
    if (!findings) return [];
    const map = new Map<string, RunGroup>();
    for (const f of findings) {
      const existing = map.get(f.run_id);
      if (existing) {
        existing.findings.push(f);
      } else {
        map.set(f.run_id, {
          run_id:         f.run_id,
          run_at:         f.analysis_runs?.run_at || '',
          run_by_email:   f.analysis_runs?.run_by_email || '',
          csv_filename:   f.analysis_runs?.csv_filename || null,
          csv_date_start: f.analysis_runs?.csv_date_start || null,
          csv_date_end:   f.analysis_runs?.csv_date_end || null,
          source:         f.analysis_runs?.source || null,
          findings:       [f],
        });
      }
    }
    return Array.from(map.values()).sort(
      (a, b) => (b.run_at || '').localeCompare(a.run_at || ''),
    );
  })();

  if (offline) {
    return <OfflineState title="Revisiones pendientes" onRetry={load} disabled={!online} />;
  }

  return (
    <main className="main">
      <div className="card">
        <h2 style={{ marginTop: 0 }}>Revisiones pendientes</h2>
        <p className="muted">
          Cada hallazgo Critical permanece pendiente hasta que un miembro del
          equipo lo acepte (se agrega a la Watchlist) o lo descarte. Los
          falsos positivos descartados no afectan la Watchlist.
        </p>
        {/* Past the query limit the list is a subset. Saying so beats the
            header badge quietly disagreeing with what is on screen. */}
        {findings !== null && total > findings.length && (
          <div className="error-banner">
            Mostrando {findings.length} de {total} pendientes, los de mayor
            riesgo primero. Revisa algunos para ver el resto.
          </div>
        )}
        {error && <div className="error-banner">{error}</div>}
        {findings === null && <p className="muted">Cargando…</p>}
        {findings !== null && findings.length === 0 && (
          <p className="success-banner">
            No hay hallazgos pendientes de revisión.
          </p>
        )}
      </div>

      {groups.map(g => {
        const groupIds = g.findings.map(f => f.id);
        const groupBusy = groupIds.some(id => busy.has(id));
        return (
          <div className="card" key={g.run_id}>
            <div className="group-head">
              <div>
                <strong>{g.csv_filename || '(sin nombre)'}</strong>
                {/* Which of these came from the robot is the first question
                    anyone asks when a number looks wrong. The runner's email
                    hints at it; `source` is what actually records it. */}
                {g.source === 'auto' ? (
                  <span className="tag origin auto" style={{ marginLeft: '0.6rem' }}>
                    Automático
                  </span>
                ) : (
                  <span className="tag origin manual" style={{ marginLeft: '0.6rem' }}>
                    Manual
                  </span>
                )}
                <div className="muted small">
                  {g.csv_date_start === g.csv_date_end
                    ? g.csv_date_start
                    : `${g.csv_date_start} → ${g.csv_date_end}`}
                  {g.source === 'auto'
                    ? ' · Generado por el runner'
                    : ` · Subido por ${g.run_by_email}`}
                  {' · '}{g.findings.length} pendiente{g.findings.length === 1 ? '' : 's'}
                </div>
              </div>
              <div className="group-actions">
                <button
                  className="btn ghost small"
                  disabled={groupBusy}
                  onClick={() => review('accept', groupIds)}
                >
                  Aceptar todos
                </button>
                <button
                  className="btn ghost small"
                  disabled={groupBusy}
                  onClick={() => review('reject', groupIds)}
                >
                  Descartar todos
                </button>
              </div>
            </div>

            <ul className="findings" style={{ marginTop: '1rem' }}>
              {g.findings.map(f => {
                const isOpen = expanded.has(f.id);
                const isBusy = busy.has(f.id);
                const evidence = ((f.payload as any)?.evidence || []) as Array<Record<string, unknown>>;
                const action = (f.payload as any)?.recommended_action_es as string | undefined;
                const reopened = reopenInfo(f);
                const country = countryCodeOf(f.analysis_runs?.currency_source);
                const seen = f.times_seen ?? 1;
                return (
                  <li key={f.id} className="finding critical">
                    {/* The runner re-opens a dismissed finding when it comes
                        back materially worse, and records why. Until now that
                        reason was written and never shown, so a re-opened
                        finding looked brand new — and a reviewer could dismiss
                        it again on reasoning that had since stopped being
                        true. Slack now points people straight here. */}
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
                    <div className="finding-head">
                      <div style={{ flex: '1 1 320px' }}>
                        <strong>{f.company_name}</strong>
                        {country && (
                          <span className="tag country" style={{ marginLeft: '0.5rem' }}>
                            {country}
                          </span>
                        )}
                        {f.section === 'zero_settlement' && (
                          <span className="tag zero-settlement" style={{ marginLeft: '0.6rem' }}>
                            Sin liquidación
                          </span>
                        )}
                        <span className="muted small" style={{ marginLeft: '0.75rem' }}>
                          Riesgo: {f.risk_score}
                        </span>
                        {/* Zero-settlement findings settle nothing, so an
                            exposure figure would always read "—". Show the
                            card-testing metrics that justify the flag instead. */}
                        <span className="muted small" style={{ marginLeft: '0.75rem' }}>
                          {f.section === 'zero_settlement'
                            ? zeroSettlementSummary(f.payload)
                            : `Exposición: ${fmtCurrency(f.chargeback_exposure_usd, f.chargeback_exposure_currency)}`}
                        </span>
                      </div>
                      <div className="row-actions">
                        <button className="btn ghost small" disabled={isBusy} onClick={() => review('accept', [f.id])}>
                          Aceptar
                        </button>
                        <button className="btn ghost small" disabled={isBusy} onClick={() => review('reject', [f.id])}>
                          Descartar
                        </button>
                        <button className="btn ghost small" onClick={() => toggleExpanded(f.id)}>
                          {isOpen ? 'Ocultar' : 'Detalles'}
                        </button>
                      </div>
                    </div>
                    {f.description_es && (
                      <p style={{ margin: '0.4rem 0', fontSize: '0.95rem' }}>{f.description_es}</p>
                    )}
                    {/* Stored since migration 0010 and read by nothing until
                        now. One sighting may be noise; sixteen in a row is
                        not, and that is the cheapest way to prioritise. */}
                    <div className="muted small">
                      {seen > 1
                        ? `Visto ${seen} veces desde el ${fmtDay(f.first_seen_at)}`
                        : `Primera detección${f.first_seen_at ? `, el ${fmtDay(f.first_seen_at)}` : ''}`}
                    </div>
                    <div className="tags">
                      {(f.fingerprints || []).map(fp => (
                        <span className="tag" key={fp}>{fp}</span>
                      ))}
                    </div>
                    {isOpen && (
                      <div className="finding-details">
                        {action && (
                          <p className="muted">
                            <strong>Acción recomendada:</strong> {action}
                          </p>
                        )}
                        {evidence.length > 0 && (
                          <>
                            <div className="muted small" style={{ marginBottom: '0.4rem' }}>
                              Evidencia ({evidence.length} de hasta 5):
                            </div>
                            <ul className="evidence-list">
                              {evidence.map((e, i) => (
                                <li key={i}>
                                  {String(e.transaction_id || '?')} · {String(e.status || '')}
                                  {e.card_bin ? ` · ${String(e.card_bin)}-${String(e.card_last_digits ?? '')}` : ''}
                                  {e.timestamp ? ` · ${String(e.timestamp).slice(0, 19).replace('T', ' ')}` : ''}
                                </li>
                              ))}
                            </ul>
                          </>
                        )}
                      </div>
                    )}
                  </li>
                );
              })}
            </ul>
          </div>
        );
      })}
    </main>
  );
}
