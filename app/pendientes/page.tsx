'use client';

import { useEffect, useState, useCallback } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { createClient } from '@/lib/supabase/client';

type PendingFinding = {
  id: string;
  run_id: string;
  company_name: string;
  company_id: string | null;
  finding_type: string;
  confidence: 'Critical';
  risk_score: number;
  fingerprints: string[];
  // Which detector produced this (migration 0007). Optional so rows written
  // before that migration — which have no section — still render.
  section?: 'exposure' | 'zero_settlement';
  chargeback_exposure_usd: number | null;
  chargeback_exposure_currency: string | null;
  description_es: string | null;
  payload: Record<string, unknown>;
  analysis_runs: {
    run_at: string;
    run_by_email: string;
    csv_filename: string | null;
    csv_date_start: string | null;
    csv_date_end: string | null;
  } | null;
};

type RunGroup = {
  run_id: string;
  run_at: string;
  run_by_email: string;
  csv_filename: string | null;
  csv_date_start: string | null;
  csv_date_end: string | null;
  findings: PendingFinding[];
};

const fmtCurrency = (n: number | null, code: string | null) => {
  if (n == null) return '—';
  try {
    return n.toLocaleString('en-US', { style: 'currency', currency: code || 'USD' });
  } catch {
    return `${code || 'USD'} ${n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  }
};

// One-line stand-in for the exposure figure on zero-settlement findings,
// pulled from the detector's own `metrics` block in the payload. Returns a
// dash if the payload predates the metrics block or is shaped unexpectedly —
// this is display-only, so it must never throw.
function zeroSettlementSummary(payload: Record<string, unknown>): string {
  const m = (payload as { metrics?: Record<string, unknown> })?.metrics;
  if (!m) return 'Sin exposición (nada se liquidó)';
  const attempts = Number(m.attempts ?? 0);
  const cards = Number(m.distinct_cards ?? 0);
  const ips = Number(m.distinct_ips ?? 0);
  return `${attempts} intentos · ${cards} tarjetas · ${ips} IP`;
}

export default function PendientesPage() {
  const router = useRouter();
  const [findings, setFindings] = useState<PendingFinding[] | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const load = useCallback(async () => {
    setError('');
    const supabase = createClient();
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) {
      router.push('/login');
      return;
    }
    const res = await fetch('/api/findings?status=pending', {
      headers: { Authorization: `Bearer ${session.access_token}` },
    });
    if (res.status === 401) {
      router.push('/login');
      return;
    }
    const json = await res.json();
    if (!res.ok) {
      setError(json.error || `El servidor respondió con ${res.status}`);
      return;
    }
    setFindings(json.findings || []);
  }, [router]);

  useEffect(() => { load(); }, [load]);

  async function review(action: 'accept' | 'reject', findingIds: string[]) {
    if (findingIds.length === 0) return;
    const supabase = createClient();
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) {
      router.push('/login');
      return;
    }
    setBusy(prev => {
      const next = new Set(prev);
      findingIds.forEach(id => next.add(id));
      return next;
    });
    try {
      const res = await fetch('/api/findings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.access_token}`,
        },
        body: JSON.stringify({ action, finding_ids: findingIds }),
      });
      const json = await res.json();
      if (!res.ok) {
        setError(json.error || `El servidor respondió con ${res.status}`);
        return;
      }
      // The RPC returns per-id success state. Drop only the rows that
      // succeeded; leave any that errored so the user can retry.
      const okIds = new Set(
        (json.results || []).filter((r: any) => r.ok).map((r: any) => r.id),
      );
      setFindings(prev => (prev || []).filter(f => !okIds.has(f.id)));
      const errors = (json.results || []).filter((r: any) => !r.ok);
      if (errors.length > 0) {
        setError(`Algunos hallazgos no se pudieron procesar: ${errors[0].error}`);
      }
    } catch (e: any) {
      setError(e?.message || 'Acción fallida');
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

  // Group findings by run so bulk actions are scoped to one upload.
  const groups: RunGroup[] = (() => {
    if (!findings) return [];
    const map = new Map<string, RunGroup>();
    for (const f of findings) {
      const existing = map.get(f.run_id);
      if (existing) {
        existing.findings.push(f);
      } else {
        map.set(f.run_id, {
          run_id: f.run_id,
          run_at: f.analysis_runs?.run_at || '',
          run_by_email: f.analysis_runs?.run_by_email || '',
          csv_filename: f.analysis_runs?.csv_filename || null,
          csv_date_start: f.analysis_runs?.csv_date_start || null,
          csv_date_end: f.analysis_runs?.csv_date_end || null,
          findings: [f],
        });
      }
    }
    return Array.from(map.values()).sort(
      (a, b) => (b.run_at || '').localeCompare(a.run_at || ''),
    );
  })();

  return (
    <>
      <header>
        <div className="brand">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img
            src="https://buznvtdzsigrtruighzx.supabase.co/storage/v1/object/public/Assets/Cubo.png"
            alt="Cubo"
          />
          <span className="product">Fraud Engine</span>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <Link href="/" className="signout">Inicio</Link>
          <Link href="/historial" className="signout">Historial</Link>
          <Link href="/indicadores" className="signout">Indicadores</Link>
        </div>
      </header>

      <div className="container">
        <div className="card">
          <h2 style={{ marginTop: 0 }}>Revisiones pendientes</h2>
          <p className="muted" style={{ marginTop: 0 }}>
            Cada hallazgo Critical permanece pendiente hasta que un miembro del
            equipo lo acepte (se agrega a la Watchlist) o lo descarte. Los
            falsos positivos descartados no afectan la Watchlist. Se incluyen
            tanto los hallazgos por exposición a chargebacks como los de
            comercios <strong>sin liquidación</strong> (card testing).
          </p>
          {error && <div className="error" style={{ marginTop: '1rem' }}>{error}</div>}
          {findings === null && <p className="muted">Cargando…</p>}
          {findings !== null && findings.length === 0 && (
            <p className="success" style={{ margin: 0 }}>
              No hay hallazgos pendientes de revisión.
            </p>
          )}
        </div>

        {groups.map(g => {
          const groupIds = g.findings.map(f => f.id);
          const groupBusy = groupIds.some(id => busy.has(id));
          return (
            <div className="card" key={g.run_id}>
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'flex-start',
                flexWrap: 'wrap',
                gap: '0.5rem',
              }}>
                <div>
                  <strong>{g.csv_filename || '(sin nombre)'}</strong>
                  <div className="muted" style={{ fontSize: '0.9rem' }}>
                    {g.csv_date_start === g.csv_date_end
                      ? g.csv_date_start
                      : `${g.csv_date_start} → ${g.csv_date_end}`}
                    {' · '}
                    Subido por {g.run_by_email}
                    {' · '}
                    {g.findings.length} pendiente{g.findings.length === 1 ? '' : 's'}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <button
                    className="signout"
                    disabled={groupBusy}
                    onClick={() => review('accept', groupIds)}
                  >
                    Aceptar todos
                  </button>
                  <button
                    className="signout"
                    disabled={groupBusy}
                    onClick={() => review('reject', groupIds)}
                  >
                    Descartar todos
                  </button>
                </div>
              </div>

              <div style={{ marginTop: '1rem' }}>
                {g.findings.map(f => {
                  const isOpen = expanded.has(f.id);
                  const isBusy = busy.has(f.id);
                  const evidence = ((f.payload as any)?.evidence || []) as Array<Record<string, unknown>>;
                  const action = (f.payload as any)?.recommended_action_es as string | undefined;
                  return (
                    <div key={f.id} className="finding">
                      <div style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'flex-start',
                        flexWrap: 'wrap',
                        gap: '0.5rem',
                      }}>
                        <div style={{ flex: '1 1 320px' }}>
                          <strong>{f.company_name}</strong>
                          {f.section === 'zero_settlement' && (
                            <span
                              className="tag"
                              style={{
                                marginLeft: '0.6rem',
                                background: 'rgba(255, 107, 53, 0.15)',
                                color: 'var(--cubo-orange)',
                              }}
                            >
                              Sin liquidación
                            </span>
                          )}
                          <span className="muted" style={{ marginLeft: '0.75rem' }}>
                            Riesgo: {f.risk_score}
                          </span>
                          {/* Zero-settlement findings settle nothing, so an
                              exposure figure would always read "—". Show the
                              card-testing metrics that justify the flag instead. */}
                          {f.section === 'zero_settlement' ? (
                            <span className="muted" style={{ marginLeft: '0.75rem' }}>
                              {zeroSettlementSummary(f.payload)}
                            </span>
                          ) : (
                            <span className="muted" style={{ marginLeft: '0.75rem' }}>
                              Exposición: {fmtCurrency(f.chargeback_exposure_usd, f.chargeback_exposure_currency)}
                            </span>
                          )}
                          <p style={{ margin: '0.4rem 0', fontSize: '0.95rem' }}>
                            {f.description_es}
                          </p>
                          <div>
                            {(f.fingerprints || []).map(fp => (
                              <span className="tag" key={fp}>{fp}</span>
                            ))}
                          </div>
                        </div>
                        <div style={{ display: 'flex', gap: '0.4rem' }}>
                          <button
                            className="signout"
                            disabled={isBusy}
                            onClick={() => review('accept', [f.id])}
                          >
                            Aceptar
                          </button>
                          <button
                            className="signout"
                            disabled={isBusy}
                            onClick={() => review('reject', [f.id])}
                          >
                            Descartar
                          </button>
                          <button
                            className="signout"
                            onClick={() => toggleExpanded(f.id)}
                          >
                            {isOpen ? 'Ocultar' : 'Detalles'}
                          </button>
                        </div>
                      </div>
                      {isOpen && (
                        <div style={{ marginTop: '0.75rem', paddingTop: '0.75rem', borderTop: '1px solid var(--border)' }}>
                          {action && (
                            <p className="muted" style={{ marginTop: 0 }}>
                              <strong>Acción recomendada:</strong> {action}
                            </p>
                          )}
                          {evidence.length > 0 && (
                            <>
                              <div className="muted" style={{ fontSize: '0.85rem', marginBottom: '0.4rem' }}>
                                Evidencia ({evidence.length} de hasta 5):
                              </div>
                              <ul style={{ margin: 0, paddingLeft: '1.2rem', fontSize: '0.85rem' }}>
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
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    </>
  );
}
