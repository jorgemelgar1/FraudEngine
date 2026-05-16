'use client';

import { useEffect, useState, useCallback } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { createClient } from '@/lib/supabase/client';

type HistoryFinding = {
  id: string;
  run_id: string;
  company_name: string;
  finding_type: string;
  risk_score: number;
  fingerprints: string[];
  chargeback_exposure_usd: number | null;
  chargeback_exposure_currency: string | null;
  description_es: string | null;
  review_status: 'accepted' | 'rejected';
  reviewed_at: string;
  reviewed_by_email: string | null;
  review_notes: string | null;
  watchlist_delta: Record<string, unknown> | null;
  payload: Record<string, unknown>;
  analysis_runs: {
    run_at: string;
    run_by_email: string;
    csv_filename: string | null;
  } | null;
};

const UNDO_WINDOW_HOURS = 24;

const fmtCurrency = (n: number | null, code: string | null) => {
  if (n == null) return '—';
  try {
    return n.toLocaleString('en-US', { style: 'currency', currency: code || 'USD' });
  } catch {
    return `${code || 'USD'} ${n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  }
};

const fmtDateTime = (iso: string) => {
  if (!iso) return '—';
  return iso.slice(0, 19).replace('T', ' ');
};

function hoursSince(iso: string): number {
  if (!iso) return Infinity;
  const then = new Date(iso).getTime();
  return (Date.now() - then) / (1000 * 60 * 60);
}

export default function HistorialPage() {
  const router = useRouter();
  const [findings, setFindings] = useState<HistoryFinding[] | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState<'all' | 'accepted' | 'rejected'>('all');

  const load = useCallback(async () => {
    setError('');
    const supabase = createClient();
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) {
      router.push('/login');
      return;
    }
    const res = await fetch('/api/findings?status=history', {
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

  async function undo(findingId: string) {
    const supabase = createClient();
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) {
      router.push('/login');
      return;
    }
    setBusy(prev => {
      const next = new Set(prev);
      next.add(findingId);
      return next;
    });
    try {
      const res = await fetch('/api/findings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.access_token}`,
        },
        body: JSON.stringify({ action: 'undo', finding_ids: [findingId] }),
      });
      const json = await res.json();
      if (!res.ok) {
        setError(json.error || `El servidor respondió con ${res.status}`);
        return;
      }
      const result = (json.results || [])[0];
      if (!result?.ok) {
        setError(result?.error || 'No se pudo deshacer');
        return;
      }
      // Drop the row from the table — it's back in pending.
      setFindings(prev => (prev || []).filter(f => f.id !== findingId));
    } catch (e: any) {
      setError(e?.message || 'Acción fallida');
    } finally {
      setBusy(prev => {
        const next = new Set(prev);
        next.delete(findingId);
        return next;
      });
    }
  }

  const visible = (findings || []).filter(f =>
    filter === 'all' ? true : f.review_status === filter,
  );

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
          <Link href="/pendientes" className="signout">Pendientes</Link>
        </div>
      </header>

      <div className="container">
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
            <h2 style={{ margin: 0 }}>Historial de revisiones</h2>
            <div style={{ display: 'flex', gap: '0.4rem' }}>
              <button
                className="signout"
                onClick={() => setFilter('all')}
                style={filter === 'all' ? { fontWeight: 700 } : undefined}
              >Todos</button>
              <button
                className="signout"
                onClick={() => setFilter('accepted')}
                style={filter === 'accepted' ? { fontWeight: 700 } : undefined}
              >Aceptados</button>
              <button
                className="signout"
                onClick={() => setFilter('rejected')}
                style={filter === 'rejected' ? { fontWeight: 700 } : undefined}
              >Descartados</button>
            </div>
          </div>
          <p className="muted" style={{ marginTop: '0.75rem', marginBottom: 0 }}>
            Decisiones tomadas por el equipo. Las decisiones pueden deshacerse
            dentro de las primeras {UNDO_WINDOW_HOURS} horas; después quedan
            bloqueadas y solo pueden revertirse re-analizando un CSV.
          </p>
          {error && <div className="error" style={{ marginTop: '1rem' }}>{error}</div>}
          {findings === null && <p className="muted">Cargando…</p>}
          {findings !== null && visible.length === 0 && (
            <p className="muted" style={{ marginTop: '1rem' }}>
              No hay revisiones para mostrar.
            </p>
          )}
        </div>

        {visible.length > 0 && (
          <div className="card">
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.9rem' }}>
                <thead>
                  <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--border)' }}>
                    <th style={{ padding: '0.5rem 0.4rem' }}>Fecha</th>
                    <th style={{ padding: '0.5rem 0.4rem' }}>Merchant</th>
                    <th style={{ padding: '0.5rem 0.4rem' }}>Riesgo</th>
                    <th style={{ padding: '0.5rem 0.4rem' }}>Exposición</th>
                    <th style={{ padding: '0.5rem 0.4rem' }}>Decisión</th>
                    <th style={{ padding: '0.5rem 0.4rem' }}>Revisor</th>
                    <th style={{ padding: '0.5rem 0.4rem' }}></th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map(f => {
                    const canUndo = hoursSince(f.reviewed_at) <= UNDO_WINDOW_HOURS;
                    const isBusy = busy.has(f.id);
                    return (
                      <tr key={f.id} style={{ borderBottom: '1px solid var(--border)' }}>
                        <td style={{ padding: '0.5rem 0.4rem', whiteSpace: 'nowrap' }}>
                          {fmtDateTime(f.reviewed_at)}
                        </td>
                        <td style={{ padding: '0.5rem 0.4rem' }}>
                          <div style={{ fontWeight: 600 }}>{f.company_name}</div>
                          <div className="muted" style={{ fontSize: '0.8rem' }}>
                            {(f.fingerprints || []).slice(0, 3).join(', ')}
                            {f.fingerprints.length > 3 ? '…' : ''}
                          </div>
                        </td>
                        <td style={{ padding: '0.5rem 0.4rem' }}>{f.risk_score}</td>
                        <td style={{ padding: '0.5rem 0.4rem', whiteSpace: 'nowrap' }}>
                          {fmtCurrency(f.chargeback_exposure_usd, f.chargeback_exposure_currency)}
                        </td>
                        <td style={{ padding: '0.5rem 0.4rem' }}>
                          <span
                            className="tag"
                            style={{
                              background: f.review_status === 'accepted'
                                ? 'rgba(0, 201, 167, 0.15)'
                                : 'rgba(255, 107, 53, 0.15)',
                              color: f.review_status === 'accepted'
                                ? 'var(--cubo-teal)'
                                : 'var(--cubo-orange)',
                            }}
                          >
                            {f.review_status === 'accepted' ? 'Aceptado' : 'Descartado'}
                          </span>
                        </td>
                        <td style={{ padding: '0.5rem 0.4rem' }}>
                          {f.reviewed_by_email || '—'}
                        </td>
                        <td style={{ padding: '0.5rem 0.4rem', textAlign: 'right' }}>
                          {canUndo ? (
                            <button
                              className="signout"
                              disabled={isBusy}
                              onClick={() => undo(f.id)}
                              title={`Deshacer (dentro de ${UNDO_WINDOW_HOURS}h)`}
                            >
                              Deshacer
                            </button>
                          ) : (
                            <span className="muted" style={{ fontSize: '0.8rem' }}>
                              bloqueado
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
