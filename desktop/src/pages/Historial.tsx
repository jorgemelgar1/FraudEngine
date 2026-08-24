import { useCallback, useEffect, useState } from 'react';
import type { Session } from '@supabase/supabase-js';

import { listHistory, reviewFindings, type HistoryFinding } from '../lib/findings';
import { isNetworkError } from '../lib/offline';
import { OfflineState } from '../components/OfflineState';

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
  return (Date.now() - new Date(iso).getTime()) / (1000 * 60 * 60);
}

export function Historial({
  session, online, onChanged,
}: {
  session: Session;
  online: boolean;
  onChanged: () => void;
}) {
  const [findings, setFindings] = useState<HistoryFinding[] | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState<'all' | 'accepted' | 'rejected'>('all');
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
      const rows = await listHistory();
      setFindings(rows);
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

  async function undo(findingId: string) {
    setBusy(prev => {
      const next = new Set(prev);
      next.add(findingId);
      return next;
    });
    try {
      const results = await reviewFindings(
        [findingId], 'undo', session.user.id, session.user.email!,
      );
      const result = results[0];
      if (!result?.ok) {
        setError(result?.error || 'No se pudo deshacer');
        return;
      }
      // The undone finding is now back in pending, so drop it from this view.
      setFindings(prev => (prev || []).filter(f => f.id !== findingId));
      setError('');
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
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

  if (offline) {
    return <OfflineState title="Historial de revisiones" onRetry={load} disabled={!online} />;
  }

  return (
    <main className="main">
      <div className="card">
        <div className="historial-head">
          <h2 style={{ margin: 0 }}>Historial de revisiones</h2>
          <div className="filter-buttons">
            <FilterButton active={filter === 'all'}      onClick={() => setFilter('all')}>Todos</FilterButton>
            <FilterButton active={filter === 'accepted'} onClick={() => setFilter('accepted')}>Aceptados</FilterButton>
            <FilterButton active={filter === 'rejected'} onClick={() => setFilter('rejected')}>Descartados</FilterButton>
          </div>
        </div>
        <p className="muted small">
          Decisiones tomadas por el equipo. Las decisiones pueden deshacerse
          dentro de las primeras {UNDO_WINDOW_HOURS} horas; después quedan
          bloqueadas y solo pueden revertirse re-analizando un CSV.
        </p>
        {error && <div className="error-banner">{error}</div>}
        {findings === null && <p className="muted">Cargando…</p>}
        {findings !== null && visible.length === 0 && (
          <p className="muted">No hay revisiones para mostrar.</p>
        )}
      </div>

      {visible.length > 0 && (
        <div className="card" style={{ overflowX: 'auto' }}>
          <table className="history-table">
            <thead>
              <tr>
                <th>Fecha</th>
                <th>Merchant</th>
                <th>Riesgo</th>
                <th>Exposición</th>
                <th>Decisión</th>
                <th>Revisor</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {visible.map(f => {
                const canUndo = hoursSince(f.reviewed_at) <= UNDO_WINDOW_HOURS;
                const isBusy = busy.has(f.id);
                return (
                  <tr key={f.id}>
                    <td className="nowrap">{fmtDateTime(f.reviewed_at)}</td>
                    <td>
                      <div style={{ fontWeight: 600 }}>
                        {f.company_name}
                        {f.section === 'zero_settlement' && (
                          <span className="tag zero-settlement" style={{ marginLeft: '0.5rem' }}>
                            Sin liquidación
                          </span>
                        )}
                      </div>
                      <div className="muted small">
                        {(f.fingerprints || []).slice(0, 3).join(', ')}
                        {f.fingerprints.length > 3 ? '…' : ''}
                      </div>
                    </td>
                    <td>{f.risk_score}</td>
                    {/* Zero-settlement findings have no exposure by
                        construction — an explicit n/a reads better than the
                        generic dash used for missing data. */}
                    <td className="nowrap">
                      {f.section === 'zero_settlement'
                        ? <span className="muted">n/a</span>
                        : fmtCurrency(f.chargeback_exposure_usd, f.chargeback_exposure_currency)}
                    </td>
                    <td>
                      <span className={`tag decision ${f.review_status}`}>
                        {f.review_status === 'accepted' ? 'Aceptado' : 'Descartado'}
                      </span>
                    </td>
                    <td>{f.reviewed_by_email || '—'}</td>
                    <td style={{ textAlign: 'right' }}>
                      {canUndo ? (
                        <button
                          className="btn ghost small"
                          disabled={isBusy}
                          onClick={() => undo(f.id)}
                          title={`Deshacer (dentro de ${UNDO_WINDOW_HOURS}h)`}
                        >
                          Deshacer
                        </button>
                      ) : (
                        <span className="muted small">bloqueado</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </main>
  );
}

function FilterButton({
  active, onClick, children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      className={`btn ghost small ${active ? 'active' : ''}`}
      onClick={onClick}
    >
      {children}
    </button>
  );
}
