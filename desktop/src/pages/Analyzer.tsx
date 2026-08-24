import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { open as openDialog } from '@tauri-apps/plugin-dialog';
import type { Session } from '@supabase/supabase-js';

import { loadWatchlistWithCache } from '../lib/watchlist';
import { syncOrQueue, type SyncResult } from '../lib/sync';

type Findings = {
  summary?: {
    date_range?: { start: string | null; end: string | null };
    total_rows?: number;
    unique_transactions?: number;
    total_critical_findings?: number;
    total_monitor_findings?: number;
    total_suspicious_rejected_merchants?: number;
    estimated_chargeback_exposure?: number;
    currency?: string;
  };
  critical_findings?: Array<{
    company_name: string;
    risk_score: number;
    fingerprints: string[];
    description_es?: string;
  }>;
  monitor_findings?: Array<{
    company_name: string;
    risk_score: number;
    fingerprints: string[];
  }>;
  // Merchants with no successful transactions that look like card testing.
  // Optional for backward compatibility with reports generated before this
  // section shipped.
  suspicious_rejected_merchants?: Array<{
    company_name: string;
    risk_score: number;
    confidence: 'Critical' | 'Monitor';
    fingerprints: string[];
    description_es?: string;
    recommended_action_es?: string;
    currency?: string;
    metrics?: {
      attempts: number;
      distinct_cards: number;
      distinct_bins: number;
      distinct_ips: number;
      rejected_amount: number;
    };
  }>;
  error?: string;
};

type Status = 'idle' | 'analyzing' | 'syncing' | 'done' | 'error';

// Tracks what happened to the sync step so the report view can render
// either "Guardado en Supabase" or "En cola para sincronizar".
type SyncStatus =
  | { kind: 'synced'; result: SyncResult }
  | { kind: 'queued'; queueId: string };

const fmt = (n: number | undefined) =>
  n === undefined ? '—' : n.toLocaleString('en-US');

const fmtCurrency = (n: number | undefined, code = 'USD') => {
  if (n === undefined) return '—';
  try {
    return n.toLocaleString('en-US', { style: 'currency', currency: code });
  } catch {
    return `${code} ${n.toLocaleString('en-US')}`;
  }
};

const fmtRelativeAge = (iso: string) => {
  const ageMin = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 60000));
  if (ageMin < 1)  return 'hace menos de un minuto';
  if (ageMin < 60) return `hace ${ageMin} minuto${ageMin === 1 ? '' : 's'}`;
  const h = Math.floor(ageMin / 60);
  if (h < 24)      return `hace ${h} hora${h === 1 ? '' : 's'}`;
  const d = Math.floor(h / 24);
  return `hace ${d} día${d === 1 ? '' : 's'}`;
};

export function Analyzer({
  session, online, onRunCompleted,
}: {
  session: Session;
  online: boolean;
  onRunCompleted: () => void;
}) {
  const [status, setStatus] = useState<Status>('idle');
  const [csvPath, setCsvPath] = useState<string | null>(null);
  const [findings, setFindings] = useState<Findings | null>(null);
  const [errorMsg, setErrorMsg] = useState('');
  const [dragOver, setDragOver] = useState(false);
  const [sync, setSync] = useState<SyncStatus | null>(null);
  const [watchlistStale, setWatchlistStale] = useState<string | null>(null); // cachedAt or null

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    getCurrentWindow().onDragDropEvent((event) => {
      if (event.payload.type === 'over') {
        setDragOver(true);
      } else if (event.payload.type === 'leave') {
        setDragOver(false);
      } else if (event.payload.type === 'drop') {
        setDragOver(false);
        const path = event.payload.paths?.[0];
        if (path && path.toLowerCase().endsWith('.csv')) {
          runAnalysis(path);
        } else if (path) {
          setErrorMsg('Solo se aceptan archivos .csv.');
          setStatus('error');
        }
      }
    }).then((fn) => { unlisten = fn; });
    return () => { unlisten?.(); };
  }, []);

  async function pickFile() {
    const selected = await openDialog({
      multiple: false,
      filters: [{ name: 'CSV', extensions: ['csv'] }],
    });
    if (typeof selected === 'string') runAnalysis(selected);
  }

  async function runAnalysis(path: string) {
    setCsvPath(path);
    setFindings(null);
    setErrorMsg('');
    setSync(null);
    setWatchlistStale(null);
    setStatus('analyzing');
    try {
      // Tries Supabase first, falls back to the local cache if the network
      // call fails. cachedAt is set only when we fell back.
      const wl = await loadWatchlistWithCache();
      if (wl.fromCache && wl.cachedAt) {
        setWatchlistStale(wl.cachedAt);
      }

      const result = await invoke<Findings>('analyze_csv', {
        csvPath: path,
        watchlistJson: JSON.stringify(wl.watchlist),
      });

      if (result?.error) {
        setErrorMsg(result.error);
        setStatus('error');
        return;
      }
      setFindings(result);

      setStatus('syncing');
      const csvFilename = path.split(/[/\\]/).pop() || 'upload.csv';
      const out = await syncOrQueue(
        session.user.id, session.user.email!, csvFilename, result,
      );
      if (out.status === 'synced') {
        setSync({ kind: 'synced', result: out.result });
      } else {
        setSync({ kind: 'queued', queueId: out.queueId });
      }

      setStatus('done');
      onRunCompleted();
    } catch (e) {
      setErrorMsg(e instanceof Error ? e.message : String(e));
      setStatus('error');
    }
  }

  function reset() {
    setStatus('idle');
    setCsvPath(null);
    setFindings(null);
    setErrorMsg('');
    setSync(null);
    setWatchlistStale(null);
  }

  return (
    <main className="main">
      {status === 'idle' && (
        <>
          {!online && (
            <div className="info-banner">
              Estás sin conexión. Los análisis seguirán funcionando si tienes
              una watchlist en caché. Los resultados quedan en cola y se
              sincronizan cuando vuelvas a estar en línea.
            </div>
          )}
          <div
            className={`dropzone ${dragOver ? 'active' : ''}`}
            onClick={pickFile}
          >
            <img
              src="https://buznvtdzsigrtruighzx.supabase.co/storage/v1/object/public/Assets/Cubo%20Holmes.png"
              alt="Cubo Holmes"
              className="mascot"
            />
            <h2>Arrastra un CSV aquí</h2>
            <p>o haz clic para examinar archivos</p>
            <p className="hint">Sin límite de tamaño · análisis local · sincroniza con Supabase</p>
          </div>
        </>
      )}

      {(status === 'analyzing' || status === 'syncing') && (
        <div className="card centered">
          <img
            src="https://buznvtdzsigrtruighzx.supabase.co/storage/v1/object/public/Assets/Cubo%20Holmes.png"
            alt="Cubo Holmes"
            className="mascot pulse"
          />
          <h2>{status === 'analyzing' ? 'Analizando…' : 'Guardando en Supabase…'}</h2>
          <p className="muted">{csvPath}</p>
          <p className="hint">
            {status === 'analyzing'
              ? 'Esto puede tomar desde segundos hasta varios minutos según el tamaño del CSV. No cierres la ventana.'
              : 'Subiendo el run y los hallazgos…'}
          </p>
        </div>
      )}

      {status === 'error' && (
        <div className="card">
          <h2 className="error-title">No se pudo procesar el archivo</h2>
          <p className="muted">{csvPath}</p>
          <pre className="error-detail">{errorMsg}</pre>
          <button className="btn" onClick={reset}>Volver a empezar</button>
        </div>
      )}

      {status === 'done' && findings && (
        <ReportView
          findings={findings}
          csvPath={csvPath}
          sync={sync}
          watchlistStale={watchlistStale}
          onReset={reset}
        />
      )}
    </main>
  );
}

function ReportView({
  findings, csvPath, sync, watchlistStale, onReset,
}: {
  findings: Findings;
  csvPath: string | null;
  sync: SyncStatus | null;
  watchlistStale: string | null;
  onReset: () => void;
}) {
  const s = findings.summary || {};
  const currency = s.currency || 'USD';

  return (
    <div className="report">
      <div className="report-header">
        <div>
          <h2>Reporte</h2>
          <p className="muted small">{csvPath}</p>
          {sync?.kind === 'synced' && (
            <p className="sync-confirm">
              Guardado en Supabase · run <code>{sync.result.run_id.slice(0, 8)}…</code>
              {sync.result.critical_inserted > 0 && (
                <> · {sync.result.critical_inserted} crítico(s) pendientes de revisión</>
              )}
              {sync.result.zero_settlement_inserted > 0 && (
                <> · {sync.result.zero_settlement_inserted} sin liquidación</>
              )}
            </p>
          )}
          {sync?.kind === 'queued' && (
            <p className="sync-queued">
              Sin conexión — el run está en cola local y se sincronizará
              automáticamente cuando vuelvas a estar en línea.
            </p>
          )}
        </div>
        <button className="btn ghost" onClick={onReset}>Analizar otro archivo</button>
      </div>

      {watchlistStale && (
        <div className="info-banner small">
          ⚠️ La watchlist usada es la caché local ({fmtRelativeAge(watchlistStale)}).
          Si se actualizó recientemente en Supabase, vuelve a analizar cuando estés en línea para usar la versión más reciente.
        </div>
      )}

      <div className="kpi-grid">
        <Kpi label="Transacciones únicas"   value={fmt(s.unique_transactions)} />
        <Kpi label="Hallazgos críticos"     value={fmt(s.total_critical_findings)} accent="critical" />
        <Kpi label="Hallazgos a monitorear" value={fmt(s.total_monitor_findings)}  accent="monitor" />
        <Kpi label="Sin liquidación"        value={fmt(s.total_suspicious_rejected_merchants)} accent="monitor" />
        <Kpi label="Exposición a chargebacks"
             value={fmtCurrency(s.estimated_chargeback_exposure, currency)} />
      </div>

      {findings.critical_findings && findings.critical_findings.length > 0 && (
        <section>
          <h3>Críticos ({findings.critical_findings.length})</h3>
          <ul className="findings">
            {findings.critical_findings.map((f, i) => (
              <li key={i} className="finding critical">
                <div className="finding-head">
                  <strong>{f.company_name}</strong>
                  <span className="score">Riesgo {f.risk_score}</span>
                </div>
                {f.description_es && <p>{f.description_es}</p>}
                <div className="tags">
                  {f.fingerprints.map((fp) => (
                    <span className="tag" key={fp}>{fp}</span>
                  ))}
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}

      {findings.monitor_findings && findings.monitor_findings.length > 0 && (
        <section>
          <h3>A monitorear ({findings.monitor_findings.length})</h3>
          <ul className="findings">
            {findings.monitor_findings.map((f, i) => (
              <li key={i} className="finding monitor">
                <div className="finding-head">
                  <strong>{f.company_name}</strong>
                  <span className="score">Riesgo {f.risk_score}</span>
                </div>
                <div className="tags">
                  {f.fingerprints.map((fp) => (
                    <span className="tag" key={fp}>{fp}</span>
                  ))}
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}

      {findings.suspicious_rejected_merchants &&
        findings.suspicious_rejected_merchants.length > 0 && (
        <section>
          <h3>
            Comercios sin transacciones exitosas (
            {findings.suspicious_rejected_merchants.length})
          </h3>
          <p className="phase-note">
            Comercios que no liquidan ningún cargo pero muestran patrones de card
            testing en sus rechazos. No generan exposición a chargebacks; indican
            posible abuso de la cuenta para probar tarjetas robadas. Los que
            aparecen como Critical quedan pendientes de revisión: al aceptarlos
            se agregan el comercio y las tarjetas probadas a la Watchlist.
          </p>
          <ul className="findings">
            {findings.suspicious_rejected_merchants.map((f, i) => (
              <li
                key={i}
                className={`finding ${f.confidence === 'Critical' ? 'critical' : 'monitor'}`}
              >
                <div className="finding-head">
                  <strong>{f.company_name}</strong>
                  <span className="score">Riesgo {f.risk_score}</span>
                </div>
                {f.description_es && <p>{f.description_es}</p>}
                {f.metrics && (
                  <p className="phase-note" style={{ marginTop: 0 }}>
                    {f.metrics.attempts} intentos · {f.metrics.distinct_cards} tarjetas
                    {' · '}{f.metrics.distinct_bins} BINs · {f.metrics.distinct_ips} IP
                    {' · '}monto rechazado{' '}
                    {fmtCurrency(f.metrics.rejected_amount, f.currency || currency)}
                  </p>
                )}
                <div className="tags">
                  {f.fingerprints.map((fp) => (
                    <span className="tag" key={fp}>{fp}</span>
                  ))}
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}

      <p className="phase-note">
        Los hallazgos críticos quedan en estado <strong>pendiente</strong> de revisión.
        Abre la pestaña <strong>Pendientes</strong> arriba para aceptarlos o descartarlos.
      </p>
    </div>
  );
}

function Kpi({ label, value, accent }: { label: string; value: string; accent?: 'critical' | 'monitor' }) {
  return (
    <div className={`kpi ${accent || ''}`}>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value">{value}</div>
    </div>
  );
}
