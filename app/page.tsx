'use client';

import { useState, useRef, useEffect, DragEvent, KeyboardEvent } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { createClient } from '@/lib/supabase/client';

type EvidenceRow = {
  transaction_id: string;
  amount: number | null;
  status: string;
  rejection_reason: string | null;
  timestamp: string;
  card_bin: string | null;
  card_last_digits: string | null;
  card_holder: string | null;
};

type CriticalFinding = {
  type: string;
  company_name: string;
  company_id: string;
  risk_score: number;
  confidence: 'Critical';
  fingerprints: string[];
  description_es: string;
  evidence: EvidenceRow[];
  recommended_action_es: string;
  action_code: string;
  estimated_chargeback_exposure: number;
  total_transactions: number;
  rejected_count: number;
  succeeded_count: number;
  // Attached server-side after the findings row is inserted, so the report
  // screen can call /api/findings without re-fetching.
  finding_id?: string;
};

type MonitorFinding = {
  type: string;
  company_name: string;
  company_id: string;
  risk_score: number;
  confidence: 'Monitor';
  fingerprints: string[];
  description_es: string;
  action_code: string;
  evidence_count: number;
};

type Findings = {
  run_id?: string;
  summary: {
    date_range: { start: string | null; end: string | null };
    total_rows: number;
    unique_transactions: number;
    total_critical_findings: number;
    total_monitor_findings: number;
    total_duplicate_findings: number;
    total_watchlist_hits: number;
    estimated_chargeback_exposure: number;
    currency?: string;  // ISO 4217 (USD, GTQ, ...). Optional for backward
                        // compatibility with reports generated before the
                        // multi-currency change shipped.
    total_high_risk_score_transactions: number;
    total_foreign_card_velocity_merchants: number;
  };
  critical_findings: CriticalFinding[];
  monitor_findings: MonitorFinding[];
};

const MAX_FILE_BYTES = 4 * 1024 * 1024; // 4 MB — keep under Vercel's 4.5 MB request-body limit.

// Force en-US formatting on numeric / monetary KPIs. Without the locale arg,
// toLocaleString() reads the browser locale, which would render "1.234,56"
// for users with a Spanish-locale browser even though the source data uses
// US-style separators across all currencies we support today (USD, GTQ).
// Internal reports go to a US-style audit pipeline, so we pin en-US.
const fmtNumber = (n: number) => n.toLocaleString('en-US');
const fmtCurrency = (n: number, code: string = 'USD') => {
  try {
    return n.toLocaleString('en-US', { style: 'currency', currency: code });
  } catch {
    // Unknown ISO code (e.g., a future country we haven't mapped server-side
    // yet). Don't crash the page — fall back to plain number + the raw code.
    return `${code} ${n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  }
};

export default function HomePage() {
  const router = useRouter();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [dragActive, setDragActive] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState('');
  const [results, setResults] = useState<Findings | null>(null);
  // Count of Critical findings awaiting team review. Fetched on mount and
  // again after each analysis so the banner always reflects current state.
  const [pendingCount, setPendingCount] = useState<number | null>(null);
  // Per-finding review state for the current report. Only populated as the
  // user clicks Aceptar/Descartar from this screen; rows that the user
  // leaves alone stay pending in the DB and remain available in /pendientes.
  const [reviewedById, setReviewedById] = useState<Record<string, 'accepted' | 'rejected'>>({});
  // Set of finding ids that have an in-flight review call.
  const [reviewingIds, setReviewingIds] = useState<Set<string>>(new Set());

  async function refreshPendingCount() {
    try {
      const supabase = createClient();
      const { data: { session } } = await supabase.auth.getSession();
      if (!session) return;
      const res = await fetch('/api/findings?status=pending', {
        headers: { Authorization: `Bearer ${session.access_token}` },
      });
      if (!res.ok) return;
      const json = await res.json();
      setPendingCount((json.findings || []).length);
    } catch {
      // Best-effort — banner just stays hidden on failure.
    }
  }

  useEffect(() => { refreshPendingCount(); }, []);

  // Bulk-safe Aceptar/Descartar from the report screen. Skips any ids that
  // were already reviewed in this session (idempotent for double-clicks).
  async function reviewFindings(action: 'accept' | 'reject', findingIds: string[]) {
    const ids = findingIds.filter(id => id && !reviewedById[id]);
    if (ids.length === 0) return;

    const supabase = createClient();
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) {
      router.push('/login');
      return;
    }
    setReviewingIds(prev => {
      const next = new Set(prev);
      ids.forEach(id => next.add(id));
      return next;
    });
    try {
      const res = await fetch('/api/findings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.access_token}`,
        },
        body: JSON.stringify({ action, finding_ids: ids }),
      });
      const json = await res.json();
      if (!res.ok) {
        setError(json.error || `El servidor respondió con ${res.status}`);
        return;
      }
      // Mark per-id outcome based on the RPC's per-row result so a partial
      // failure leaves the failed rows still actionable.
      const settled: Record<string, 'accepted' | 'rejected'> = {};
      const failed: string[] = [];
      for (const r of (json.results || []) as Array<{ id: string; ok: boolean; error?: string }>) {
        if (r.ok) {
          settled[r.id] = action === 'accept' ? 'accepted' : 'rejected';
        } else {
          failed.push(r.error || r.id);
        }
      }
      setReviewedById(prev => ({ ...prev, ...settled }));
      if (failed.length > 0) {
        setError(`Algunos hallazgos no se pudieron procesar: ${failed[0]}`);
      }
      refreshPendingCount();
    } catch (e: any) {
      setError(e?.message || 'Acción fallida');
    } finally {
      setReviewingIds(prev => {
        const next = new Set(prev);
        ids.forEach(id => next.delete(id));
        return next;
      });
    }
  }

  async function handleFile(file: File) {
    if (uploading) return;  // guard against double-click / double-drop racing
    setError('');
    setResults(null);
    setReviewedById({});
    setReviewingIds(new Set());

    if (!file.name.toLowerCase().endsWith('.csv')) {
      setError('Por favor sube un archivo .csv.');
      return;
    }
    if (file.size === 0) {
      setError('El archivo está vacío.');
      return;
    }
    if (file.size > MAX_FILE_BYTES) {
      setError(
        `El archivo es de ${(file.size / 1024 / 1024).toFixed(1)} MB — supera el límite de 4 MB. ` +
          `Para reportes mensuales, ejecuta analyze.py localmente.`,
      );
      return;
    }

    setUploading(true);
    try {
      const supabase = createClient();

      // Use the cached session first. The Supabase browser client auto-
      // refreshes in the background while the tab is open, so the cached
      // token is usually fresh. If the server still returns 401 (e.g. tab
      // was backgrounded long enough to expire mid-flight), we refresh and
      // retry exactly once before giving up — same end-user effect as the
      // old eager-refresh, without the extra round-trip on every upload.
      const form = new FormData();
      form.append('file', file);

      async function postWithToken(token: string) {
        return fetch('/api/analyze', {
          method: 'POST',
          body: form,
          headers: { Authorization: `Bearer ${token}` },
        });
      }

      const { data: { session } } = await supabase.auth.getSession();
      if (!session) {
        router.push('/login');
        return;
      }

      let res = await postWithToken(session.access_token);
      if (res.status === 401) {
        const { data: { session: fresh }, error: refreshErr } =
          await supabase.auth.refreshSession();
        if (refreshErr || !fresh) {
          router.push('/login');
          return;
        }
        res = await postWithToken(fresh.access_token);
      }

      const json = await res.json();
      if (!res.ok) {
        setError(json.error || `El servidor respondió con ${res.status}`);
        return;
      }
      setResults(json);
      // Findings are now pending review, so the banner count went up.
      refreshPendingCount();
    } catch (e: any) {
      setError(e?.message || 'Falló la carga');
    } finally {
      setUploading(false);
    }
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    setDragActive(false);
    if (uploading) return;
    const file = e.dataTransfer.files?.[0];
    if (file) handleFile(file);
  }

  async function signOut() {
    const supabase = createClient();
    await supabase.auth.signOut();
    router.push('/login');
  }

  function downloadJSON() {
    if (!results) return;
    const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `findings_${results.summary.date_range.start || 'report'}.json`;
    a.click();
    // Defer revoke so the browser has actually started the download —
    // some browsers haven't begun fetching the blob URL synchronously
    // after .click() returns.
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }

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
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <Link href="/pendientes" className="signout">
            Pendientes{pendingCount && pendingCount > 0 ? ` (${pendingCount})` : ''}
          </Link>
          <Link href="/historial" className="signout">Historial</Link>
          <button
            className="signout"
            onClick={signOut}
            disabled={uploading}
            aria-label={uploading ? 'Cerrar sesión (deshabilitado durante la carga)' : 'Cerrar sesión'}
          >
            Cerrar sesión
          </button>
        </div>
      </header>

      <div className="container">
        {!results && pendingCount !== null && pendingCount > 0 && (
          <Link
            href="/pendientes"
            className="card"
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              textDecoration: 'none',
              color: 'var(--text)',
              borderColor: 'var(--cubo-orange)',
              borderLeft: '4px solid var(--cubo-orange)',
            }}
          >
            <span>
              <strong>{pendingCount}</strong>{' '}
              hallazgo{pendingCount === 1 ? '' : 's'} Critical pendiente{pendingCount === 1 ? '' : 's'} de revisión.
            </span>
            <span className="muted">Revisar →</span>
          </Link>
        )}
        {!results && (
          <div className="card">
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '1.5rem',
                marginBottom: '1.5rem',
                flexWrap: 'wrap',
              }}
            >
              <div style={{ flex: '1 1 280px' }}>
                <h2 style={{ marginTop: 0, marginBottom: '0.4rem' }}>
                  Análisis diario de transacciones
                </h2>
                <p className="muted" style={{ margin: 0 }}>
                  Carga un CSV exportado de Cubo. El archivo se procesa en memoria y
                  se descarta inmediatamente — solo se persiste la Watchlist.
                </p>
              </div>
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src="https://buznvtdzsigrtruighzx.supabase.co/storage/v1/object/public/Assets/Cubo%20Holmes.png"
                alt="Mascota Cubo Holmes"
                style={{ height: 140, width: 'auto', flex: '0 0 auto' }}
              />
            </div>

            <div
              className={`dropzone ${dragActive ? 'active' : ''}`}
              role="button"
              tabIndex={uploading ? -1 : 0}
              aria-label="Cargar archivo CSV"
              aria-disabled={uploading}
              onDragOver={(e) => {
                e.preventDefault();
                if (!uploading) setDragActive(true);
              }}
              onDragLeave={() => setDragActive(false)}
              onDrop={onDrop}
              onClick={() => !uploading && fileInputRef.current?.click()}
              onKeyDown={(e: KeyboardEvent<HTMLDivElement>) => {
                if (uploading) return;
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  fileInputRef.current?.click();
                }
              }}
              style={{ opacity: uploading ? 0.5 : 1 }}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".csv"
                style={{ display: 'none' }}
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) handleFile(f);
                }}
              />
              {uploading ? (
                <p>Analizando… esto normalmente toma unos segundos.</p>
              ) : (
                <>
                  <p style={{ fontSize: '1.1rem', marginBottom: '0.4rem' }}>
                    Suelta el CSV aquí, o haz clic para seleccionar
                  </p>
                  <p className="muted" style={{ margin: 0 }}>
                    Tamaño máximo: 4 MB (hasta 3 días de transacciones).
                  </p>
                </>
              )}
            </div>

            {error && <div className="error" style={{ marginTop: '1rem' }}>{error}</div>}
          </div>
        )}

        {results && (
          <>
            <div className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h2 style={{ margin: 0 }}>
                  Reporte:{' '}
                  {results.summary.date_range.start === results.summary.date_range.end
                    ? results.summary.date_range.start
                    : `${results.summary.date_range.start} → ${results.summary.date_range.end}`}
                </h2>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <button className="signout" onClick={downloadJSON}>
                    Descargar JSON
                  </button>
                  <button className="signout" onClick={() => setResults(null)}>
                    Nuevo análisis
                  </button>
                </div>
              </div>

              <div className="kpi-grid" style={{ marginTop: '1rem' }}>
                <Kpi label="Transacciones" value={fmtNumber(results.summary.unique_transactions)} />
                <Kpi label="Crítico" value={fmtNumber(results.summary.total_critical_findings)} />
                <Kpi label="Monitorear" value={fmtNumber(results.summary.total_monitor_findings)} />
                <Kpi label="Hits en Watchlist" value={fmtNumber(results.summary.total_watchlist_hits)} />
                <Kpi
                  label={`Exposición CB (${results.summary.currency || 'USD'})`}
                  value={fmtCurrency(
                    results.summary.estimated_chargeback_exposure,
                    results.summary.currency,
                  )}
                />
                <Kpi label="Tx alto riesgo" value={fmtNumber(results.summary.total_high_risk_score_transactions)} />
              </div>
            </div>

            {results.critical_findings.length > 0 && (
              <div className="card">
                <div style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'flex-start',
                  flexWrap: 'wrap',
                  gap: '0.5rem',
                }}>
                  <h3 style={{ marginTop: 0 }}>Hallazgos Críticos</h3>
                  {(() => {
                    // Bulk controls — only enabled when at least one finding
                    // in the report is still unreviewed and has a DB id.
                    const actionable = results.critical_findings
                      .map(f => f.finding_id)
                      .filter((id): id is string => !!id && !reviewedById[id]);
                    const anyInflight = actionable.some(id => reviewingIds.has(id));
                    if (actionable.length === 0) return null;
                    return (
                      <div style={{ display: 'flex', gap: '0.4rem' }}>
                        <button
                          className="signout"
                          disabled={anyInflight}
                          onClick={() => reviewFindings('accept', actionable)}
                        >
                          Aceptar todos
                        </button>
                        <button
                          className="signout"
                          disabled={anyInflight}
                          onClick={() => reviewFindings('reject', actionable)}
                        >
                          Descartar todos
                        </button>
                      </div>
                    );
                  })()}
                </div>
                <p className="muted" style={{ marginTop: 0, fontSize: '0.9rem' }}>
                  La Watchlist no se actualiza hasta que un miembro del equipo
                  acepte cada hallazgo. Puedes revisarlos aquí o más tarde
                  desde <Link href="/pendientes">Revisiones pendientes</Link>.
                </p>
                {results.critical_findings.map((f, i) => {
                  const id = f.finding_id;
                  const reviewedAs = id ? reviewedById[id] : undefined;
                  const inflight = id ? reviewingIds.has(id) : false;
                  return (
                    <FindingCard
                      key={id || i}
                      finding={f}
                      tier="critical"
                      reviewState={reviewedAs}
                      inflight={inflight}
                      onAccept={id && !reviewedAs ? () => reviewFindings('accept', [id]) : undefined}
                      onReject={id && !reviewedAs ? () => reviewFindings('reject', [id]) : undefined}
                    />
                  );
                })}
              </div>
            )}

            {results.monitor_findings.length > 0 && (
              <div className="card">
                <h3 style={{ marginTop: 0 }}>Hallazgos a Monitorear</h3>
                {results.monitor_findings.map((f, i) => (
                  <FindingCard key={i} finding={f} tier="monitor" />
                ))}
              </div>
            )}

            {results.critical_findings.length === 0 && results.monitor_findings.length === 0 && (
              <div className="card">
                <p className="success" style={{ margin: 0 }}>
                  No se detectó actividad sospechosa en este CSV.
                </p>
              </div>
            )}
          </>
        )}
      </div>
    </>
  );
}

function Kpi({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="kpi">
      <div className="kpi-label">{label}</div>
      <div className="kpi-value">{value}</div>
    </div>
  );
}

function FindingCard({
  finding,
  tier,
  reviewState,
  inflight,
  onAccept,
  onReject,
}: {
  finding: CriticalFinding | MonitorFinding;
  tier: 'critical' | 'monitor';
  reviewState?: 'accepted' | 'rejected';
  inflight?: boolean;
  onAccept?: () => void;
  onReject?: () => void;
}) {
  // Only critical findings carry a recommended_action_es. Use a type guard
  // so TypeScript narrows the optional access to the right branch.
  const action =
    'recommended_action_es' in finding ? finding.recommended_action_es : undefined;

  // Visual treatment for the post-review badge — green for Aceptado, orange
  // for Descartado, matching the chip style used on /historial.
  const badge = reviewState === 'accepted'
    ? { text: 'Aceptado ✓', bg: 'rgba(0, 201, 167, 0.15)', fg: 'var(--cubo-teal)' }
    : reviewState === 'rejected'
      ? { text: 'Descartado',   bg: 'rgba(255, 107, 53, 0.15)', fg: 'var(--cubo-orange)' }
      : null;

  return (
    <div
      className={`finding ${tier === 'monitor' ? 'monitor' : ''}`}
      style={reviewState ? { opacity: 0.7 } : undefined}
    >
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        flexWrap: 'wrap',
        gap: '0.5rem',
      }}>
        <div style={{ flex: '1 1 auto' }}>
          <strong>{finding.company_name}</strong>
          <span className="muted" style={{ marginLeft: '0.75rem' }}>
            Riesgo: {finding.risk_score}
          </span>
        </div>
        {/* Review controls only render for Critical (onAccept/onReject are
            only passed in for that tier). Monitor cards show no buttons. */}
        {(onAccept || onReject || badge) && (
          <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
            {badge && (
              <span
                className="tag"
                style={{ background: badge.bg, color: badge.fg }}
              >
                {badge.text}
              </span>
            )}
            {!badge && onAccept && (
              <button
                className="signout"
                disabled={inflight}
                onClick={onAccept}
              >
                Aceptar
              </button>
            )}
            {!badge && onReject && (
              <button
                className="signout"
                disabled={inflight}
                onClick={onReject}
              >
                Descartar
              </button>
            )}
          </div>
        )}
      </div>
      <p style={{ margin: '0.4rem 0', fontSize: '0.95rem' }}>{finding.description_es}</p>
      <div>
        {(finding.fingerprints || []).map((fp) => (
          <span className="tag" key={fp}>
            {fp}
          </span>
        ))}
      </div>
      {action && (
        <p className="muted" style={{ marginTop: '0.5rem', marginBottom: 0 }}>
          <strong>Acción:</strong> {action}
        </p>
      )}
    </div>
  );
}
