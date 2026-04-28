'use client';

import { useState, useRef, DragEvent } from 'react';
import { useRouter } from 'next/navigation';
import { createClient } from '@/lib/supabase/client';

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
    total_high_risk_score_transactions: number;
    total_foreign_card_velocity_merchants: number;
  };
  critical_findings: Array<any>;
  monitor_findings: Array<any>;
};

const MAX_FILE_BYTES = 4 * 1024 * 1024; // 4 MB — keep under Vercel's 4.5 MB request-body limit.

export default function HomePage() {
  const router = useRouter();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [dragActive, setDragActive] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState('');
  const [results, setResults] = useState<Findings | null>(null);

  async function handleFile(file: File) {
    setError('');
    setResults(null);

    if (!file.name.toLowerCase().endsWith('.csv')) {
      setError('Please upload a .csv file.');
      return;
    }
    if (file.size > MAX_FILE_BYTES) {
      setError(
        `File is ${(file.size / 1024 / 1024).toFixed(1)} MB — over the 4 MB limit. ` +
          `For monthly reports, run analyze.py locally instead.`,
      );
      return;
    }

    setUploading(true);
    try {
      const supabase = createClient();
      const { data: { session } } = await supabase.auth.getSession();
      if (!session) {
        router.push('/login');
        return;
      }

      const form = new FormData();
      form.append('file', file);

      const res = await fetch('/api/analyze', {
        method: 'POST',
        body: form,
        headers: { Authorization: `Bearer ${session.access_token}` },
      });

      const json = await res.json();
      if (!res.ok) {
        setError(json.error || `Server returned ${res.status}`);
        return;
      }
      setResults(json);
    } catch (e: any) {
      setError(e?.message || 'Upload failed');
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
    URL.revokeObjectURL(url);
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
        <button className="signout" onClick={signOut}>
          Sign out
        </button>
      </header>

      <div className="container">
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
                  Daily transaction analysis
                </h2>
                <p className="muted" style={{ margin: 0 }}>
                  Drop a CSV exported from Cubo. The file is processed in memory and
                  discarded immediately — only the watchlist is persisted.
                </p>
              </div>
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src="https://buznvtdzsigrtruighzx.supabase.co/storage/v1/object/public/Assets/Cubo%20Holmes.png"
                alt="Cubo Holmes mascot"
                style={{ height: 140, width: 'auto', flex: '0 0 auto' }}
              />
            </div>

            <div
              className={`dropzone ${dragActive ? 'active' : ''}`}
              onDragOver={(e) => {
                e.preventDefault();
                if (!uploading) setDragActive(true);
              }}
              onDragLeave={() => setDragActive(false)}
              onDrop={onDrop}
              onClick={() => !uploading && fileInputRef.current?.click()}
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
                <p>Analyzing… this usually takes a few seconds.</p>
              ) : (
                <>
                  <p style={{ fontSize: '1.1rem', marginBottom: '0.4rem' }}>
                    Drop CSV here, or click to choose
                  </p>
                  <p className="muted" style={{ margin: 0 }}>
                    Maximum file size: 4 MB (one day of transactions).
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
                  Report:{' '}
                  {results.summary.date_range.start === results.summary.date_range.end
                    ? results.summary.date_range.start
                    : `${results.summary.date_range.start} → ${results.summary.date_range.end}`}
                </h2>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <button className="signout" onClick={downloadJSON}>
                    Download JSON
                  </button>
                  <button className="signout" onClick={() => setResults(null)}>
                    New analysis
                  </button>
                </div>
              </div>

              <div className="kpi-grid" style={{ marginTop: '1rem' }}>
                <Kpi label="Transactions" value={results.summary.unique_transactions.toLocaleString()} />
                <Kpi label="Critical" value={results.summary.total_critical_findings} />
                <Kpi label="Monitor" value={results.summary.total_monitor_findings} />
                <Kpi label="Watchlist hits" value={results.summary.total_watchlist_hits} />
                <Kpi
                  label="CB exposure"
                  value={`$${results.summary.estimated_chargeback_exposure.toLocaleString()}`}
                />
                <Kpi label="High-risk tx" value={results.summary.total_high_risk_score_transactions} />
              </div>
            </div>

            {results.critical_findings.length > 0 && (
              <div className="card">
                <h3 style={{ marginTop: 0 }}>Critical findings</h3>
                {results.critical_findings.map((f, i) => (
                  <FindingCard key={i} finding={f} tier="critical" />
                ))}
              </div>
            )}

            {results.monitor_findings.length > 0 && (
              <div className="card">
                <h3 style={{ marginTop: 0 }}>Monitor findings</h3>
                {results.monitor_findings.map((f, i) => (
                  <FindingCard key={i} finding={f} tier="monitor" />
                ))}
              </div>
            )}

            {results.critical_findings.length === 0 && results.monitor_findings.length === 0 && (
              <div className="card">
                <p className="success" style={{ margin: 0 }}>
                  No suspicious activity detected in this CSV.
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

function FindingCard({ finding, tier }: { finding: any; tier: 'critical' | 'monitor' }) {
  return (
    <div className={`finding ${tier === 'monitor' ? 'monitor' : ''}`}>
      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
        <strong>{finding.company_name}</strong>
        <span>Risk: {finding.risk_score}</span>
      </div>
      <p style={{ margin: '0.4rem 0', fontSize: '0.95rem' }}>{finding.description_es}</p>
      <div>
        {(finding.fingerprints || []).map((fp: string) => (
          <span className="tag" key={fp}>
            {fp}
          </span>
        ))}
      </div>
      {finding.recommended_action_es && (
        <p className="muted" style={{ marginTop: '0.5rem', marginBottom: 0 }}>
          <strong>Action:</strong> {finding.recommended_action_es}
        </p>
      )}
    </div>
  );
}
