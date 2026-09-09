import { useCallback, useEffect, useState } from 'react';
import type { Session } from '@supabase/supabase-js';

import {
  reviewStats, countryCodeOf, REVIEW_REASONS, REASON_LABELS,
  type ReviewStats, type ReviewReason,
} from '../lib/findings';
import {
  listRuns, listRunFindings, merchantHistory, changeDecision,
  listWatchlistMerchants, listWatchlistCards, listWatchlistIndicators,
  setMerchantRemoved,
  type AnalysisRun, type DecidedFinding,
  type WatchlistMerchant, type WatchlistCard, type WatchlistIndicator,
} from '../lib/history';
import { verdictFor, rankPatterns, describePattern } from '../lib/patterns';
import { isNetworkError } from '../lib/offline';
import { OfflineState } from '../components/OfflineState';

// ── Formatting ───────────────────────────────────────────────────────────────

const fmtCurrency = (n: number | null, code: string | null) => {
  if (n == null) return '—';
  if (!code || code === 'UNKNOWN') {
    return `${n.toLocaleString('en-US', { maximumFractionDigits: 0 })} (sin moneda)`;
  }
  try {
    return n.toLocaleString('en-US', { style: 'currency', currency: code, maximumFractionDigits: 0 });
  } catch {
    return `${code} ${n.toLocaleString('en-US', { maximumFractionDigits: 0 })}`;
  }
};

const fmtNum = (n: number | null | undefined) =>
  n == null ? '—' : n.toLocaleString('en-US');

const fmtDate = (iso: string | null | undefined) => {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString('es', { day: 'numeric', month: 'short' })
    + ', ' + d.toLocaleTimeString('es', { hour: '2-digit', minute: '2-digit' });
};

const fmtDay = (iso: string | null | undefined) => {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? '—' : d.toLocaleDateString('es', { day: 'numeric', month: 'short' });
};

const STATUS = {
  accepted:       { label: 'Fraude confirmado', cls: 'confirmed' },
  rejected:       { label: 'No es fraude',      cls: 'cleared' },
  pending:        { label: 'Pendiente',         cls: 'pending' },
  not_applicable: { label: 'Informativo',       cls: 'na' },
} as Record<string, { label: string; cls: string }>;

// ── Page ─────────────────────────────────────────────────────────────────────

type Tab = 'reportes' | 'watchlist';

export function Historial({
  session, online, onChanged,
}: {
  session: Session;
  online: boolean;
  onChanged: () => void;
}) {
  const [tab, setTab] = useState<Tab>('reportes');
  const [offline, setOffline] = useState(false);

  if (offline) {
    return <OfflineState title="Historial" onRetry={() => setOffline(false)} disabled={!online} />;
  }

  return (
    <main className="main">
      <div className="card">
        <h2 style={{ marginTop: 0 }}>Historial</h2>
        <div className="chip-filters" style={{ marginBottom: 0 }}>
          <button className={`chip-filter ${tab === 'reportes' ? 'on' : ''}`}
                  onClick={() => setTab('reportes')}>Reportes</button>
          <button className={`chip-filter ${tab === 'watchlist' ? 'on' : ''}`}
                  onClick={() => setTab('watchlist')}>Watchlist</button>
        </div>
      </div>

      {tab === 'reportes'
        ? <Reportes session={session} online={online} onChanged={onChanged}
                    onOffline={() => setOffline(true)} />
        : <Watchlist session={session} online={online}
                     onOffline={() => setOffline(true)} />}
    </main>
  );
}

// ── Reports ──────────────────────────────────────────────────────────────────

function Reportes({
  session, online, onChanged, onOffline,
}: {
  session: Session;
  online: boolean;
  onChanged: () => void;
  onOffline: () => void;
}) {
  const [runs, setRuns] = useState<AnalysisRun[] | null>(null);
  const [stats, setStats] = useState<ReviewStats | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [findings, setFindings] = useState<Record<string, DecidedFinding[]>>({});
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    if (!online) { onOffline(); return; }
    try {
      const [r, s] = await Promise.all([
        listRuns(),
        // Optional: before migration 0013 this RPC does not exist, and the
        // reports list is still perfectly useful without it.
        reviewStats().catch(() => null),
      ]);
      setRuns(r);
      setStats(s);
    } catch (e) {
      if (isNetworkError(e)) onOffline();
      else setError(e instanceof Error ? e.message : String(e));
    }
  }, [online, onOffline]);

  useEffect(() => { load(); }, [load]);

  async function toggle(run: AnalysisRun) {
    const next = open === run.id ? null : run.id;
    setOpen(next);
    if (next && !findings[run.id]) {
      try {
        const rows = await listRunFindings(run.id);
        setFindings(p => ({ ...p, [run.id]: rows }));
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    }
  }

  return (
    <>
      {stats && stats.decided > 0 && (
        <div className="card">
          <h3 style={{ marginTop: 0 }}>¿El motor acierta?</h3>
          <p className="muted small">
            Sobre los {stats.decided} hallazgos críticos que alguien ya decidió.
            Los pendientes no cuentan — todavía no son evidencia de nada.
          </p>
          <div className="kpi-grid" style={{ marginBottom: 0 }}>
            <Kpi label="Decididos" value={fmtNum(stats.decided)} />
            <Kpi label="Fraude confirmado" value={fmtNum(stats.confirmed)} tone="critical" />
            <Kpi label="Descartados" value={fmtNum(stats.dismissed)} />
            <Kpi label="Acierto"
                 value={stats.precision == null ? '—' : `${stats.precision}%`} />
          </div>
          {Object.keys(stats.by_reason).length > 0 && (
            <div className="reason-bars">
              {Object.entries(stats.by_reason)
                .sort((a, b) => b[1] - a[1])
                .map(([reason, n]) => (
                  <div className="reason-bar" key={reason}>
                    <span className="reason-name">
                      {REASON_LABELS[reason] || 'Sin motivo'}
                    </span>
                    <span className="reason-track">
                      <span className="reason-fill"
                            style={{ width: `${Math.round(n * 100 / Math.max(1, stats.dismissed))}%` }} />
                    </span>
                    <span className="reason-n">{n}</span>
                  </div>
                ))}
              <p className="muted small" style={{ margin: '.5rem 0 0' }}>
                <strong>Error del detector</strong> es el motivo que importa:
                separa "el motor se equivocó" de "el motor tenía razón y
                estamos bien con este comercio".
              </p>
            </div>
          )}
        </div>
      )}

      <div className="card">
        {error && <div className="error-banner">{error}</div>}
        {runs === null && <p className="muted">Cargando…</p>}
        {runs !== null && runs.length === 0 && (
          <p className="muted">Todavía no hay análisis.</p>
        )}

        {(runs || []).map(run => {
          const isOpen = open === run.id;
          const country = countryCodeOf(run.currency_source);
          const crit = (run.critical_findings_count || 0)
            + (run.zero_settlement_findings_count || 0);
          return (
            <div className={`runrow ${isOpen ? 'open' : ''}`} key={run.id}>
              <button className="runrow-head" onClick={() => toggle(run)} aria-expanded={isOpen}>
                <span className={`srcpill ${run.source === 'auto' ? 'auto' : 'man'}`}>
                  {run.source === 'auto' ? 'AUTO' : 'MANUAL'}
                </span>
                <span className="runrow-main">
                  <span className="runrow-title">
                    {country || run.currency_source || 'País desconocido'}
                    {' · '}{fmtDate(run.run_at)}
                  </span>
                  <span className="runrow-meta">
                    {fmtNum(run.unique_transactions)} transacciones ·{' '}
                    {run.source === 'auto' ? 'runner' : (run.run_by_email || 'alguien')}
                  </span>
                </span>
                <span className="runrow-counts">
                  <span><b>Crítico</b>{crit}</span>
                  <span><b>Monitor</b>{run.monitor_findings_count ?? 0}</span>
                </span>
                <span className="qcaret" aria-hidden="true">{isOpen ? '▾' : '▸'}</span>
              </button>

              {isOpen && (
                <div className="runrow-body">
                  <div className="kpi-grid">
                    <Kpi label="Transacciones" value={fmtNum(run.unique_transactions)} />
                    <Kpi label="Filas" value={fmtNum(run.total_rows)} />
                    <Kpi label="Críticos" value={fmtNum(crit)} tone="critical" />
                    <Kpi label="A monitorear" value={fmtNum(run.monitor_findings_count)} tone="monitor" />
                    <Kpi label="Exposición" value={fmtCurrency(
                      run.chargeback_exposure_usd, run.chargeback_exposure_currency)} />
                  </div>
                  <div className="muted small" style={{ marginBottom: '.6rem' }}>
                    Ventana {run.csv_date_start} → {run.csv_date_end}
                    {run.csv_filename ? ` · ${run.csv_filename}` : ''}
                  </div>
                  <RunFindings
                    rows={findings[run.id]}
                    session={session}
                    onChanged={() => { onChanged(); load(); }}
                  />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </>
  );
}

function RunFindings({
  rows, session, onChanged,
}: {
  rows: DecidedFinding[] | undefined;
  session: Session;
  onChanged: () => void;
}) {
  const [changing, setChanging] = useState<string | null>(null);

  if (!rows) return <p className="muted small">Cargando hallazgos…</p>;
  if (rows.length === 0) {
    return <p className="muted small">Este análisis no produjo hallazgos.</p>;
  }

  return (
    <div className="decided-list">
      {rows.map(f => {
        const st = STATUS[f.review_status] || { label: f.review_status, cls: 'na' };
        const patterns = rankPatterns(f.fingerprints || []).slice(0, 4);
        return (
          <div className="decided" key={f.id}>
            <div className="decided-head">
              <span className="decided-name">{f.company_name}</span>
              <span className={`tag decision-tag ${st.cls}`}>{st.label}</span>
              <span className="decided-amt">
                {f.section === 'zero_settlement'
                  ? <span className="muted small">sin liquidación</span>
                  : fmtCurrency(f.chargeback_exposure_usd, f.chargeback_exposure_currency)}
              </span>
            </div>
            <div className="muted small">
              {verdictFor(f.finding_type)} · riesgo {f.risk_score}
              {f.reviewed_by_email && <> · {st.label.toLowerCase()} por {f.reviewed_by_email} el {fmtDay(f.reviewed_at)}</>}
              {f.review_reason && <> — “{REASON_LABELS[f.review_reason] || f.review_reason}”</>}
            </div>
            <div className="tags">
              {patterns.map(c => (
                <span className="tag" key={c}>{describePattern(c).label}</span>
              ))}
            </div>

            {(f.review_status === 'accepted' || f.review_status === 'rejected') && (
              changing === f.id ? (
                <ChangeForm
                  finding={f}
                  session={session}
                  onCancel={() => setChanging(null)}
                  onDone={() => { setChanging(null); onChanged(); }}
                />
              ) : (
                <button className="btn ghost small" onClick={() => setChanging(f.id)}>
                  Cambiar decisión
                </button>
              )
            )}
          </div>
        );
      })}
    </div>
  );
}

function ChangeForm({
  finding, session, onCancel, onDone,
}: {
  finding: DecidedFinding;
  session: Session;
  onCancel: () => void;
  onDone: () => void;
}) {
  const target = finding.review_status === 'accepted' ? 'rejected' : 'accepted';
  const [explanation, setExplanation] = useState('');
  const [reason, setReason] = useState<ReviewReason | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  async function submit() {
    setBusy(true); setErr('');
    try {
      await changeDecision(
        finding.id, target, session.user.id, session.user.email!,
        explanation.trim(), reason ?? undefined,
      );
      onDone();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="dismiss" style={{ marginTop: '.6rem' }}>
      <div className="dismiss-title">
        Cambiar a “{STATUS[target].label}”
      </div>
      <div className="muted small" style={{ marginBottom: '.6rem' }}>
        Esto reescribe una decisión que alguien ya tomó. La explicación queda
        en el expediente y es obligatoria.
      </div>
      {target === 'rejected' && (
        <div className="chip-filters">
          {REVIEW_REASONS.map(r => (
            <button key={r.value}
                    className={`chip-filter ${reason === r.value ? 'on' : ''}`}
                    onClick={() => setReason(r.value)}>{r.label}</button>
          ))}
        </div>
      )}
      <input
        className="dismiss-note"
        placeholder="¿Por qué cambia? (obligatorio)"
        value={explanation}
        maxLength={400}
        onChange={e => setExplanation(e.target.value)}
      />
      {err && <div className="error-banner">{err}</div>}
      <div className="qactions">
        <button className="btn" disabled={busy || !explanation.trim()} onClick={submit}>
          {busy ? 'Guardando…' : 'Guardar cambio'}
        </button>
        <button className="btn ghost" disabled={busy} onClick={onCancel}>Cancelar</button>
      </div>
    </div>
  );
}

// ── Watchlist ────────────────────────────────────────────────────────────────

type WlTab = 'merchants' | 'cards' | 'indicators' | 'removed';

function Watchlist({
  session, online, onOffline,
}: {
  session: Session;
  online: boolean;
  onOffline: () => void;
}) {
  const [tab, setTab] = useState<WlTab>('merchants');
  const [search, setSearch] = useState('');
  const [merchants, setMerchants] = useState<WatchlistMerchant[] | null>(null);
  const [cards, setCards] = useState<WatchlistCard[] | null>(null);
  const [indicators, setIndicators] = useState<WatchlistIndicator[] | null>(null);
  const [openMerchant, setOpenMerchant] = useState<string | null>(null);
  const [history, setHistory] = useState<Record<string, DecidedFinding[]>>({});
  const [removing, setRemoving] = useState<string | null>(null);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    if (!online) { onOffline(); return; }
    setError('');
    try {
      if (tab === 'indicators') {
        setIndicators(await listWatchlistIndicators({ search }));
      } else if (tab === 'cards') {
        setCards(await listWatchlistCards({ search }));
      } else {
        setMerchants(await listWatchlistMerchants({
          search, removed: tab === 'removed',
        }));
      }
    } catch (e) {
      if (isNetworkError(e)) onOffline();
      else setError(e instanceof Error ? e.message : String(e));
    }
  }, [online, onOffline, tab, search]);

  // Debounced so typing does not fire a query per keystroke.
  useEffect(() => {
    const t = setTimeout(load, search ? 250 : 0);
    return () => clearTimeout(t);
  }, [load, search]);

  async function openHistory(name: string) {
    const next = openMerchant === name ? null : name;
    setOpenMerchant(next);
    if (next && !history[next]) {
      try {
        const rows = await merchantHistory(next);
        setHistory(p => ({ ...p, [next]: rows }));
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    }
  }

  return (
    <div className="card">
      <p className="muted small" style={{ marginTop: 0 }}>
        Todo lo que el sistema ha guardado. Un comercio entra aquí cuando
        alguien confirma fraude; sale solo si alguien lo retira, y el registro
        se queda como constancia.
      </p>

      <input
        className="wl-search"
        placeholder="Buscar comercio, tarjeta, BIN, correo, nombre…"
        value={search}
        onChange={e => setSearch(e.target.value)}
      />

      <div className="chip-filters">
        {([['merchants', 'Comercios'], ['cards', 'Tarjetas'],
           ['indicators', 'Indicadores'], ['removed', 'Retirados']] as [WlTab, string][])
          .map(([k, label]) => (
            <button key={k} className={`chip-filter ${tab === k ? 'on' : ''}`}
                    onClick={() => setTab(k)}>{label}</button>
          ))}
      </div>

      {error && <div className="error-banner">{error}</div>}

      {(tab === 'merchants' || tab === 'removed') && (
        merchants === null ? <p className="muted">Cargando…</p> :
        merchants.length === 0 ? (
          <p className="muted">
            {tab === 'removed'
              ? 'Nadie ha sido retirado de la watchlist.'
              : search ? 'Ningún comercio coincide.' : 'La watchlist está vacía.'}
          </p>
        ) : merchants.map(m => (
          <div className="wl-row" key={m.company_name}>
            <button className="wl-head" onClick={() => openHistory(m.company_name)}>
              <span className="wl-name">{m.company_name}</span>
              <span className="wl-meta">
                En la watchlist desde el {fmtDay(m.first_flagged)} ·{' '}
                marcado {m.flag_count} {m.flag_count === 1 ? 'vez' : 'veces'} ·{' '}
                visto por última vez el {fmtDay(m.last_flagged)}
                {m.removed_at && (
                  <> · <strong>retirado el {fmtDay(m.removed_at)}</strong>
                    {m.removed_by ? ` por ${m.removed_by}` : ''}
                    {m.removed_reason ? ` — “${m.removed_reason}”` : ''}</>
                )}
              </span>
            </button>
            <span className="wl-score">{m.last_risk_score ?? '—'}</span>

            {openMerchant === m.company_name && (
              <div className="wl-body">
                <MerchantHistory rows={history[m.company_name]} />
                {removing === m.company_name ? (
                  <RemoveForm
                    company={m.company_name}
                    removed={!!m.removed_at}
                    email={session.user.email!}
                    onCancel={() => setRemoving(null)}
                    onDone={() => { setRemoving(null); load(); }}
                  />
                ) : (
                  <button className="btn ghost small"
                          onClick={() => setRemoving(m.company_name)}>
                    {m.removed_at ? 'Devolver a la watchlist' : 'Retirar de la watchlist…'}
                  </button>
                )}
              </div>
            )}
          </div>
        ))
      )}

      {tab === 'cards' && (
        cards === null ? <p className="muted">Cargando…</p> :
        cards.length === 0 ? <p className="muted">Ninguna tarjeta coincide.</p> :
        <div className="wl-cards">
          {cards.map(c => (
            <div className="wl-card" key={c.card_key}>
              <span className="mono">{c.bin}-{c.last4}</span>
              <span className="muted small">
                {c.flag_count} {c.flag_count === 1 ? 'vez' : 'veces'} ·{' '}
                {fmtDay(c.last_flagged)}
              </span>
            </div>
          ))}
        </div>
      )}

      {tab === 'indicators' && (
        indicators === null ? <p className="muted">Cargando…</p> :
        indicators.length === 0 ? <p className="muted">Ningún indicador coincide.</p> :
        <div className="wl-cards">
          {indicators.map(i => (
            <div className="wl-card" key={i.id}>
              <span className="mono">{i.value_raw}</span>
              <span className="muted small">
                {i.indicator_type}
                {i.source_company_name ? ` · ${i.source_company_name}` : ''}
                {i.hit_count > 0
                  ? ` · ${i.hit_count} coincidencia${i.hit_count === 1 ? '' : 's'}`
                  : ' · sin coincidencias'}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function MerchantHistory({ rows }: { rows: DecidedFinding[] | undefined }) {
  if (!rows) return <p className="muted small">Cargando historial…</p>;
  if (rows.length === 0) return <p className="muted small">Sin hallazgos registrados.</p>;
  return (
    <div className="wl-history">
      {rows.map(f => {
        const st = STATUS[f.review_status] || { label: f.review_status, cls: 'na' };
        return (
          <div className="wl-hist-item" key={f.id}>
            <span className="wl-hist-date">{fmtDay(f.first_seen_at || f.reviewed_at)}</span>
            <span>
              <span className={`tag decision-tag ${st.cls}`}>{st.label}</span>{' '}
              {verdictFor(f.finding_type)} · riesgo {f.risk_score}
              {f.reviewed_by_email ? ` · ${f.reviewed_by_email}` : ''}
            </span>
          </div>
        );
      })}
    </div>
  );
}

function RemoveForm({
  company, removed, email, onCancel, onDone,
}: {
  company: string;
  removed: boolean;
  email: string;
  onCancel: () => void;
  onDone: () => void;
}) {
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  async function submit() {
    setBusy(true); setErr('');
    try {
      await setMerchantRemoved(company, !removed, email, reason.trim());
      onDone();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="dismiss" style={{ marginTop: '.6rem' }}>
      <div className="dismiss-title">
        {removed ? `Devolver ${company} a la watchlist` : `Retirar ${company} de la watchlist`}
      </div>
      <div className="muted small" style={{ marginBottom: '.6rem' }}>
        {removed
          ? 'Volverá a marcarse en los análisis.'
          : 'El registro no se borra: queda como constancia de por qué se marcó ' +
            'en su momento. Deja de contar en los análisis a partir de ahora.'}
      </div>
      {!removed && (
        <input
          className="dismiss-note"
          placeholder="Motivo (obligatorio)"
          value={reason}
          maxLength={300}
          onChange={e => setReason(e.target.value)}
        />
      )}
      {err && <div className="error-banner">{err}</div>}
      <div className="qactions">
        <button className="btn" disabled={busy || (!removed && !reason.trim())} onClick={submit}>
          {busy ? 'Guardando…' : removed ? 'Devolver' : 'Retirar'}
        </button>
        <button className="btn ghost" disabled={busy} onClick={onCancel}>Cancelar</button>
      </div>
    </div>
  );
}

function Kpi({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div className={`kpi ${tone || ''}`}>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value">{value}</div>
    </div>
  );
}
