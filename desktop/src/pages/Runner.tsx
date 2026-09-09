import { useCallback, useEffect, useState } from 'react';

import {
  listCycles,
  listRunFindings,
  runnerHealth,
  hoursSince,
  isStale,
  nextSlotHour,
  daysUntil,
  recordedFindingCount,
  COUNTRY_NAMES,
  ROTATION,
  STALE_AFTER_HOURS,
  TOKEN_WARN_DAYS,
  type CountryHealth,
  type CycleOutcome,
  type RunFinding,
  type RunnerCycle,
} from '../lib/runner';
import { isNetworkError } from '../lib/offline';
import { OfflineState } from '../components/OfflineState';

// How many cycles the timeline fetches. At one cycle an hour this is a bit
// over a day, which covers "what happened overnight" — the question this
// screen exists to answer without an SSH session.
const CYCLE_LIMIT = 30;

// Ticks per country tile. Eight slots is a full day for one country on the
// three-hour rotation, so a country that has been failing all day shows a
// full row of misses rather than an ambiguous one or two.
const TICKS = 8;

// ── Vocabulary ───────────────────────────────────────────────────────────────
// `severity` is deliberately not "did it produce findings". no_email is a
// designed ending, not a failure: the report was slow, the cycle stopped
// rather than requesting a second identical one, and the country picks up at
// its next slot. Painting it red would train everyone to ignore red.

type Severity = 'good' | 'neutral' | 'bad';

const OUTCOMES: Record<CycleOutcome, { label: string; severity: Severity }> = {
  ok:             { label: 'Analizado',              severity: 'good' },
  running:        { label: 'En curso',               severity: 'neutral' },
  no_email:       { label: 'Sin correo',             severity: 'neutral' },
  cms_error:      { label: 'Error del CMS',          severity: 'bad' },
  token_error:    { label: 'Token del CMS',          severity: 'bad' },
  gmail_error:    { label: 'Error de Gmail',         severity: 'bad' },
  supabase_error: { label: 'Error de Supabase',      severity: 'bad' },
  config_error:   { label: 'Configuración incompleta', severity: 'bad' },
  unexpected:     { label: 'Error inesperado',       severity: 'bad' },
};

// The fix, next to the failure. These are the same symptom-to-fix mappings as
// the runbook; having them here means a broken cycle is self-explaining
// instead of sending someone to look for the document.
const FIXES: Partial<Record<CycleOutcome, string>> = {
  no_email:
    'No es un fallo. El reporte no llegó dentro del tiempo de espera y el ' +
    'ciclo terminó en vez de pedir un segundo reporte idéntico — dos correos ' +
    'iguales en el buzón no se pueden distinguir. Este país lo reintenta en ' +
    'su próximo turno.',
  running:
    'Si lleva más de una hora así, el proceso murió a mitad del ciclo (corte ' +
    'de luz, o alguien lo terminó). No hay nada que reparar: el siguiente ' +
    'turno corre normalmente.',
  cms_error:
    'Un 403 aquí es un problema de cabeceras, no del token. Compara ' +
    '`python3 runner/cycle.py --show-request` con ' +
    '`python3 runner/import_curl.py --show-headers`.',
  token_error:
    'Vuelve a capturar el cURL del navegador y pásalo por ' +
    '`python3 runner/import_curl.py`.',
  gmail_error:
    'Reautoriza el buzón con `python3 runner/gmail.py --authorize`.',
  supabase_error:
    'Revisa NEXT_PUBLIC_SUPABASE_URL y SUPABASE_SERVICE_ROLE_KEY en ' +
    'runner/.env.',
  config_error:
    'Falta un valor en runner/.env — el mensaje de arriba dice cuál. ' +
    '`python3 runner/setup_env.py` los vuelve a pedir.',
  unexpected:
    'El detalle completo está en el log del día, en la Pi: ' +
    '~/fraud-engine-logs/cycle-AAAA-MM-DD.log',
};

// ── Formatting ───────────────────────────────────────────────────────────────

const fmtCurrency = (n: number | null, code: string | null) => {
  if (n == null) return '—';
  // Rows written before the 2026-09 currency fix carry 'UNKNOWN': the engine
  // could not tell GTQ from USD, so claiming either would be a guess.
  if (!code || code === 'UNKNOWN') {
    return `${n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })} (sin moneda)`;
  }
  try {
    return n.toLocaleString('en-US', { style: 'currency', currency: code });
  } catch {
    return `${code} ${n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  }
};

const fmtNumber = (n: number | null) =>
  n == null ? '—' : n.toLocaleString('en-US');

const fmtClock = (iso: string | null) => {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleTimeString('es', { hour: '2-digit', minute: '2-digit' });
};

const fmtDay = (iso: string | null) => {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleDateString('es', { day: 'numeric', month: 'short' });
};

function fmtAgo(iso: string | null): string {
  const hours = hoursSince(iso);
  if (hours === null) return 'nunca';
  if (hours < 1) return `hace ${Math.max(1, Math.round(hours * 60))} min`;
  if (hours < 48) return `hace ${Math.round(hours)} h`;
  return `hace ${Math.round(hours / 24)} días`;
}

function fmtDuration(startIso: string, endIso: string | null): string {
  if (!endIso) return '—';
  const ms = new Date(endIso).getTime() - new Date(startIso).getTime();
  if (Number.isNaN(ms) || ms < 0) return '—';
  const secs = Math.round(ms / 1000);
  if (secs < 60) return `${secs}s`;
  return `${Math.floor(secs / 60)}m ${String(secs % 60).padStart(2, '0')}s`;
}

// PostgREST reports a missing table through the schema cache, which produces
// a message nobody would connect to "run the migration". Naming it here turns
// a mystifying error into an instruction.
function looksLikeMissingTable(message: string): boolean {
  const m = message.toLowerCase();
  return m.includes('runner_cycles') || m.includes('runner_health')
    ? m.includes('does not exist') || m.includes('schema cache')
      || m.includes('could not find') || m.includes('404')
    : false;
}

// ── Page ─────────────────────────────────────────────────────────────────────

export function Runner({ online }: { online: boolean }) {
  const [health, setHealth] = useState<CountryHealth[] | null>(null);
  const [cycles, setCycles] = useState<RunnerCycle[] | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [findings, setFindings] =
    useState<Record<string, RunFinding[] | 'loading' | 'error'>>({});
  const [filter, setFilter] = useState<'all' | 'findings' | 'failed'>('all');
  const [error, setError] = useState('');
  const [needsMigration, setNeedsMigration] = useState(false);
  const [offline, setOffline] = useState(false);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    if (!online) {
      setOffline(true);
      setCycles(null);
      setHealth(null);
      return;
    }
    setLoading(true);
    setError('');
    setNeedsMigration(false);
    setOffline(false);
    try {
      const [h, c] = await Promise.all([runnerHealth(), listCycles(CYCLE_LIMIT)]);
      setHealth(h);
      setCycles(c);
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      if (isNetworkError(e)) {
        setOffline(true);
        setCycles(null);
        setHealth(null);
      } else if (looksLikeMissingTable(message)) {
        setNeedsMigration(true);
      } else {
        setError(message);
      }
    } finally {
      setLoading(false);
    }
  }, [online]);

  useEffect(() => { load(); }, [load]);

  const toggle = useCallback(async (cycle: RunnerCycle) => {
    const open = expanded.has(cycle.id);
    setExpanded(prev => {
      const next = new Set(prev);
      if (open) next.delete(cycle.id); else next.add(cycle.id);
      return next;
    });
    // Findings load lazily, on first expand: the collapsed row already shows
    // counts recorded on the run itself, so fetching them up front would be
    // thirty queries nobody asked for.
    if (open || !cycle.run_id || findings[cycle.run_id]) return;
    const runId = cycle.run_id;
    setFindings(prev => ({ ...prev, [runId]: 'loading' }));
    try {
      const rows = await listRunFindings(runId);
      setFindings(prev => ({ ...prev, [runId]: rows }));
    } catch {
      setFindings(prev => ({ ...prev, [runId]: 'error' }));
    }
  }, [expanded, findings]);

  if (offline) {
    return <OfflineState title="Estado del runner" onRetry={load} disabled={!online} />;
  }

  const visible = (cycles || []).filter(c => {
    if (filter === 'failed') {
      return OUTCOMES[c.outcome]?.severity === 'bad';
    }
    if (filter === 'findings') {
      return (recordedFindingCount(c.analysis_runs) || 0) > 0;
    }
    return true;
  });

  return (
    <main className="main">
      {needsMigration && (
        <div className="card">
          <h2 style={{ marginTop: 0 }}>Falta aplicar una migración</h2>
          <p>
            Esta pantalla lee la tabla <code>runner_cycles</code>, que todavía
            no existe. Abre el SQL Editor de Supabase, pega el contenido de{' '}
            <code>supabase/migrations/0012_runner_cycles.sql</code> y ejecútalo
            una vez.
          </p>
          <p className="muted small">
            Hasta entonces el runner sigue corriendo con normalidad — lo único
            que falta es que deje constancia de cada ciclo.
          </p>
          <button className="btn" onClick={load}>Reintentar</button>
        </div>
      )}

      {!needsMigration && (
        <>
          <StatusStrip health={health} loading={loading} onReload={load} />
          <CountryTiles health={health} cycles={cycles} />
          <Facts health={health} cycles={cycles} />
        </>
      )}

      {error && <div className="card"><div className="error-banner">{error}</div></div>}

      {!needsMigration && (
        <div className="card">
          <div className="historial-head">
            <div>
              <h2 style={{ margin: 0 }}>Ciclos recientes</h2>
              <p className="muted small" style={{ margin: '0.35rem 0 0' }}>
                Un <strong>ciclo</strong> es cada vez que el runner despierta e
                intenta. Los ciclos que fallan no producen ningún análisis, así
                que una lista de análisis sería justamente la que los esconde.
              </p>
            </div>
            <div className="filter-buttons">
              <FilterButton active={filter === 'all'} onClick={() => setFilter('all')}>
                Todos
              </FilterButton>
              <FilterButton active={filter === 'findings'} onClick={() => setFilter('findings')}>
                Con hallazgos
              </FilterButton>
              <FilterButton active={filter === 'failed'} onClick={() => setFilter('failed')}>
                Fallidos
              </FilterButton>
            </div>
          </div>

          {cycles === null && <p className="muted">Cargando…</p>}
          {cycles !== null && cycles.length === 0 && (
            <p className="muted">
              Todavía no hay ciclos registrados. El primero aparecerá aquí
              después del próximo turno programado, al inicio de la hora.
            </p>
          )}
          {cycles !== null && cycles.length > 0 && visible.length === 0 && (
            <p className="success-banner">
              Ningún ciclo coincide con este filtro
              {filter === 'failed' ? ' — no ha fallado ninguno.' : '.'}
            </p>
          )}
        </div>
      )}

      {visible.length > 0 && (
        <div className="card cycle-list">
          {visible.map(c => (
            <CycleRow
              key={c.id}
              cycle={c}
              open={expanded.has(c.id)}
              findings={c.run_id ? findings[c.run_id] : undefined}
              onToggle={() => toggle(c)}
            />
          ))}
        </div>
      )}
    </main>
  );
}

// ── Status strip ─────────────────────────────────────────────────────────────

function StatusStrip({
  health, loading, onReload,
}: {
  health: CountryHealth[] | null;
  loading: boolean;
  onReload: () => void;
}) {
  if (health === null) {
    return <div className="runner-status neutral"><span>Consultando el estado del runner…</span></div>;
  }

  const known = ROTATION.map(code =>
    health.find(h => h.country_code === code)
      || { country_code: code, last_success_at: null, last_success_run_id: null,
           last_cycle_at: null, last_outcome: null, last_detail: null,
           consecutive_failures: 0, cycles_24h: 0, ok_24h: 0,
           token_expires_at: null } as CountryHealth,
  );
  const stale = known.filter(isStale);
  const never = stale.filter(h => h.last_success_at === null);

  let severity: Severity = 'good';
  let message = 'El runner está al día. Los tres países han corrido en las '
    + `últimas ${STALE_AFTER_HOURS} horas.`;

  if (stale.length === known.length && never.length === known.length) {
    severity = 'neutral';
    message = 'El runner todavía no ha registrado ningún ciclo. El primero '
      + 'aparecerá al inicio de la próxima hora.';
  } else if (stale.length > 0) {
    severity = 'bad';
    const names = stale.map(h => COUNTRY_NAMES[h.country_code] || h.country_code);
    message = stale.length === 1
      ? `${names[0]} no ha corrido con éxito en ${STALE_AFTER_HOURS} horas.`
      : `${names.join(', ')} no han corrido con éxito en ${STALE_AFTER_HOURS} horas.`;
  }

  return (
    <div className={`runner-status ${severity}`}>
      <span className="runner-status-dot" aria-hidden="true" />
      <span className="runner-status-text">{message}</span>
      <button className="btn ghost small" onClick={onReload} disabled={loading}>
        {loading ? 'Actualizando…' : 'Actualizar'}
      </button>
    </div>
  );
}

// ── Country tiles ────────────────────────────────────────────────────────────

function CountryTiles({
  health, cycles,
}: {
  health: CountryHealth[] | null;
  cycles: RunnerCycle[] | null;
}) {
  if (health === null) return null;

  return (
    <div className="runner-countries">
      {ROTATION.map(code => {
        const h = health.find(x => x.country_code === code);
        const stale = h ? isStale(h) : true;
        const slot = nextSlotHour(code);
        // Newest first out of the fetched window, then reversed so the strip
        // reads left-to-right in time like everything else.
        const ticks = (cycles || [])
          .filter(c => c.country_code === code)
          .slice(0, TICKS)
          .reverse();

        return (
          <div className={`runner-country ${stale ? 'stale' : ''}`} key={code}>
            <div className="runner-country-head">
              <strong>{COUNTRY_NAMES[code] || code}</strong>
              <span className="runner-country-code">{code}</span>
            </div>

            <div className="runner-country-main">
              <span className="runner-country-ago">
                {fmtAgo(h?.last_success_at ?? null)}
              </span>
              <span className="muted small">último éxito</span>
            </div>

            <div className="runner-ticks" aria-hidden="true">
              {ticks.length === 0 && <span className="muted small">sin ciclos aún</span>}
              {ticks.map(c => (
                <span
                  key={c.id}
                  className={`runner-tick ${OUTCOMES[c.outcome]?.severity || 'neutral'}`}
                  title={`${fmtClock(c.started_at)} · ${OUTCOMES[c.outcome]?.label || c.outcome}`}
                />
              ))}
            </div>

            <div className="runner-country-foot muted small">
              {h && h.consecutive_failures > 0 ? (
                <span className="runner-fail-count">
                  {h.consecutive_failures} fallo
                  {h.consecutive_failures === 1 ? '' : 's'} desde el último éxito
                </span>
              ) : (
                <span>{h ? `${h.ok_24h}/${h.cycles_24h} ciclos hoy` : 'sin datos'}</span>
              )}
              {slot !== null && (
                <span>próximo turno {String(slot).padStart(2, '0')}:00</span>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Facts ────────────────────────────────────────────────────────────────────

function Facts({
  health, cycles,
}: {
  health: CountryHealth[] | null;
  cycles: RunnerCycle[] | null;
}) {
  if (health === null || cycles === null) return null;

  const cycles24 = health.reduce((n, h) => n + h.cycles_24h, 0);
  const ok24 = health.reduce((n, h) => n + h.ok_24h, 0);

  // Every cycle records the expiry it saw, so the newest row carries the
  // freshest reading.
  const tokenIso = cycles.find(c => c.token_expires_at)?.token_expires_at ?? null;
  const tokenDays = daysUntil(tokenIso);

  let tokenTone: Severity = 'good';
  let tokenText = '—';
  if (tokenDays === null) {
    tokenTone = 'neutral';
    tokenText = 'sin leer';
  } else if (tokenDays <= 0) {
    tokenTone = 'bad';
    tokenText = 'vencido';
  } else if (tokenDays < TOKEN_WARN_DAYS) {
    tokenTone = 'bad';
    tokenText = `${Math.floor(tokenDays)} días`;
  } else {
    tokenText = `${Math.floor(tokenDays)} días`;
  }

  const last = cycles[0];
  const host = cycles.find(c => c.host)?.host;

  return (
    <div className="runner-facts">
      <Fact label="Ciclos en 24 h" value={`${ok24}/${cycles24}`}
            hint={cycles24 === 0 ? 'ninguno todavía' : 'con éxito / intentados'} />
      <Fact label="Token del CMS" value={tokenText} tone={tokenTone}
            hint={tokenIso ? `vence el ${fmtDay(tokenIso)}` : 'no se pudo leer'} />
      <Fact label="Último ciclo"
            value={last ? fmtClock(last.started_at) : '—'}
            hint={last ? `${COUNTRY_NAMES[last.country_code] || last.country_code} · ${OUTCOMES[last.outcome]?.label || last.outcome}` : 'sin registros'} />
      <Fact label="Máquina" value={host || '—'} hint="donde corre el runner" />
    </div>
  );
}

function Fact({
  label, value, hint, tone = 'good',
}: {
  label: string;
  value: string;
  hint?: string;
  tone?: Severity;
}) {
  return (
    <div className="runner-fact">
      <div className="runner-fact-label">{label}</div>
      <div className={`runner-fact-value ${tone}`}>{value}</div>
      {hint && <div className="runner-fact-hint">{hint}</div>}
    </div>
  );
}

// ── One cycle ────────────────────────────────────────────────────────────────

function CycleRow({
  cycle, open, findings, onToggle,
}: {
  cycle: RunnerCycle;
  open: boolean;
  findings: RunFinding[] | 'loading' | 'error' | undefined;
  onToggle: () => void;
}) {
  const meta = OUTCOMES[cycle.outcome]
    || { label: cycle.outcome, severity: 'neutral' as Severity };
  const run = cycle.analysis_runs;
  const recorded = recordedFindingCount(run);

  let summary: React.ReactNode = <span className="muted">—</span>;
  if (cycle.outcome === 'ok') {
    const critical = (run?.critical_findings_count || 0)
      + (run?.zero_settlement_findings_count || 0);
    summary = recorded === 0
      // A quiet run is a success, not an empty row. Saying so explicitly is
      // the difference between "it worked and found nothing" and "something
      // is broken", which read identically as a blank cell.
      ? <span className="muted">sin hallazgos</span>
      : (
        <span>
          <strong>{critical}</strong> crítico{critical === 1 ? '' : 's'}
          {(run?.monitor_findings_count || 0) > 0 && (
            <span className="muted"> · {run?.monitor_findings_count} monitor</span>
          )}
        </span>
      );
  }

  return (
    <div className={`cycle ${meta.severity} ${open ? 'open' : ''}`}>
      <button className="cycle-head" onClick={onToggle} aria-expanded={open}>
        <span className="cycle-time">
          {fmtClock(cycle.started_at)}
          <span className="cycle-day muted small">{fmtDay(cycle.started_at)}</span>
        </span>
        <span className="cycle-country">{cycle.country_code}</span>
        <span className={`tag outcome ${meta.severity}`}>{meta.label}</span>
        <span className="cycle-summary">{summary}</span>
        <span className="cycle-tx muted small">
          {run?.unique_transactions != null
            ? `${fmtNumber(run.unique_transactions)} tx`
            : ''}
        </span>
        <span className="cycle-duration muted small">
          {fmtDuration(cycle.started_at, cycle.finished_at)}
        </span>
        <span className="cycle-caret" aria-hidden="true">{open ? '▾' : '▸'}</span>
      </button>

      {open && (
        <div className="cycle-body">
          <CycleFacts cycle={cycle} />
          {cycle.detail && (
            <p className="cycle-detail">{cycle.detail}</p>
          )}
          {FIXES[cycle.outcome] && (
            <p className={`cycle-fix ${meta.severity}`}>{FIXES[cycle.outcome]}</p>
          )}
          {cycle.outcome === 'ok' && (
            <CycleFindings
              findings={findings}
              recorded={recorded}
              currency={run?.chargeback_exposure_currency ?? null}
            />
          )}
        </div>
      )}
    </div>
  );
}

function CycleFacts({ cycle }: { cycle: RunnerCycle }) {
  const run = cycle.analysis_runs;
  const window = cycle.window_start === cycle.window_end
    ? cycle.window_start
    : `${cycle.window_start} → ${cycle.window_end}`;

  // Both are derived independently — the cycle asked for a country id, the
  // analysis read country_name out of the CSV — so a disagreement is a real
  // signal rather than a restatement.
  const declared = run?.currency_source;
  const asked = (COUNTRY_NAMES[cycle.country_code] || '').toLowerCase();
  const mismatch = !!declared
    && declared.toLowerCase() !== asked
    && declared.toLowerCase() !== asked.replace('á', 'a');

  return (
    <dl className="cycle-facts">
      <Pair label="Ventana pedida" value={window || '—'} />
      <Pair label="Transacciones" value={
        run ? `${fmtNumber(run.unique_transactions)} únicas de ${fmtNumber(run.total_rows)} filas` : '—'
      } />
      <Pair label="Exposición" value={
        run ? fmtCurrency(run.chargeback_exposure_usd, run.chargeback_exposure_currency) : '—'
      } />
      <Pair
        label="País del archivo"
        value={declared || '—'}
        warn={mismatch}
        note={mismatch ? `se pidió ${cycle.country_code}` : undefined}
      />
      <Pair label="Archivo" value={run?.csv_filename || '—'} />
      <Pair label="Terminó" value={
        cycle.finished_at
          ? `${fmtClock(cycle.finished_at)} (${fmtDuration(cycle.started_at, cycle.finished_at)})`
          : 'no terminó'
      } />
    </dl>
  );
}

function Pair({
  label, value, warn, note,
}: {
  label: string;
  value: string;
  warn?: boolean;
  note?: string;
}) {
  return (
    <div className="cycle-pair">
      <dt>{label}</dt>
      <dd className={warn ? 'warn' : ''}>
        {value}
        {note && <span className="muted small"> · {note}</span>}
      </dd>
    </div>
  );
}

function CycleFindings({
  findings, recorded, currency,
}: {
  findings: RunFinding[] | 'loading' | 'error' | undefined;
  recorded: number | null;
  currency: string | null;
}) {
  if (findings === 'loading' || findings === undefined) {
    return <p className="muted small">Cargando hallazgos…</p>;
  }
  if (findings === 'error') {
    return <p className="muted small">No se pudieron cargar los hallazgos.</p>;
  }
  if (recorded === 0) {
    return (
      <p className="muted small">
        Este ciclo analizó el reporte y no encontró nada. Eso es un éxito.
      </p>
    );
  }

  const moved = recorded != null && recorded > findings.length;

  return (
    <>
      <div className="cycle-findings-head">
        <strong>Hallazgos</strong>
        <span className="muted small">estado actual, no el del momento del análisis</span>
      </div>

      {moved && (
        <p className="muted small cycle-moved">
          Este ciclo registró {recorded} hallazgo{recorded === 1 ? '' : 's'} y
          aquí se ven {findings.length}. La diferencia son hallazgos que un
          ciclo posterior volvió a detectar: la de-duplicación los reasigna al
          ciclo más reciente en vez de duplicarlos.
        </p>
      )}

      <ul className="findings">
        {findings.map(f => (
          <li
            key={f.id}
            className={`finding ${f.confidence === 'Critical' ? 'critical' : 'monitor'}`}
          >
            <div className="finding-head">
              <div style={{ flex: '1 1 320px' }}>
                <strong>{f.company_name}</strong>
                {f.section === 'zero_settlement' && (
                  <span className="tag zero-settlement" style={{ marginLeft: '0.5rem' }}>
                    Sin liquidación
                  </span>
                )}
                <span className="muted small" style={{ marginLeft: '0.75rem' }}>
                  Riesgo: {f.risk_score}
                </span>
                {f.section !== 'zero_settlement' && (
                  <span className="muted small" style={{ marginLeft: '0.75rem' }}>
                    Exposición: {fmtCurrency(f.chargeback_exposure_usd,
                                             f.chargeback_exposure_currency || currency)}
                  </span>
                )}
              </div>
              <ReviewTag status={f.review_status} by={f.reviewed_by_email} />
            </div>

            {f.description_es && (
              <p style={{ margin: '0.4rem 0', fontSize: '0.95rem' }}>{f.description_es}</p>
            )}

            <div className="finding-sightings muted small">
              {(f.times_seen || 1) > 1
                ? `Visto ${f.times_seen} veces desde el ${fmtDay(f.first_seen_at)}`
                : `Primera vez, el ${fmtDay(f.first_seen_at)}`}
            </div>

            <div className="tags">
              {(f.fingerprints || []).map(fp => (
                <span className="tag" key={fp}>{fp}</span>
              ))}
            </div>
          </li>
        ))}
      </ul>

      <p className="muted small cycle-readonly">
        Esta vista es de solo lectura. Aceptar o descartar se hace en{' '}
        <strong>Pendientes</strong>, que es donde vive la cola de revisión.
      </p>
    </>
  );
}

function ReviewTag({ status, by }: { status: string; by: string | null }) {
  const map: Record<string, { label: string; cls: string }> = {
    pending:        { label: 'Pendiente',   cls: 'pending' },
    accepted:       { label: 'Aceptado',    cls: 'accepted' },
    rejected:       { label: 'Descartado',  cls: 'rejected' },
    not_applicable: { label: 'Informativo', cls: 'na' },
  };
  const m = map[status] || { label: status, cls: 'na' };
  return (
    <span className={`tag review ${m.cls}`} title={by || undefined}>
      {m.label}
    </span>
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
    <button className={`btn ghost small ${active ? 'active' : ''}`} onClick={onClick}>
      {children}
    </button>
  );
}
