import { useCallback, useEffect, useMemo, useState } from 'react';
import type { Session } from '@supabase/supabase-js';

import {
  listIndicators,
  createIndicators,
  deactivateIndicator,
  FUZZY_CAPABLE,
  TYPE_LABELS,
  TYPE_HINTS,
  type Indicator,
  type IndicatorType,
  type MatchMode,
} from '../lib/indicators';

const SOURCES = ['contracargo', 'revisión de ops', 'reporte bancario', 'otro'];
const ALL_TYPES = Object.keys(TYPE_LABELS) as IndicatorType[];

const fmtDate = (iso: string | null) => (iso ? iso.slice(0, 10) : '—');

/**
 * Hide most of a value while keeping it recognisable.
 *
 * These are real people's emails, card numbers and phone numbers, sitting on a
 * screen someone scrolls in an open-plan office. Enough remains to confirm
 * "yes, that is the one I was looking for" — which is all this list is for.
 */
function maskValue(raw: string): string {
  const v = (raw || '').trim();
  if (v.length <= 4) return '•'.repeat(v.length);
  const at = v.indexOf('@');
  if (at > 0) {
    // Keep the first letter and the whole domain: the domain is often the
    // signal (a disposable-mail provider), and it is not personal.
    return `${v[0]}${'•'.repeat(Math.max(1, at - 1))}${v.slice(at)}`;
  }
  return `${v.slice(0, 2)}${'•'.repeat(Math.max(2, v.length - 4))}${v.slice(-2)}`;
}

export function Indicadores({
  session, online, onChanged,
}: {
  session: Session;
  online: boolean;
  onChanged?: () => void;
}) {
  const email = session.user.email || '';

  const [indicators, setIndicators] = useState<Indicator[] | null>(null);
  const [showInactive, setShowInactive] = useState(false);
  const [error, setError] = useState('');
  const [saved, setSaved] = useState('');
  const [busy, setBusy] = useState(false);

  const [search, setSearch] = useState('');
  const [hitFilter, setHitFilter] = useState<'all' | 'hits' | 'nohits'>('all');
  const [unmasked, setUnmasked] = useState(false);
  // Collapsed groups, by type. Everything starts open: on a small list that is
  // the useful state, and on a large one the search box is the better tool.
  const [closed, setClosed] = useState<Set<string>>(new Set());

  const [type, setType] = useState<IndicatorType>('email');
  const [values, setValues] = useState('');
  const [matchMode, setMatchMode] = useState<MatchMode>('exact');
  const [source, setSource] = useState(SOURCES[0]);
  const [sourceCompany, setSourceCompany] = useState('');
  const [notes, setNotes] = useState('');

  const load = useCallback(async () => {
    if (!online) return;
    setError('');
    try {
      setIndicators(await listIndicators(showInactive));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [online, showInactive]);

  useEffect(() => { load(); }, [load]);

  // Switching to a type that can't do fuzzy must not leave a stale mode.
  useEffect(() => {
    if (matchMode !== 'exact' && !FUZZY_CAPABLE.includes(type)) setMatchMode('exact');
  }, [type, matchMode]);

  const canFuzzy = FUZZY_CAPABLE.includes(type);

  // "Does this feature even work?" was a real question, and the answer was
  // sitting in a column nobody surfaced. Promoting the hit counts to the
  // header answers it permanently, at a glance.
  const all = indicators || [];
  const withHits = all.filter(i => i.hit_count > 0).length;
  const noHits = all.length - withHits;
  const lastHit = all
    .map(i => i.last_hit_at)
    .filter((d): d is string => !!d)
    .sort()
    .pop() || null;

  const visible = useMemo(() => {
    const q = search.trim().toLowerCase();
    return all.filter(i => {
      if (hitFilter === 'hits' && i.hit_count === 0) return false;
      if (hitFilter === 'nohits' && i.hit_count > 0) return false;
      if (!q) return true;
      // Search always matches against the real value even while it is masked
      // on screen — an analyst pasting an email expects to find it.
      return [i.value_raw, i.source, i.source_company_name, i.notes]
        .some(v => (v || '').toLowerCase().includes(q));
    });
  }, [all, search, hitFilter]);

  const grouped = useMemo(() => {
    const byType = new Map<string, Indicator[]>();
    for (const i of visible) {
      const list = byType.get(i.indicator_type) || [];
      list.push(i);
      byType.set(i.indicator_type, list);
    }
    for (const list of byType.values()) {
      // Most recently useful first: an indicator that keeps firing is the one
      // worth looking at, and a fresh one is worth confirming landed.
      list.sort((a, b) => (b.hit_count - a.hit_count)
        || (b.added_at || '').localeCompare(a.added_at || ''));
    }
    return [...byType.entries()]
      .sort((a, b) => b[1].length - a[1].length);
  }, [visible]);

  async function save() {
    const list = values.split(/[\n,;]+/).map(v => v.trim()).filter(Boolean);
    if (list.length === 0) { setError('Escribe al menos un valor.'); return; }
    setBusy(true); setError(''); setSaved('');
    try {
      const n = await createIndicators({
        indicator_type: type,
        values: list,
        match_mode: matchMode,
        source,
        source_company_name: sourceCompany || null,
        notes: notes || null,
      }, email);
      setSaved(`${n} indicador${n === 1 ? '' : 'es'} guardado${n === 1 ? '' : 's'}.`);
      setValues('');
      await load();
      onChanged?.();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function remove(ind: Indicator) {
    const reason = window.prompt('¿Por qué se desactiva? (opcional)') ?? '';
    setBusy(true); setError('');
    try {
      await deactivateIndicator(ind.id, email, reason);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  // `.main` is what supplies the page padding and the 1100px max-width. This
  // was the only screen in the app that skipped it, so its text ran edge to
  // edge on a wide monitor and became genuinely hard to read. `.report` is a
  // content class, not a layout one — every other page nests it inside
  // `.main` exactly like this.
  if (!online) {
    return (
      <main className="main">
        <div className="report">
          <h2>Indicadores de fraude confirmado</h2>
          <div className="info-banner">
            Necesitas conexión para ver y editar los indicadores. La lista es
            compartida con todo el equipo, así que no se guarda una copia local.
          </div>
        </div>
      </main>
    );
  }

  return (
    <main className="main">
    <div className="report">
      <h2>Indicadores de fraude confirmado</h2>
      <p className="phase-note">
        Datos que el equipo ya confirmó como fraude — un correo de un contracargo,
        un nombre de un reporte bancario, la IP de un caso anterior. Cada análisis
        se compara contra esta lista. Cuando un valor confirmado en un comercio
        aparece en <strong>otro comercio distinto</strong>, el hallazgo se marca
        como Critical automáticamente.
      </p>

      {/* ── Add ──────────────────────────────────────────────────── */}
      <section>
        <h3>Agregar</h3>
        <div className="ind-form">
          <label>
            <span className="muted small">Tipo de dato</span>
            <select value={type} onChange={e => setType(e.target.value as IndicatorType)}>
              {ALL_TYPES.map(t => <option key={t} value={t}>{TYPE_LABELS[t]}</option>)}
            </select>
          </label>

          <label>
            <span className="muted small">Cómo comparar</span>
            <select
              value={matchMode}
              onChange={e => setMatchMode(e.target.value as MatchMode)}
              disabled={!canFuzzy}
            >
              <option value="exact">Exacta — marca Critical</option>
              {canFuzzy && <option value="both">Exacta + aproximada</option>}
              {canFuzzy && <option value="fuzzy">Solo aproximada</option>}
            </select>
          </label>

          <label>
            <span className="muted small">Fuente</span>
            <select value={source} onChange={e => setSource(e.target.value)}>
              {SOURCES.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>

          <label>
            <span className="muted small">Comercio donde se confirmó</span>
            <input
              value={sourceCompany}
              onChange={e => setSourceCompany(e.target.value)}
              placeholder="p. ej. Mandados sv"
            />
          </label>
        </div>

        <p className="phase-note" style={{ marginTop: '0.6rem' }}>{TYPE_HINTS[type]}</p>
        {!canFuzzy && (
          <p className="muted small">
            Este tipo solo admite coincidencia exacta: un valor «parecido»
            simplemente es otro valor.
          </p>
        )}

        <label style={{ display: 'block', marginTop: '0.8rem' }}>
          <span className="muted small">Valores (uno por línea, o separados por comas)</span>
          <textarea
            value={values}
            onChange={e => setValues(e.target.value)}
            rows={4}
            placeholder={type === 'card_key'
              ? '411111-1234\n455555-9876'
              : 'fraude@example.com\notro@example.com'}
          />
        </label>

        <label style={{ display: 'block', marginTop: '0.6rem' }}>
          <input
            value={notes}
            onChange={e => setNotes(e.target.value)}
            placeholder="Nota (opcional) — número de caso, contexto…"
          />
        </label>

        <div className="row-actions" style={{ marginTop: '0.8rem' }}>
          <button className="btn" onClick={save} disabled={busy}>Guardar</button>
        </div>

        {saved && <div className="sync-confirm">{saved}</div>}
        {error && <div className="info-banner small">{error}</div>}
      </section>

      {/* ── List ─────────────────────────────────────────────────────
          Grouped by type rather than one flat table. The list is a
          reference someone scans looking for a KIND of thing ("did we ever
          add that email?"), and a single ordered list of every indicator
          answers that question worst of all.

          Values are masked by default: these are real people's emails, card
          numbers and phone numbers, and there is no reason for them to be
          readable over a shoulder while somebody scrolls. */}
      <section>
        <div className="report-header">
          <div>
            <h3 style={{ margin: 0 }}>
              {indicators === null ? 'Lista' : `${visible.length} indicadores`}
            </h3>
            {indicators !== null && (
              <p className="muted small" style={{ margin: '.2rem 0 0' }}>
                {withHits} {withHits === 1 ? 'ha coincidido' : 'han coincidido'} alguna vez
                {lastHit && ` · el último, el ${fmtDate(lastHit)}`}
              </p>
            )}
          </div>
          <button className="btn ghost small" onClick={() => setShowInactive(v => !v)}>
            {showInactive ? 'Ocultar desactivados' : 'Mostrar desactivados'}
          </button>
        </div>

        <input
          className="wl-search"
          placeholder="Buscar valor, comercio de origen o nota…"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />

        <div className="chip-filters">
          <button className={`chip-filter ${hitFilter === 'all' ? 'on' : ''}`}
                  onClick={() => setHitFilter('all')}>Todos</button>
          <button className={`chip-filter ${hitFilter === 'hits' ? 'on' : ''}`}
                  onClick={() => setHitFilter('hits')}>Con coincidencias {withHits}</button>
          <button className={`chip-filter ${hitFilter === 'nohits' ? 'on' : ''}`}
                  onClick={() => setHitFilter('nohits')}>Sin coincidencias {noHits}</button>
          <button className={`chip-filter ${unmasked ? 'on' : ''}`}
                  onClick={() => setUnmasked(v => !v)}>
            {unmasked ? 'Ocultar valores' : 'Mostrar valores'}
          </button>
        </div>

        {indicators === null && <p className="muted">Cargando…</p>}
        {indicators !== null && visible.length === 0 && (
          <p className="muted">
            {search ? 'Ningún indicador coincide con la búsqueda.'
                    : 'Todavía no hay indicadores registrados.'}
          </p>
        )}

        {grouped.map(([type, items]) => {
          const hits = items.filter(i => i.hit_count > 0).length;
          const collapsed = closed.has(type);
          return (
            <div className="ind-group" key={type}>
              <button className="ind-group-head"
                      onClick={() => setClosed(prev => {
                        const next = new Set(prev);
                        if (next.has(type)) next.delete(type); else next.add(type);
                        return next;
                      })}>
                <span className="ind-caret">{collapsed ? '▸' : '▾'}</span>
                <span className="ind-group-name">
                  {TYPE_LABELS[type as IndicatorType] || type}
                </span>
                <span className="ind-group-count">
                  {items.length}{hits > 0 && ` · ${hits} con coincidencias`}
                </span>
              </button>
              {!collapsed && items.map(ind => (
                <div className="ind-item" key={ind.id}
                     style={{ opacity: ind.active ? 1 : 0.55 }}>
                  <span className="mono ind-value" title={unmasked ? undefined : 'Pulsa «Mostrar valores»'}>
                    {unmasked ? ind.value_raw : maskValue(ind.value_raw)}
                  </span>
                  <span className={`ind-hits ${ind.hit_count > 0 ? 'on' : ''}`}>
                    {ind.hit_count > 0
                      ? `${ind.hit_count} ${ind.hit_count === 1 ? 'coincidencia' : 'coincidencias'}`
                      : '0'}
                  </span>
                  <span className="muted small ind-src">
                    {ind.source || '—'}
                    {ind.source_company_name ? ` · ${ind.source_company_name}` : ''}
                    {' · '}{fmtDate(ind.added_at)}
                  </span>
                  {ind.active ? (
                    <button className="btn ghost small" disabled={busy}
                            onClick={() => remove(ind)}>Desactivar</button>
                  ) : <span className="muted small">desactivado</span>}
                </div>
              ))}
            </div>
          );
        })}
      </section>
    </div>
    </main>
  );
}
