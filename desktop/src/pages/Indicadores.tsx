import { useCallback, useEffect, useState } from 'react';
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

  if (!online) {
    return (
      <div className="report">
        <h2>Indicadores de fraude confirmado</h2>
        <div className="info-banner">
          Necesitas conexión para ver y editar los indicadores. La lista es
          compartida con todo el equipo, así que no se guarda una copia local.
        </div>
      </div>
    );
  }

  return (
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

      {/* ── List ─────────────────────────────────────────────────── */}
      <section>
        <div className="report-header">
          <h3 style={{ margin: 0 }}>
            Lista {indicators ? `(${indicators.length})` : ''}
          </h3>
          <button className="btn ghost small" onClick={() => setShowInactive(v => !v)}>
            {showInactive ? 'Ocultar desactivados' : 'Mostrar desactivados'}
          </button>
        </div>

        {indicators === null && <p className="muted">Cargando…</p>}
        {indicators !== null && indicators.length === 0 && (
          <p className="muted">Todavía no hay indicadores registrados.</p>
        )}

        {indicators !== null && indicators.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Tipo</th>
                  <th>Valor</th>
                  <th>Confirmado en</th>
                  <th>Coincidencias</th>
                  <th>Registrado</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {indicators.map(ind => (
                  <tr key={ind.id} style={{ opacity: ind.active ? 1 : 0.55 }}>
                    <td>
                      {TYPE_LABELS[ind.indicator_type] || ind.indicator_type}
                      {ind.match_mode !== 'exact' && (
                        <span className="tag" style={{ marginLeft: '0.4rem' }}>{ind.match_mode}</span>
                      )}
                    </td>
                    <td className="mono">{ind.value_raw}</td>
                    <td>
                      {ind.source_company_name || <span className="muted">—</span>}
                      {ind.source && <div className="muted small">{ind.source}</div>}
                    </td>
                    <td>
                      {ind.hit_count > 0 ? (
                        <>
                          <strong>{ind.hit_count}</strong>
                          {ind.last_hit_company && (
                            <div className="muted small">último: {ind.last_hit_company}</div>
                          )}
                        </>
                      ) : <span className="muted">0</span>}
                    </td>
                    <td>
                      {fmtDate(ind.added_at)}
                      <div className="muted small">{ind.added_by_email}</div>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      {ind.active ? (
                        <button className="btn ghost small" disabled={busy} onClick={() => remove(ind)}>
                          Desactivar
                        </button>
                      ) : (
                        <span className="muted small">desactivado</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
