'use client';

import { useEffect, useState, useCallback } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { createClient } from '@/lib/supabase/client';

type Indicator = {
  id: string;
  indicator_type: string;
  value_raw: string;
  value_norm: string;
  match_mode: 'exact' | 'fuzzy' | 'both';
  source: string | null;
  source_company_name: string | null;
  notes: string | null;
  added_by_email: string;
  added_at: string;
  active: boolean;
  expires_at: string | null;
  hit_count: number;
  last_hit_at: string | null;
  last_hit_company: string | null;
};

type PreviewRow = {
  value_raw: string;
  value_norm: string | null;
  ok: boolean;
  reason: string | null;
  evidence_hits: number | null;
};

// Spanish labels for the indicator types. Keys mirror
// analyze.py:INDICATOR_SOURCE_COLUMNS — keep them in step.
const TYPE_LABELS: Record<string, string> = {
  card_key:     'Tarjeta (BIN + últimos 4)',
  email:        'Correo electrónico',
  email_domain: 'Dominio de correo',
  phone:        'Teléfono',
  ip:           'Dirección IP',
  person_name:  'Nombre de persona',
  company_name: 'Nombre de comercio',
  company_id:   'ID de comercio',
};

// What each type is for, shown under the picker so the analyst chooses well.
const TYPE_HINTS: Record<string, string> = {
  card_key:     'BIN y últimos 4 juntos, p. ej. «411111-1234» o «411111 1234». '
              + 'Cualquiera de los dos por separado genera demasiadas coincidencias: '
              + 'el BIN es todo un banco emisor y los últimos 4 son 1 de cada 10,000. '
              + 'No registres el número completo — no se almacena.',
  email:        'El correo del pagador. Se ignoran los +etiquetas y, en Gmail, los puntos.',
  email_domain: 'Todo un dominio. No se permiten dominios públicos como gmail.com.',
  phone:        'Se comparan los últimos 8 dígitos, así el código de país no importa.',
  ip:           'La IP del dispositivo. Considera que caduque: las IP cambian de dueño.',
  person_name:  'Nombre completo. Se compara contra el tarjetahabiente y el pagador.',
  company_name: 'Nombre del comercio, sin la razón social (S.A., Ltda.).',
  company_id:   'El identificador interno del comercio.',
};

const SOURCES = ['contracargo', 'revisión de ops', 'reporte bancario', 'otro'];

const fmtDate = (iso: string | null) => (iso ? iso.slice(0, 10) : '—');

export default function IndicadoresPage() {
  const router = useRouter();

  const [indicators, setIndicators] = useState<Indicator[] | null>(null);
  const [types, setTypes] = useState<string[]>([]);
  const [fuzzyCapable, setFuzzyCapable] = useState<string[]>([]);
  const [fuzzyScoringEnabled, setFuzzyScoringEnabled] = useState(false);
  const [showInactive, setShowInactive] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  // Form
  const [type, setType] = useState('email');
  const [values, setValues] = useState('');
  const [matchMode, setMatchMode] = useState<'exact' | 'fuzzy' | 'both'>('exact');
  const [source, setSource] = useState(SOURCES[0]);
  const [sourceCompany, setSourceCompany] = useState('');
  const [notes, setNotes] = useState('');
  const [preview, setPreview] = useState<PreviewRow[] | null>(null);
  const [saved, setSaved] = useState('');

  const authedFetch = useCallback(async (input: string, init?: RequestInit) => {
    const supabase = createClient();
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) {
      router.push('/login');
      return null;
    }
    return fetch(input, {
      ...init,
      headers: {
        ...(init?.headers || {}),
        Authorization: `Bearer ${session.access_token}`,
      },
    });
  }, [router]);

  const load = useCallback(async () => {
    setError('');
    const res = await authedFetch(`/api/indicators?include_inactive=${showInactive ? 1 : 0}`);
    if (!res) return;
    if (res.status === 401) { router.push('/login'); return; }
    const json = await res.json();
    if (!res.ok) { setError(json.error || `El servidor respondió con ${res.status}`); return; }
    setIndicators(json.indicators || []);
    setTypes(json.types || []);
    setFuzzyCapable(json.fuzzy_capable || []);
    setFuzzyScoringEnabled(!!json.fuzzy_scoring_enabled);
  }, [authedFetch, router, showInactive]);

  useEffect(() => { load(); }, [load]);

  // Switching to a type that can't do fuzzy must not leave a stale mode.
  useEffect(() => {
    if (matchMode !== 'exact' && !fuzzyCapable.includes(type)) setMatchMode('exact');
  }, [type, fuzzyCapable, matchMode]);

  const valueList = () =>
    values.split(/[\n,;]+/).map(v => v.trim()).filter(Boolean);

  async function runPreview() {
    const list = valueList();
    if (list.length === 0) { setError('Escribe al menos un valor.'); return; }
    setError(''); setBusy(true); setSaved('');
    try {
      const res = await authedFetch('/api/indicators', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'preview', indicator_type: type, values: list }),
      });
      if (!res) return;
      const json = await res.json();
      if (!res.ok) { setError(json.error || 'La verificación falló'); return; }
      setPreview(json.preview || []);
    } catch (e: any) {
      setError(e?.message || 'La verificación falló');
    } finally {
      setBusy(false);
    }
  }

  async function save() {
    const list = valueList();
    if (list.length === 0) { setError('Escribe al menos un valor.'); return; }
    setError(''); setBusy(true);
    try {
      const res = await authedFetch('/api/indicators', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'create',
          indicator_type: type,
          values: list,
          match_mode: matchMode,
          source,
          source_company_name: sourceCompany || null,
          notes: notes || null,
        }),
      });
      if (!res) return;
      const json = await res.json();
      if (!res.ok) { setError(json.error || 'No se pudo guardar'); return; }

      const n = (json.inserted || []).length;
      const rejected = json.rejected || [];
      setSaved(
        `${n} indicador${n === 1 ? '' : 'es'} guardado${n === 1 ? '' : 's'}` +
        (rejected.length ? ` · ${rejected.length} rechazado${rejected.length === 1 ? '' : 's'}` : ''),
      );
      if (rejected.length) {
        setError(rejected.map((r: any) => `«${r.value_raw}»: ${r.reason}`).join(' · '));
      }
      setValues(''); setPreview(null);
      load();
    } catch (e: any) {
      setError(e?.message || 'No se pudo guardar');
    } finally {
      setBusy(false);
    }
  }

  async function deactivate(id: string) {
    const reason = window.prompt('¿Por qué se desactiva? (opcional)') ?? '';
    setBusy(true); setError('');
    try {
      const res = await authedFetch('/api/indicators', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'deactivate', id, reason }),
      });
      if (!res) return;
      const json = await res.json();
      if (!res.ok) { setError(json.error || 'No se pudo desactivar'); return; }
      load();
    } finally {
      setBusy(false);
    }
  }

  const canFuzzy = fuzzyCapable.includes(type);

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
          <Link href="/historial" className="signout">Historial</Link>
        </div>
      </header>

      <div className="container">
        <div className="card">
          <h2 style={{ marginTop: 0 }}>Indicadores de fraude confirmado</h2>
          <p className="muted" style={{ marginTop: 0 }}>
            Datos que el equipo ya confirmó como fraude — un correo de un contracargo,
            un nombre de un reporte bancario, la IP de un caso anterior. Cada análisis
            se compara contra esta lista. Cuando un valor confirmado en un comercio
            aparece en <strong>otro comercio distinto</strong>, el hallazgo se marca
            como Critical automáticamente.
          </p>
          <p className="muted" style={{ marginTop: '0.5rem', marginBottom: 0, fontSize: '0.88rem' }}>
            Esta lista contiene datos personales. Registra solo lo que esté confirmado
            y desactiva lo que deje de ser relevante.
          </p>
        </div>

        {/* ── Add form ─────────────────────────────────────────────── */}
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Agregar indicadores</h3>

          <div style={{ display: 'grid', gap: '0.9rem', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))' }}>
            <label>
              <div className="muted" style={{ fontSize: '0.85rem', marginBottom: '0.25rem' }}>Tipo de dato</div>
              <select
                value={type}
                onChange={e => { setType(e.target.value); setPreview(null); }}
                style={{ width: '100%', padding: '0.5rem', borderRadius: 8, border: '1px solid var(--border)' }}
              >
                {(types.length ? types : Object.keys(TYPE_LABELS)).map(t => (
                  <option key={t} value={t}>{TYPE_LABELS[t] || t}</option>
                ))}
              </select>
            </label>

            <label>
              <div className="muted" style={{ fontSize: '0.85rem', marginBottom: '0.25rem' }}>Cómo comparar</div>
              <select
                value={matchMode}
                onChange={e => setMatchMode(e.target.value as any)}
                disabled={!canFuzzy}
                style={{ width: '100%', padding: '0.5rem', borderRadius: 8, border: '1px solid var(--border)' }}
              >
                <option value="exact">Exacta — marca Critical</option>
                {canFuzzy && <option value="both">Exacta + aproximada</option>}
                {canFuzzy && <option value="fuzzy">Solo aproximada</option>}
              </select>
            </label>

            <label>
              <div className="muted" style={{ fontSize: '0.85rem', marginBottom: '0.25rem' }}>Fuente</div>
              <select
                value={source}
                onChange={e => setSource(e.target.value)}
                style={{ width: '100%', padding: '0.5rem', borderRadius: 8, border: '1px solid var(--border)' }}
              >
                {SOURCES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </label>

            <label>
              <div className="muted" style={{ fontSize: '0.85rem', marginBottom: '0.25rem' }}>
                Comercio donde se confirmó
              </div>
              <input
                value={sourceCompany}
                onChange={e => setSourceCompany(e.target.value)}
                placeholder="p. ej. Mandados sv"
                style={{ width: '100%', padding: '0.5rem', borderRadius: 8, border: '1px solid var(--border)' }}
              />
            </label>
          </div>

          <p className="muted" style={{ fontSize: '0.85rem', margin: '0.6rem 0 0' }}>
            {TYPE_HINTS[type]}
          </p>
          {!canFuzzy && (
            <p className="muted" style={{ fontSize: '0.85rem', margin: '0.3rem 0 0' }}>
              Este tipo solo admite coincidencia exacta: un valor «parecido» simplemente
              es otro valor.
            </p>
          )}
          {matchMode !== 'exact' && !fuzzyScoringEnabled && (
            <p className="muted" style={{ fontSize: '0.85rem', margin: '0.3rem 0 0' }}>
              Las coincidencias aproximadas se reportan en el hallazgo, pero todavía no
              suman al puntaje — quedan activas cuando se recalibren los pesos del motor.
            </p>
          )}

          <div style={{ marginTop: '0.9rem' }}>
            <div className="muted" style={{ fontSize: '0.85rem', marginBottom: '0.25rem' }}>
              Valores (uno por línea, o separados por comas)
            </div>
            <textarea
              value={values}
              onChange={e => { setValues(e.target.value); setPreview(null); }}
              rows={4}
              placeholder={type === 'card_key'
                ? '411111-1234\n455555-9876'
                : 'fraude@example.com\notro@example.com'}
              style={{
                width: '100%', padding: '0.6rem', borderRadius: 8,
                border: '1px solid var(--border)', fontFamily: 'inherit', fontSize: '0.95rem',
              }}
            />
          </div>

          <div style={{ marginTop: '0.7rem' }}>
            <input
              value={notes}
              onChange={e => setNotes(e.target.value)}
              placeholder="Nota (opcional) — número de caso, contexto…"
              style={{ width: '100%', padding: '0.5rem', borderRadius: 8, border: '1px solid var(--border)' }}
            />
          </div>

          <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.9rem', flexWrap: 'wrap' }}>
            <button className="signout" onClick={runPreview} disabled={busy}>
              Verificar antes de guardar
            </button>
            <button className="signout" onClick={save} disabled={busy}>
              Guardar
            </button>
          </div>

          {saved && <div className="success" style={{ marginTop: '0.8rem' }}>{saved}</div>}
          {error && <div className="error" style={{ marginTop: '0.8rem' }}>{error}</div>}

          {preview && (
            <div style={{ marginTop: '1rem' }}>
              <div className="muted" style={{ fontSize: '0.85rem', marginBottom: '0.4rem' }}>
                Verificación — así quedará cada valor:
              </div>
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.88rem' }}>
                  <thead>
                    <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--border)' }}>
                      <th style={{ padding: '0.4rem' }}>Valor</th>
                      <th style={{ padding: '0.4rem' }}>Normalizado</th>
                      <th style={{ padding: '0.4rem' }}>En evidencia</th>
                      <th style={{ padding: '0.4rem' }}>Estado</th>
                    </tr>
                  </thead>
                  <tbody>
                    {preview.map((r, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                        <td style={{ padding: '0.4rem' }}>{r.value_raw}</td>
                        <td style={{ padding: '0.4rem', fontFamily: 'monospace', fontSize: '0.85rem' }}>
                          {r.value_norm || '—'}
                        </td>
                        <td style={{ padding: '0.4rem' }}>
                          {r.evidence_hits == null ? '—' : r.evidence_hits}
                        </td>
                        <td style={{ padding: '0.4rem' }}>
                          {r.ok
                            ? <span className="tag" style={{ background: 'rgba(0,201,167,0.15)', color: 'var(--cubo-teal)' }}>Válido</span>
                            : <span className="muted">{r.reason}</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="muted" style={{ fontSize: '0.8rem', marginTop: '0.5rem', marginBottom: 0 }}>
                «En evidencia» cuenta apariciones en los hallazgos guardados. Las
                transacciones nunca se almacenan, así que un 0 significa «no aparece en
                lo que conservamos», no «nunca ocurrió».
              </p>
            </div>
          )}
        </div>

        {/* ── List ─────────────────────────────────────────────────── */}
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
            <h3 style={{ margin: 0 }}>
              Lista {indicators ? `(${indicators.length})` : ''}
            </h3>
            <button className="signout" onClick={() => setShowInactive(v => !v)}>
              {showInactive ? 'Ocultar desactivados' : 'Mostrar desactivados'}
            </button>
          </div>

          {indicators === null && <p className="muted">Cargando…</p>}
          {indicators !== null && indicators.length === 0 && (
            <p className="muted" style={{ marginBottom: 0 }}>
              Todavía no hay indicadores registrados.
            </p>
          )}

          {indicators !== null && indicators.length > 0 && (
            <div style={{ overflowX: 'auto', marginTop: '0.8rem' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.9rem' }}>
                <thead>
                  <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--border)' }}>
                    <th style={{ padding: '0.5rem 0.4rem' }}>Tipo</th>
                    <th style={{ padding: '0.5rem 0.4rem' }}>Valor</th>
                    <th style={{ padding: '0.5rem 0.4rem' }}>Confirmado en</th>
                    <th style={{ padding: '0.5rem 0.4rem' }}>Coincidencias</th>
                    <th style={{ padding: '0.5rem 0.4rem' }}>Registrado</th>
                    <th style={{ padding: '0.5rem 0.4rem' }}></th>
                  </tr>
                </thead>
                <tbody>
                  {indicators.map(ind => (
                    <tr key={ind.id} style={{ borderBottom: '1px solid var(--border)', opacity: ind.active ? 1 : 0.55 }}>
                      <td style={{ padding: '0.5rem 0.4rem' }}>
                        {TYPE_LABELS[ind.indicator_type] || ind.indicator_type}
                        {ind.match_mode !== 'exact' && (
                          <span className="tag" style={{ marginLeft: '0.4rem' }}>{ind.match_mode}</span>
                        )}
                      </td>
                      <td style={{ padding: '0.5rem 0.4rem', fontFamily: 'monospace', fontSize: '0.85rem' }}>
                        {ind.value_raw}
                      </td>
                      <td style={{ padding: '0.5rem 0.4rem' }}>
                        {ind.source_company_name || <span className="muted">—</span>}
                        {ind.source && <div className="muted" style={{ fontSize: '0.78rem' }}>{ind.source}</div>}
                      </td>
                      <td style={{ padding: '0.5rem 0.4rem' }}>
                        {ind.hit_count > 0 ? (
                          <>
                            <strong>{ind.hit_count}</strong>
                            {ind.last_hit_company && (
                              <div className="muted" style={{ fontSize: '0.78rem' }}>
                                último: {ind.last_hit_company}
                              </div>
                            )}
                          </>
                        ) : <span className="muted">0</span>}
                      </td>
                      <td style={{ padding: '0.5rem 0.4rem' }}>
                        {fmtDate(ind.added_at)}
                        <div className="muted" style={{ fontSize: '0.78rem' }}>{ind.added_by_email}</div>
                      </td>
                      <td style={{ padding: '0.5rem 0.4rem', textAlign: 'right' }}>
                        {ind.active ? (
                          <button className="signout" disabled={busy} onClick={() => deactivate(ind.id)}>
                            Desactivar
                          </button>
                        ) : (
                          <span className="muted" style={{ fontSize: '0.8rem' }}>desactivado</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
