'use client';

// The watchlist, in the browser.
//
// Accepting a finding writes a merchant and its cards to tables migration 0001
// calls permanent and never pruned, and every later analysis reads them. Until
// now no web screen showed any of it: the reading code existed, but only in
// desktop/src/lib/, which .vercelignore forbids the web app from importing.
// So the most durable consequence of an analyst's decision was the one an
// analyst could not audit — unless they happened to be on the desktop app.
//
// It is worth more than a tidy-up. Findings accepted before the 2026-09
// evidence fix quoted the wrong rows, so some cards on this list were never
// the attacker's, and nothing prunes them. The people best placed to
// recognise that work in the browser.
//
// Queries come from shared/history.ts — the same ones the desktop runs. This
// page supplies the browser's Supabase client and nothing else. The RPCs are
// granted to `authenticated` (migration 0015), and the SELECT policies require
// a cubopago.com address, so the browser reaches exactly as far as the person
// signed into it.

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { createClient } from '@/lib/supabase/client';
import {
  listWatchlistMerchants, listWatchlistCards, listWatchlistIndicators,
  merchantHistory, setMerchantRemoved, setCardRemoved,
  type WatchlistMerchant, type WatchlistCard, type WatchlistIndicator,
  type DecidedFinding,
} from '@/shared/history';
import { fmtDay } from '@/shared/review';
import { verdictFor } from '@/shared/patterns';

type Tab = 'merchants' | 'cards' | 'indicators' | 'removed';

const TABS: [Tab, string][] = [
  ['merchants', 'Comercios'],
  ['cards', 'Tarjetas'],
  ['indicators', 'Indicadores'],
  ['removed', 'Retirados'],
];

export default function WatchlistPage() {
  const router = useRouter();
  const [tab, setTab] = useState<Tab>('merchants');
  const [search, setSearch] = useState('');
  const [email, setEmail] = useState<string>('');
  const [merchants, setMerchants] = useState<WatchlistMerchant[] | null>(null);
  const [cards, setCards] = useState<WatchlistCard[] | null>(null);
  const [indicators, setIndicators] = useState<WatchlistIndicator[] | null>(null);
  const [openMerchant, setOpenMerchant] = useState<string | null>(null);
  const [history, setHistory] = useState<Record<string, DecidedFinding[]>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setError('');
    const supabase = createClient();
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) {
      router.push('/login');
      return;
    }
    setEmail(session.user.email || '');
    try {
      if (tab === 'indicators') {
        setIndicators(await listWatchlistIndicators(supabase, { search }));
      } else if (tab === 'cards') {
        setCards(await listWatchlistCards(supabase, { search }));
      } else {
        setMerchants(await listWatchlistMerchants(supabase, {
          search, removed: tab === 'removed',
        }));
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [router, tab, search]);

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
        const supabase = createClient();
        const rows = await merchantHistory(supabase, next);
        setHistory(p => ({ ...p, [next]: rows }));
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    }
  }

  // Removal is soft on purpose: the row stays with who removed it and why, so
  // the decision is auditable rather than vanishing (migration 0014).
  async function removeMerchant(name: string, removed: boolean) {
    const reason = removed
      ? window.prompt(`¿Por qué se retira ${name} de la watchlist?`)
      : window.prompt(`¿Por qué se restaura ${name}?`);
    if (reason === null) return;                 // cancelled
    if (removed && !reason.trim()) {
      setError('Hace falta un motivo para retirar un comercio.');
      return;
    }
    setBusy(name);
    try {
      const supabase = createClient();
      await setMerchantRemoved(supabase, name, removed, email, reason.trim() || undefined);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  async function removeCard(bin: string, last4: string, removed: boolean) {
    const reason = window.prompt(
      removed ? `¿Por qué se retira la tarjeta ${bin}…${last4}?`
              : `¿Por qué se restaura la tarjeta ${bin}…${last4}?`);
    if (reason === null) return;
    if (removed && !reason.trim()) {
      setError('Hace falta un motivo para retirar una tarjeta.');
      return;
    }
    const key = `${bin}-${last4}`;
    setBusy(key);
    try {
      const supabase = createClient();
      await setCardRemoved(supabase, bin, last4, removed, email, reason.trim() || undefined);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <main className="container">
      <div className="topbar">
        <h2 style={{ margin: 0 }}>Watchlist</h2>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <Link href="/pendientes" className="signout">Pendientes</Link>
          <Link href="/historial" className="signout">Historial</Link>
          <Link href="/indicadores" className="signout">Indicadores</Link>
          <Link href="/" className="signout">Analizar</Link>
        </div>
      </div>

      <div className="card">
        <p className="muted" style={{ marginTop: 0 }}>
          Todo lo que el sistema ha guardado. Un comercio entra aquí cuando
          alguien confirma fraude; sale solo si alguien lo retira, y el registro
          se queda como constancia.
        </p>

        <input
          className="wl-search"
          style={{ width: '100%', padding: '0.5rem', marginBottom: '0.75rem' }}
          placeholder="Buscar comercio, tarjeta, BIN, correo, nombre…"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />

        <div style={{ display: 'flex', gap: '0.4rem', marginBottom: '0.75rem', flexWrap: 'wrap' }}>
          {TABS.map(([k, label]) => (
            <button
              key={k}
              className="signout"
              style={tab === k ? { background: 'var(--cubo-orange)', color: '#fff' } : undefined}
              onClick={() => setTab(k)}
            >
              {label}
            </button>
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
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.9rem' }}>
              <thead>
                <tr className="muted" style={{ textAlign: 'left' }}>
                  <th style={{ padding: '0.5rem 0.4rem' }}>Comercio</th>
                  <th style={{ padding: '0.5rem 0.4rem' }}>Veces confirmado</th>
                  <th style={{ padding: '0.5rem 0.4rem' }}>Primera vez</th>
                  <th style={{ padding: '0.5rem 0.4rem' }}>Última vez</th>
                  <th style={{ padding: '0.5rem 0.4rem' }}></th>
                </tr>
              </thead>
              <tbody>
                {merchants.map(m => (
                  <tr key={m.company_name} style={{ borderTop: '1px solid var(--border, #333)' }}>
                    <td style={{ padding: '0.5rem 0.4rem' }}>
                      <button
                        className="linklike"
                        style={{ background: 'none', border: 0, padding: 0, cursor: 'pointer', color: 'inherit', textAlign: 'left' }}
                        onClick={() => openHistory(m.company_name)}
                      >
                        <strong>{m.company_name}</strong>
                      </button>
                      {tab === 'removed' && m.removed_reason && (
                        <div className="muted" style={{ fontSize: '0.8rem' }}>
                          Retirado por {m.removed_by || '—'}: {m.removed_reason}
                        </div>
                      )}
                      {openMerchant === m.company_name && (
                        <div className="muted" style={{ fontSize: '0.8rem', marginTop: '0.4rem' }}>
                          {history[m.company_name] === undefined ? 'Cargando historial…' :
                           history[m.company_name].length === 0 ? 'Sin hallazgos registrados.' :
                           history[m.company_name].slice(0, 8).map(f => (
                             <div key={f.id}>
                               {fmtDay(f.first_seen_at)} · {verdictFor(f.finding_type)} · {f.review_status}
                             </div>
                           ))}
                        </div>
                      )}
                    </td>
                    {/* flag_count counts HUMAN confirmations only — the runner
                        never bumps it, so this is "how many times did someone
                        look at this and agree", not "how often did it fire". */}
                    <td style={{ padding: '0.5rem 0.4rem' }}>{m.flag_count}</td>
                    <td style={{ padding: '0.5rem 0.4rem' }}>{fmtDay(m.first_flagged)}</td>
                    <td style={{ padding: '0.5rem 0.4rem' }}>{fmtDay(m.last_flagged)}</td>
                    <td style={{ padding: '0.5rem 0.4rem', whiteSpace: 'nowrap' }}>
                      <button
                        className="signout"
                        disabled={busy === m.company_name}
                        onClick={() => removeMerchant(m.company_name, tab !== 'removed')}
                      >
                        {tab === 'removed' ? 'Restaurar' : 'Retirar'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        )}

        {tab === 'cards' && (
          cards === null ? <p className="muted">Cargando…</p> :
          cards.length === 0 ? (
            <p className="muted">
              {search ? 'Ninguna tarjeta coincide.' : 'No hay tarjetas en la watchlist.'}
            </p>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.9rem' }}>
              <thead>
                <tr className="muted" style={{ textAlign: 'left' }}>
                  <th style={{ padding: '0.5rem 0.4rem' }}>Tarjeta</th>
                  <th style={{ padding: '0.5rem 0.4rem' }}>Veces confirmada</th>
                  <th style={{ padding: '0.5rem 0.4rem' }}>Primera vez</th>
                  <th style={{ padding: '0.5rem 0.4rem' }}>Última vez</th>
                  <th style={{ padding: '0.5rem 0.4rem' }}></th>
                </tr>
              </thead>
              <tbody>
                {cards.map(c => (
                  <tr key={c.card_key} style={{ borderTop: '1px solid var(--border, #333)' }}>
                    {/* BIN + last four. Neither half identifies a card on its
                        own — a BIN is an entire issuing bank — which is why
                        the engine never stores or matches them separately. */}
                    <td style={{ padding: '0.5rem 0.4rem' }}>
                      <code>{c.bin} ···· {c.last4}</code>
                      {c.removed_at && (
                        <div className="muted" style={{ fontSize: '0.8rem' }}>
                          Retirada por {c.removed_by || '—'}
                          {c.removed_reason ? `: ${c.removed_reason}` : ''}
                        </div>
                      )}
                    </td>
                    <td style={{ padding: '0.5rem 0.4rem' }}>{c.flag_count}</td>
                    <td style={{ padding: '0.5rem 0.4rem' }}>{fmtDay(c.first_flagged)}</td>
                    <td style={{ padding: '0.5rem 0.4rem' }}>{fmtDay(c.last_flagged)}</td>
                    <td style={{ padding: '0.5rem 0.4rem', whiteSpace: 'nowrap' }}>
                      <button
                        className="signout"
                        disabled={busy === `${c.bin}-${c.last4}`}
                        onClick={() => removeCard(c.bin, c.last4, !c.removed_at)}
                      >
                        {c.removed_at ? 'Restaurar' : 'Retirar'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        )}

        {tab === 'indicators' && (
          indicators === null ? <p className="muted">Cargando…</p> :
          indicators.length === 0 ? (
            <p className="muted">
              {search ? 'Ningún indicador coincide.' : 'No hay indicadores confirmados.'}
            </p>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.9rem' }}>
              <thead>
                <tr className="muted" style={{ textAlign: 'left' }}>
                  <th style={{ padding: '0.5rem 0.4rem' }}>Tipo</th>
                  <th style={{ padding: '0.5rem 0.4rem' }}>Valor</th>
                  <th style={{ padding: '0.5rem 0.4rem' }}>Confirmado en</th>
                  <th style={{ padding: '0.5rem 0.4rem' }}>Coincidencias</th>
                </tr>
              </thead>
              <tbody>
                {indicators.map(i => (
                  <tr key={i.id} style={{ borderTop: '1px solid var(--border, #333)' }}>
                    <td style={{ padding: '0.5rem 0.4rem' }}>{i.indicator_type}</td>
                    <td style={{ padding: '0.5rem 0.4rem' }}><code>{i.value_raw}</code></td>
                    <td style={{ padding: '0.5rem 0.4rem' }}>{i.source_company_name || '—'}</td>
                    <td style={{ padding: '0.5rem 0.4rem' }}>
                      {i.hit_count}
                      {i.last_hit_at && (
                        <span className="muted"> · {fmtDay(i.last_hit_at)}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        )}
      </div>
    </main>
  );
}
