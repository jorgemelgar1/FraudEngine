import { supabase } from './supabase';

// Confirmed-fraud indicators — values the team has verified are linked to
// fraud (an email from a chargeback, a name from a bank notice, an IP from a
// previous case). The engine matches every analyzed CSV against them.
//
// The desktop talks to Supabase directly under the user's JWT, so this file
// is the counterpart to api/indicators.py rather than a client for it. The
// two must agree on shape — see LIST_SELECT below and _LIST_SELECT there.

const LIST_SELECT = [
  'id',
  'indicator_type',
  'value_raw',
  'value_norm',
  'match_mode',
  'source',
  'source_company_name',
  'notes',
  'added_by_email',
  'added_at',
  'active',
  'expires_at',
  'hit_count',
  'last_hit_at',
  'last_hit_company',
].join(',');

// No 'card_bin' or 'card_last4': a card is always BIN + last 4 together.
// Either half alone matches far too much — a BIN is an entire issuing bank,
// and last-4 is one in ten thousand.
export type IndicatorType =
  | 'card_key' | 'email' | 'email_domain'
  | 'phone' | 'ip' | 'person_name' | 'company_name' | 'company_id';

export type MatchMode = 'exact' | 'fuzzy' | 'both';

export type Indicator = {
  id: string;
  indicator_type: IndicatorType;
  value_raw: string;
  value_norm: string;
  match_mode: MatchMode;
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

// Types where a near match is meaningful. Mirrors
// analyze.py:FUZZY_CAPABLE_TYPES — a "nearly right" card_key is simply a
// different card, so offering fuzzy there would be misleading.
export const FUZZY_CAPABLE: IndicatorType[] = [
  'email', 'person_name', 'company_name', 'ip',
];

export const TYPE_LABELS: Record<IndicatorType, string> = {
  card_key:     'Tarjeta (BIN + últimos 4)',
  email:        'Correo electrónico',
  email_domain: 'Dominio de correo',
  phone:        'Teléfono',
  ip:           'Dirección IP',
  person_name:  'Nombre de persona',
  company_name: 'Nombre de comercio',
  company_id:   'ID de comercio',
};

export const TYPE_HINTS: Record<IndicatorType, string> = {
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

/**
 * Active indicators, shaped the way analyze.py expects them.
 *
 * Fetched fresh before each analysis rather than cached: unlike the
 * watchlist, this list is edited by hand and a stale copy would mean missing
 * a value someone added minutes ago. The explicit limit overrides
 * PostgREST's 1000-row default, for the same reason the watchlist fetch has
 * one — silently dropping indicators means silently missing confirmed fraud.
 */
export async function fetchActiveIndicators(): Promise<Indicator[]> {
  const { data, error } = await supabase
    .from('fraud_indicators')
    .select(LIST_SELECT)
    .eq('active', true)
    .limit(100000);
  if (error) throw new Error(`fetchActiveIndicators: ${error.message}`);
  return (data as unknown as Indicator[]) || [];
}

export async function listIndicators(includeInactive: boolean): Promise<Indicator[]> {
  let q = supabase
    .from('fraud_indicators')
    .select(LIST_SELECT)
    .order('added_at', { ascending: false })
    .limit(2000);
  if (!includeInactive) q = q.eq('active', true);
  const { data, error } = await q;
  if (error) throw new Error(`listIndicators: ${error.message}`);
  return (data as unknown as Indicator[]) || [];
}

export type NewIndicator = {
  indicator_type: IndicatorType;
  values: string[];
  match_mode: MatchMode;
  source: string | null;
  source_company_name: string | null;
  notes: string | null;
};

/**
 * Insert one or more indicators.
 *
 * `value_norm` is deliberately not sent: a BEFORE INSERT trigger computes it
 * (migration 0008). That is what keeps this client and the Vercel function
 * from splitting one indicator into two rows by normalizing differently —
 * exactly the drift the two-client comment in findings.ts warns about.
 * Precise matching normalization lives in analyze.py and is re-derived from
 * value_raw on every run.
 */
export async function createIndicators(
  input: NewIndicator,
  userEmail: string,
): Promise<number> {
  const seen = new Set<string>();
  const rows = input.values
    .map(v => v.trim())
    .filter(v => {
      if (!v || seen.has(v.toLowerCase())) return false;
      seen.add(v.toLowerCase());
      return true;
    })
    .map(v => ({
      indicator_type:      input.indicator_type,
      value_raw:           v,
      match_mode:          input.match_mode,
      source:              input.source,
      source_company_name: input.source_company_name,
      notes:               input.notes,
      added_by_email:      userEmail,
      active:              true,
    }));

  if (rows.length === 0) return 0;

  const { error } = await supabase
    .from('fraud_indicators')
    .upsert(rows, { onConflict: 'indicator_type,value_norm' });
  if (error) throw new Error(`createIndicators: ${error.message}`);
  return rows.length;
}

export async function deactivateIndicator(
  id: string,
  userEmail: string,
  reason: string,
): Promise<void> {
  const { error } = await supabase.rpc('deactivate_indicator', {
    p_indicator_id: id,
    p_user_email:   userEmail,
    p_reason:       reason || null,
  });
  if (error) throw new Error(`deactivate_indicator: ${error.message}`);
}

/**
 * Bump hit counts for the indicators that fired during a run.
 *
 * Best-effort: the analysis already succeeded and the report is on screen,
 * so a bookkeeping failure must never surface as an error to the user. One
 * RPC per merchant keeps it to a handful of calls.
 */
export async function recordIndicatorHits(
  matches: Array<{ company_name: string; hits: Array<{ indicator_id: string }> }>,
): Promise<void> {
  for (const match of matches) {
    const ids = Array.from(
      new Set(match.hits.map(h => h.indicator_id).filter(Boolean)),
    );
    if (ids.length === 0) continue;
    const { error } = await supabase.rpc('record_indicator_hits', {
      p_indicator_ids: ids,
      p_company_name:  match.company_name,
    });
    if (error) {
      // Log the shape, never the values.
      console.warn('[indicators] hit recording failed:', error.message);
      return;
    }
  }
}
