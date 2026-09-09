// Plain-Spanish names for everything the engine emits in codes.
//
// Why this lives in the app and not in analyze.py
// ───────────────────────────────────────────────
// The engine already writes Spanish, in build_description_es(). Three things
// go wrong on the way to a screen: it joins every sentence into one paragraph,
// it is half in English ("amount ladder", "REPEAT OFFENDER", "flaggeado",
// "retry", "fencing"), and nothing connects a tag to the sentence explaining
// it — you get a row of codes and, separately, a wall of prose.
//
// Fixing that in the engine would mean editing analyze.py, which the desktop
// app carries as a FROZEN PyInstaller snapshot: a wording change would force a
// sidecar rebuild and put scoring logic in the blast radius. So the engine
// keeps emitting stable codes and this file owns the words. One dictionary,
// both clients, changeable without touching fraud detection.
//
// tests/test_pattern_dictionary.py reads analyze.py and fails if the engine
// can emit a code that is missing here — otherwise a new detector would show
// up in front of an analyst as `bin_diversity_burst`.

export type Pattern = {
  /** Two or three words. Goes on the chip. */
  label: string;
  /** One sentence, for someone who is not an engineer. */
  explain: string;
};

export const PATTERNS: Record<string, Pattern> = {
  amount_ladder: {
    label: 'Escalera de montos',
    explain:
      'Tres o más intentos seguidos con la misma tarjeta subiendo o bajando ' +
      'el monto en menos de 20 minutos. Es la forma clásica de probar hasta ' +
      'dónde pasa una tarjeta robada.',
  },
  velocity_burst: {
    label: 'Ráfaga de intentos',
    explain:
      'Muchas más transacciones por minuto de las normales para este comercio.',
  },
  round_number_repetition: {
    label: 'Montos redondos',
    explain:
      'El mismo monto exacto repetido muchas veces, típico de pruebas ' +
      'automatizadas más que de compras reales.',
  },
  bin_diversity_burst: {
    label: 'Muchos bancos distintos',
    explain:
      'Tarjetas de muchos bancos diferentes en poco tiempo. Un comercio real ' +
      'no recibe esa mezcla.',
  },
  high_reject_rate: {
    label: 'Rechazos muy altos',
    explain:
      'Una proporción de rechazos muy por encima de lo normal para el volumen ' +
      'de este comercio.',
  },
  critical_codes: {
    label: 'Rechazos por fraude',
    explain:
      'Rechazos con códigos que la red de tarjetas asocia directamente a ' +
      'fraude (05, 63, 43, SM).',
  },
  minfraud_blocked: {
    label: 'Bloqueado por MinFraud',
    explain:
      'El proveedor antifraude bloqueó estos intentos por su cuenta, antes de ' +
      'que llegaran al banco.',
  },
  watchlist_merchant: {
    label: 'Reincidente',
    explain:
      'Este comercio ya había sido marcado como crítico en los últimos 90 días.',
  },
  watchlist_card: {
    label: 'Tarjeta ya marcada',
    explain:
      'Una tarjeta que ya estaba en la watchlist vuelve a aparecer aquí.',
  },
  cross_merchant_reuse: {
    label: 'Tarjeta compartida',
    explain:
      'La misma tarjeta aparece en varios comercios distintos, lo que sugiere ' +
      'que no es un cliente sino una tarjeta circulando.',
  },
  channel_switch_retry: {
    label: 'Reintento por otro canal',
    explain:
      'Después de un rechazo por fraude, volvió a intentar el cobro por un ' +
      'canal diferente para esquivar el bloqueo.',
  },
  real_name_rotation: {
    label: 'Identidades rotativas',
    explain:
      'La misma tarjeta usada con tres o más nombres, correos o teléfonos ' +
      'distintos.',
  },
  multi_test_transactions: {
    label: 'Cobros de prueba',
    explain:
      'Varios cobros de un dólar o menos, para ver si la tarjeta responde ' +
      'antes de intentar un monto real.',
  },
  foreign_card_velocity: {
    label: 'Tarjetas extranjeras',
    explain:
      'Muchas tarjetas de países distintos en pocas horas.',
  },
  confirmed_indicator_exact: {
    label: 'Fraude confirmado',
    explain:
      'Coincide exactamente con un dato que el equipo ya confirmó como fraude.',
  },
  confirmed_indicator_cross_merchant: {
    label: 'Confirmado en otro comercio',
    explain:
      'El dato viene de un fraude confirmado en un comercio distinto — la ' +
      'señal más fuerte que produce el motor.',
  },
  confirmed_indicator_fuzzy: {
    label: 'Parecido a fraude confirmado',
    explain:
      'Se parece mucho a un dato de fraude confirmado, sin ser idéntico.',
  },
};

/** The one-line verdict, from `finding_type`. Mirrors classify_finding_type(). */
export const VERDICTS: Record<string, string> = {
  card_testing:    'Prueba de tarjetas',
  ring:            'Posible red de tarjetas',
  channel_switch:  'Reintento tras rechazo por fraude',
  repeat_offender: 'Reincidente',
  general_fraud:   'Patrón de fraude',
};

/** Recommended action, from `action_code`. Mirrors decide_action(). */
export const ACTIONS: Record<string, string> = {
  FREEZE_MERCHANT:  'Congelar el comercio',
  REVIEW_CHARGE:    'Revisar el cobro',
  INVESTIGATE_RING: 'Investigar una posible red',
};

/**
 * A code the dictionary does not know still has to render.
 *
 * The engine can grow a detector without this file being updated. A missing
 * entry should look like an untranslated tag, not a blank space and not a
 * crash — and the contract test will catch it before it ships.
 */
export function describePattern(code: string): Pattern {
  return PATTERNS[code] || { label: code, explain: '' };
}

export function verdictFor(findingType: string | null | undefined): string {
  if (!findingType) return 'Patrón de fraude';
  return VERDICTS[findingType] || 'Patrón de fraude';
}

export function actionFor(actionCode: string | null | undefined): string | null {
  if (!actionCode) return null;
  return ACTIONS[actionCode] || null;
}

/**
 * Patterns worth putting in front of someone, strongest first.
 *
 * A confirmed-fraud match outranks everything — it is not a heuristic, it is a
 * value the team has already seen do damage. After that, evidence about
 * behaviour beats evidence about volume.
 */
const RANK = [
  'confirmed_indicator_cross_merchant',
  'confirmed_indicator_exact',
  'confirmed_indicator_fuzzy',
  'watchlist_merchant',
  'watchlist_card',
  'cross_merchant_reuse',
  'channel_switch_retry',
  'amount_ladder',
  'real_name_rotation',
  'multi_test_transactions',
  'bin_diversity_burst',
  'foreign_card_velocity',
  'velocity_burst',
  'round_number_repetition',
  'critical_codes',
  'minfraud_blocked',
  'high_reject_rate',
];

export function rankPatterns(codes: string[]): string[] {
  const seen = new Set<string>();
  const unique = codes.filter(c => (seen.has(c) ? false : seen.add(c)));
  return unique.sort((a, b) => {
    const ia = RANK.indexOf(a), ib = RANK.indexOf(b);
    // Unknown codes sort last rather than first: they are the ones with no
    // explanation to show, so they should not lead.
    return (ia < 0 ? 999 : ia) - (ib < 0 ? 999 : ib);
  });
}
