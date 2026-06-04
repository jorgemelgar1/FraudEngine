#!/usr/bin/env python3
"""Generate a synthetic transaction CSV reproducing the two operations-confirmed
fraud merchants (Mandados sv, Inversiones Kabu) plus benign controls, so the
suspicious-rejected-merchant detector can be validated deterministically.

This does NOT contain real cardholder data — every value is fabricated.

Run:  python tests/make_fixtures.py   -> writes tests/fixtures/synthetic.csv
"""
import csv
import os
from datetime import datetime, timedelta

COLUMNS = [
    'transaction_id', 'company_name', 'company_id', 'amount', 'status',
    'transaction_type', 'transaction_created_at', 'last_intent_at',
    'card_last_digits', 'bin_card_number', 'card_holder', 'card_brand',
    'rejection_reason', 'gateway_message', 'ip', 'authentication_type',
    'client_name', 'client_email', 'client_phone', 'country_name',
    'risk_score', 'ip_risk_score', 'card_country_mind_fraud',
]

BASE = datetime(2026, 5, 20, 10, 0, 0)
_tid = [0]


def row(company, cid, amount, status, ttype, t_offset_sec, bin_, last4, holder,
        reason, ip, client_name, client_email, country='El Salvador',
        card_country='EL SALVADOR'):
    _tid[0] += 1
    ts = (BASE + timedelta(seconds=t_offset_sec)).isoformat()
    return {
        'transaction_id': f"tx{_tid[0]:06d}",
        'company_name': company,
        'company_id': cid,
        'amount': amount,
        'status': status,
        'transaction_type': ttype,
        'transaction_created_at': ts,
        'last_intent_at': ts,
        'card_last_digits': last4,
        'bin_card_number': bin_,
        'card_holder': holder,
        'card_brand': 'VISA',
        'rejection_reason': reason,
        'gateway_message': reason or 'OK',
        'ip': ip,
        'authentication_type': 'NONE',
        'client_name': client_name,
        'client_email': client_email,
        'client_phone': '50370000000',
        'country_name': country,
        'risk_score': 10,
        'ip_risk_score': 10,
        'card_country_mind_fraud': card_country,
    }


rows = []

# ── Mandados sv: 4 distinct cards, one IP, 12x same code on one card, $0 ──────
IP_M = '186.77.1.10'
code = '14 - LLAMAR AL EMISOR'
t = 0
# card A hammered 12 times, same code, same payer identity
for i in range(12):
    rows.append(row('Mandados sv', 'C-MANDADOS', 45.00, 'REJECTED', 'LINK',
                    t, 411111, 1111, 'JUAN PEREZ', code, IP_M,
                    'Juan Perez', 'juan@example.com'))
    t += 90
# cards B, C, D a couple attempts each (different last4), same IP
for j, (b, l4, holder) in enumerate([(422222, 2222, 'JUAN PEREZ'),
                                      (433333, 3333, 'JUAN PEREZ'),
                                      (444444, 4444, 'JUAN PEREZ')]):
    for _ in range(2):
        rows.append(row('Mandados sv', 'C-MANDADOS', 50.00, 'REJECTED', 'LINK',
                        t, b, l4, holder, '05 - SOSPECHA DE FRAUDE', IP_M,
                        'Juan Perez', 'juan@example.com'))
        t += 60

# ── Inversiones Kabu: 8 cards / 6 BINs, 6 cards in ~2.4 min, one IP, $0 ───────
IP_K = '190.55.2.20'
kabu_cards = [
    (510001, 5633, 'MARIA LOPEZ'),
    (510002, 5634, 'MARIA LOPEZ'),
    (510003, 5635, 'CARLOS RUIZ'),
    (510004, 5636, 'CARLOS RUIZ'),
    (510005, 5637, 'ANA GOMEZ'),
    (510006, 5638, 'ANA GOMEZ'),
    (510001, 7001, 'LUIS DIAZ'),   # BIN reused, different last4
    (510002, 7002, 'LUIS DIAZ'),   # -> 8 cards, 6 distinct BINs
]
t = 0
# 6 cards within ~2.4 min (24s apart)
for i, (b, l4, holder) in enumerate(kabu_cards[:6]):
    rows.append(row('Inversiones Kabu', 'C-KABU', 75.00, 'REJECTED', 'LINK',
                    t, b, l4, holder, '59 - SOSPECHA DE FRAUDE', IP_K,
                    'Comprador Web', 'kabu@example.com'))
    t += 24
# remaining 2 cards a bit later
for (b, l4, holder) in kabu_cards[6:]:
    rows.append(row('Inversiones Kabu', 'C-KABU', 80.00, 'REJECTED', 'LINK',
                    t, b, l4, holder, '46 - undefined', IP_K,
                    'Comprador Web', 'kabu@example.com'))
    t += 30

# ── Benign control A: single customer retrying ONE blocked card (gated out) ──
t = 0
for i in range(8):
    rows.append(row('Cafe Honesto', 'C-CAFE', 12.00, 'REJECTED', 'LINK',
                    t, 466666, 9999, 'PEDRO SOSA', '41 - TARJETA BLOQUEADA',
                    '200.1.1.1', 'Pedro Sosa', 'pedro@example.com'))
    t += 120

# ── Benign control B: normal merchant with successful settlements ────────────
t = 0
for i in range(10):
    status = 'SUCCEEDED'
    rows.append(row('Comercio Exitoso', 'C-EXITO', 30.00, status, 'POS',
                    t, 470000 + i, 1000 + i, f'CLIENTE {i}', '', f'10.0.0.{i}',
                    f'Cliente {i}', f'cliente{i}@example.com'))
    t += 300

# ── Boundary case: all-fail, 2 cards, no escalation -> Monitor (base only) ───
t = 0
for i in range(6):
    b, l4, holder, ip = (480000, 1212, 'SARA MENA', '201.2.2.2') if i % 2 == 0 \
        else (490000, 3434, 'TOMAS VEGA', '201.2.2.99')
    rows.append(row('Dos Clientes', 'C-DOS', 25.00, 'REJECTED', 'LINK',
                    t, b, l4, holder, '14 - LLAMAR AL EMISOR', ip,
                    holder.title(), f'{holder.split()[0].lower()}@example.com'))
    t += 600  # 10 min apart -> no fan-out burst

out_dir = os.path.join(os.path.dirname(__file__), 'fixtures')
os.makedirs(out_dir, exist_ok=True)
out_path = os.path.join(out_dir, 'synthetic.csv')
with open(out_path, 'w', newline='', encoding='utf-8') as f:
    w = csv.DictWriter(f, fieldnames=COLUMNS)
    w.writeheader()
    w.writerows(rows)

print(f"Wrote {len(rows)} rows to {out_path}")
