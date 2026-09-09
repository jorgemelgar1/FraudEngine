"""Tests for runner/import_curl.py — configuring the CMS side from a cURL.

The failure this exists to prevent: reading a report URL by hand and not
noticing that one path segment is a country id. Hard-coding it there sends
every request to one country forever, and the runner would look completely
healthy while reporting Guatemala's data as El Salvador's.

Run with plain python (no pytest needed):

    python tests/test_import_curl.py
"""

import os
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, '..'))
for _p in (_ROOT, os.path.join(_ROOT, 'runner')):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import import_curl    # noqa: E402


TOKEN = 'eyJhbGciOiJIUzI1NiJ9.' + 'A' * 80 + '.signature'

CURL = f"""curl 'https://api.example.internal/api/v1/cms/3/transactions/report?createdAt=2026-09-08&createdAt=2026-09-09&isAEVIRTUAL=false&countryId=3&depositStatusFilter=ALL' \\
  -H 'accept: */*' \\
  -H 'authorization: Bearer {TOKEN}' \\
  -H 'content-type: application/json' \\
  -H 'origin: https://cms.example.internal' \\
  -H 'referer: https://cms.example.internal/' \\
  --compressed"""


# ── Parsing the command ──────────────────────────────────────────────────────

def test_url_and_headers_are_extracted():
    parsed = import_curl.parse_curl(CURL)
    assert parsed['url'].startswith('https://api.example.internal/')
    assert parsed['headers']['origin'] == 'https://cms.example.internal'
    assert parsed['headers']['authorization'].startswith('Bearer ')


def test_windows_line_continuations_are_handled():
    """cmd.exe uses ^ instead of \\, and someone will paste that eventually."""
    windows = CURL.replace(' \\\n', ' ^\n')
    parsed = import_curl.parse_curl(windows)
    assert parsed['url'].startswith('https://api.example.internal/')


# ── Dialects: the failure this file's author actually hit ────────────────────

# Chrome's "Copy as cURL (cmd)". Every argument is wrapped ^"..."^ because cmd
# needs ^ to escape a quote, and % is doubled. Parsed naively the header name
# becomes '^authorization', so the lookup for 'authorization' finds nothing -
# while the token is plainly visible in what was pasted. That exact confusion
# cost a round trip, hence this test.
CURL_CMD = (
    'curl ^"https://api.example.internal/api/v1/cms/3/transactions/report'
    '?createdAt=2026-09-08^&countryId=3^&depositStatusFilter=ALL^" ^\n'
    '  -H ^"accept: */*^" ^\n'
    f'  -H ^"authorization: Bearer {TOKEN}^" ^\n'
    '  -H ^"origin: https://cms.example.internal^" ^\n'
    '  -H ^"referer: https://cms.example.internal/^" ^\n'
    '  --compressed'
)

# Chrome's "Copy as cURL (PowerShell)": backtick continuations, curl.exe.
CURL_PS = (
    'curl.exe "https://api.example.internal/api/v1/cms/3/transactions/report'
    '?countryId=3" `\n'
    '  -H "accept: */*" `\n'
    f'  -H "authorization: Bearer {TOKEN}" `\n'
    '  -H "origin: https://cms.example.internal" `\n'
    '  -H "referer: https://cms.example.internal/"'
)


def test_cmd_dialect_finds_the_authorization_header():
    """The regression. The token was visible and the parser said there was
    none, because the header was named '^authorization'."""
    parsed = import_curl.parse_curl(CURL_CMD)
    assert 'authorization' in parsed['headers'], parsed['headers']
    assert import_curl.token_from_headers(parsed['headers']) == TOKEN


def test_cmd_dialect_end_to_end():
    settings, token, _notes = import_curl.settings_from_curl(CURL_CMD)
    assert token == TOKEN
    assert settings['CUBO_API_ROOT'] == 'https://api.example.internal'
    assert settings['CUBO_REPORT_PATH'] == \
        '/api/v1/cms/{country_id}/transactions/report'
    assert settings['CUBO_ORIGIN'] == 'https://cms.example.internal'


def test_powershell_dialect_end_to_end():
    settings, token, _notes = import_curl.settings_from_curl(CURL_PS)
    assert token == TOKEN
    assert settings['CUBO_REPORT_PATH'] == \
        '/api/v1/cms/{country_id}/transactions/report'


def test_a_paste_with_no_newlines_still_works():
    """A wrapped or re-joined paste keeps the backslashes and loses the
    newlines. Left in place, a lone backslash escapes the following space
    under shlex and every header stops being recognised."""
    joined = CURL.replace('\\\n', '\\ ')
    parsed = import_curl.parse_curl(joined)
    assert 'authorization' in parsed['headers'], parsed['headers']


def test_bearer_is_recovered_from_raw_text_as_a_last_resort():
    """If a future browser emits a dialect nobody predicted, seeing the token
    in the paste and being told it is absent is the worst outcome."""
    weird = f'curl --some-new-flag {{a}} https://api.example.internal/x/3/report' \
            f'?countryId=3 --headers-somehow "Authorization=Bearer {TOKEN}"'
    parsed = import_curl.parse_curl(weird)
    assert import_curl.token_from_headers(
        parsed['headers'], raw_text=weird) == TOKEN


def test_percent_escaping_is_undone_for_cmd():
    """cmd doubles % — leaving it doubled corrupts any URL-encoded value."""
    text = ('curl ^"https://api.example.internal/api/1/cms/3/report'
            '?countryId=3^&q=a%%20b^" ^\n'
            f'  -H ^"authorization: Bearer {TOKEN}^"')
    parsed = import_curl.parse_curl(text)
    assert '%20' in parsed['url'] and '%%' not in parsed['url']


def test_non_curl_input_is_explained():
    try:
        import_curl.parse_curl('https://api.example.internal/whatever')
    except import_curl.CurlError as e:
        assert 'Copy as cURL' in str(e)
    else:
        raise AssertionError('a bare URL is not a cURL command')


# ── The token ────────────────────────────────────────────────────────────────

def test_token_is_extracted_and_cleaned():
    parsed = import_curl.parse_curl(CURL)
    assert import_curl.token_from_headers(parsed['headers']) == TOKEN


def test_anonymous_request_is_refused():
    """A request copied while logged out has no token, and the resulting
    404s would look like a broken endpoint rather than a missing login."""
    try:
        import_curl.token_from_headers({'origin': 'https://x'})
    except import_curl.CurlError as e:
        message = str(e)
        assert 'No Authorization header' in message
        # It must also offer the diagnostic, because "I can see the token"
        # is the far more common cause than "I was logged out".
        assert '--show-headers' in message
    else:
        raise AssertionError('a request with no Authorization must be refused')


def test_truncated_token_is_refused():
    """Copy-paste truncation is common and would otherwise be stored happily,
    then fail as a 401 much later."""
    try:
        import_curl.token_from_headers({'authorization': 'Bearer eyJshort'})
    except import_curl.CurlError as e:
        assert 'truncated' in str(e)
    else:
        raise AssertionError('a short token must be refused')


# ── The path template — the reason this file exists ──────────────────────────

def test_country_id_becomes_a_placeholder():
    shape = import_curl.templatize(import_curl.parse_curl(CURL)['url'])
    assert shape['CUBO_REPORT_PATH'] == \
        '/api/v1/cms/{country_id}/transactions/report'
    assert shape['CUBO_API_ROOT'] == 'https://api.example.internal'
    assert shape['country_id_seen'] == '3'
    assert shape['looks_like_report'] is True


def test_the_query_parameter_decides_which_segment_to_replace():
    """There can be several numbers in a path. countryId in the query says
    which one is the country, so this is a lookup rather than a guess."""
    url = ('https://api.example.internal/api/v2/1/cms/2/tx/report'
           '?countryId=2&page=1')
    shape = import_curl.templatize(url)
    assert shape['CUBO_REPORT_PATH'] == \
        '/api/v2/1/cms/{country_id}/tx/report', shape['CUBO_REPORT_PATH']


def test_countryid_absent_from_the_path_is_refused():
    """Better to stop than to substitute the wrong segment - that would send
    every country's request to one country, invisibly."""
    url = ('https://api.example.internal/api/v1/cms/reports/build'
           '?countryId=7')
    try:
        import_curl.templatize(url)
    except import_curl.CurlError as e:
        assert 'countryId=7' in str(e)
    else:
        raise AssertionError('an unsubstitutable path must be refused')


def test_ambiguous_path_without_a_query_hint_is_refused():
    url = 'https://api.example.internal/api/1/cms/2/tx/report'
    try:
        import_curl.templatize(url)
    except import_curl.CurlError as e:
        assert 'REPORT request' in str(e)
    else:
        raise AssertionError('two candidate segments must be refused')


def test_a_non_report_path_warns_but_proceeds():
    """It might genuinely not contain the word. Worth saying, not worth
    blocking on."""
    url = 'https://api.example.internal/api/v1/cms/3/transactions?countryId=3'
    shape = import_curl.templatize(url)
    assert shape['looks_like_report'] is False


# ── Origin and Referer ───────────────────────────────────────────────────────

def test_origin_and_referer_are_taken_from_the_headers():
    values = import_curl.origins_from_headers(
        {'origin': 'https://cms.example.internal',
         'referer': 'https://cms.example.internal/transactions'},
        'https://api.example.internal')
    assert values['CUBO_ORIGIN'] == 'https://cms.example.internal'
    assert values['CUBO_REFERER'] == 'https://cms.example.internal/transactions'


def test_missing_origin_is_derived_from_the_referer():
    values = import_curl.origins_from_headers(
        {'referer': 'https://cms.example.internal/x/y'},
        'https://api.example.internal')
    assert values['CUBO_ORIGIN'] == 'https://cms.example.internal'


def test_both_missing_falls_back_to_the_api_host():
    values = import_curl.origins_from_headers({}, 'https://api.example.internal')
    assert values['CUBO_ORIGIN'] == 'https://api.example.internal'
    assert values['CUBO_REFERER'] == 'https://api.example.internal/'


# ── End to end ───────────────────────────────────────────────────────────────

def test_settings_from_curl():
    settings, token, notes = import_curl.settings_from_curl(CURL)
    assert settings == {
        'CUBO_API_ROOT': 'https://api.example.internal',
        'CUBO_REPORT_PATH': '/api/v1/cms/{country_id}/transactions/report',
        'CUBO_ORIGIN': 'https://cms.example.internal',
        'CUBO_REFERER': 'https://cms.example.internal/',
    }
    assert token == TOKEN
    assert any('Country id seen' in n for n in notes)


def test_the_report_path_actually_formats():
    """config.REPORT_PATH.format(country_id=...) is how it gets used, so the
    placeholder has to be spelled the way str.format expects."""
    settings, _token, _notes = import_curl.settings_from_curl(CURL)
    for country_id in (1, 2, 3):
        formatted = settings['CUBO_REPORT_PATH'].format(country_id=country_id)
        assert f'/{country_id}/' in formatted
        assert '{' not in formatted


# ── Writing .env ─────────────────────────────────────────────────────────────

def _temp_env(content=''):
    path = os.path.join(tempfile.mkdtemp(prefix='import-curl-'), '.env')
    if content:
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(content)
    return path


def test_existing_keys_are_replaced_in_place():
    path = _temp_env(
        '# my config\n'
        'CUBO_API_ROOT=https://old.example\n'
        'GMAIL_CLIENT_SECRET=keep-me\n')
    changed = import_curl.upsert_env(
        {'CUBO_API_ROOT': 'https://new.example'}, path)

    with open(path, encoding='utf-8') as fh:
        written = fh.read()
    assert changed == ['CUBO_API_ROOT']
    assert 'CUBO_API_ROOT=https://new.example' in written
    assert 'https://old.example' not in written
    assert 'GMAIL_CLIENT_SECRET=keep-me' in written
    assert '# my config' in written, 'comments must survive'
    assert written.count('CUBO_API_ROOT=') == 1


def test_new_keys_are_appended():
    path = _temp_env('SUPABASE_SERVICE_ROLE_KEY=sb_secret_x\n')
    settings, _t, _n = import_curl.settings_from_curl(CURL)
    import_curl.upsert_env(settings, path)

    with open(path, encoding='utf-8') as fh:
        written = fh.read()
    assert 'SUPABASE_SERVICE_ROLE_KEY=sb_secret_x' in written
    for key in import_curl.CMS_KEYS:
        assert f'{key}=' in written, key


def test_the_token_is_never_written_to_env():
    """It belongs in the platform keystore. A service-role key in .env is
    bad enough; a second credential there is not an improvement."""
    path = _temp_env()
    settings, token, _n = import_curl.settings_from_curl(CURL)
    import_curl.upsert_env(settings, path)

    with open(path, encoding='utf-8') as fh:
        written = fh.read()
    assert token not in written
    assert 'authorization' not in written.lower()
    assert 'Bearer' not in written


def test_writing_a_missing_file_works():
    path = _temp_env()
    import_curl.upsert_env({'CUBO_API_ROOT': 'https://x.example'}, path)
    with open(path, encoding='utf-8') as fh:
        assert 'CUBO_API_ROOT=https://x.example' in fh.read()


def test_env_is_not_world_readable():
    if sys.platform == 'win32':
        return  # NTFS inherits the directory ACL; nothing to assert
    import stat
    path = _temp_env('A=1\n')
    import_curl.upsert_env({'CUBO_API_ROOT': 'https://x.example'}, path)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600, f'expected 0600, got {oct(mode)}'


# ── Runner ───────────────────────────────────────────────────────────────────

def _run_all():
    tests = [(n, o) for n, o in sorted(globals().items())
             if n.startswith('test_') and callable(o)]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn()
            passed += 1
        except AssertionError as e:
            failed += 1
            print(f'FAIL {name}: {e}')
        except Exception as e:                              # noqa: BLE001
            failed += 1
            print(f'ERROR {name}: {type(e).__name__}: {e}')
    print(f'{passed}/{len(tests)} passed'
          + (f', {failed} failed' if failed else ''))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(_run_all())
