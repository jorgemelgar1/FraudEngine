# Cubo Fraud Engine — Web App

Internal fraud-analysis tool for Cubo Pago. Upload a daily CSV, get a structured
report. Watchlist persists across runs in Supabase. CSV data is never stored.

---

## What's in this repo

```
.
├── analyze.py              ← Original analysis engine — unchanged, still runs as a CLI
├── api/analyze.py          ← Vercel Python function that wraps analyze.py
├── app/                    ← Next.js frontend (login + upload UI)
│   ├── login/page.tsx
│   ├── auth/callback/route.ts
│   ├── page.tsx            ← Main upload page
│   ├── layout.tsx
│   └── globals.css
├── lib/supabase/           ← Supabase client helpers (browser + server)
├── middleware.ts           ← Protects every route with login + email-domain check
├── supabase/migrations/
│   └── 0001_init.sql       ← The SQL to run in your Supabase project (one time)
├── package.json            ← Next.js dependencies
├── requirements.txt        ← Python dependencies for the serverless function
├── vercel.json             ← Function memory / timeout config
└── .env.example            ← Template for environment variables
```

The CLI still works locally for monthly analyses:

```bash
python analyze.py /path/to/month.csv --output report.json
```

---

## First-time setup (about 20 minutes)

You'll do this once. The order matters.

### 1. Create the Supabase project

1. Go to <https://supabase.com> and sign in.
2. Click **New Project**.
3. Pick any name (e.g., `cubo-fraud-engine`), set a strong database password,
   and choose the region closest to your team.
4. Wait ~2 minutes for it to provision.

### 2. Run the SQL migration

1. In your new Supabase project, click **SQL Editor** in the left sidebar.
2. Click **New query**.
3. Open the file `supabase/migrations/0001_init.sql` from this repo, copy the
   entire contents, paste into the SQL editor, and click **Run**.
4. You should see "Success. No rows returned." If you see errors, copy them and
   share them — the script is idempotent so you can re-run safely.

### 3. Configure Supabase Auth (Google OAuth via Cubo Workspace)

This app uses Google sign-in restricted to your Google Workspace
(`@cubopago.com`). You need to register the app with Google once, then
plug those credentials into Supabase.

#### 3a. Create the Google OAuth client

1. Go to <https://console.cloud.google.com> while signed in with a
   `@cubopago.com` account.
2. Top bar → project selector → create or select a project inside the
   **Cubo Pago organization** (not a personal one — this matters for the
   "Internal" restriction below).
3. Left sidebar → **APIs & Services → OAuth consent screen**:
   - **User Type:** **Internal** (only available because the project lives
     in the Workspace org). This automatically restricts sign-in to
     `@cubopago.com` accounts at Google's level — no one else can even
     attempt to authenticate.
   - **App name:** `Cubo Fraud Engine`
   - **User support email:** your Cubo email
   - **Developer contact:** your Cubo email
   - Save & continue. You can skip the Scopes and Test Users screens.
4. Left sidebar → **APIs & Services → Credentials → Create Credentials →
   OAuth client ID**:
   - **Application type:** Web application
   - **Name:** `Cubo Fraud Engine Web`
   - **Authorized redirect URIs:** add the URL Supabase shows you on the
     Google provider page in the next step. It will look like
     `https://YOUR-PROJECT.supabase.co/auth/v1/callback`.
   - Save.
5. A modal appears with **Client ID** and **Client Secret**. Copy both
   somewhere safe — you'll paste them into Supabase next.

#### 3b. Enable Google in Supabase

1. In Supabase: **Authentication → Providers → Google → enable**.
2. Paste the Client ID and Client Secret from the previous step.
3. Save.

#### 3c. Set the redirect URLs

1. Supabase: **Authentication → URL Configuration**.
2. **Site URL:** your Vercel deployment URL
   (e.g., `https://fraud-engine.vercel.app`). For local dev,
   use `http://localhost:3000`.
3. **Redirect URLs:** add both:
   - `https://fraud-engine.vercel.app/auth/callback`
   - `http://localhost:3000/auth/callback` (for local dev only)

### 4. Grab your Supabase credentials

In Supabase, go to **Project Settings → API**. You'll need four values:

| Value | Where in Supabase |
|---|---|
| `NEXT_PUBLIC_SUPABASE_URL` | "Project URL" |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | "Project API keys → anon public" |
| `SUPABASE_SERVICE_ROLE_KEY` | "Project API keys → service_role" — **secret, never expose to browser** |
| `SUPABASE_JWT_SECRET` | **Project Settings → API → JWT Settings → JWT Secret** |

### 5. Push this repo to GitHub

```bash
git init
git add .
git commit -m "Initial commit"
gh repo create cubo-fraud-engine --private --source=. --push
```

(Or create the repo manually on github.com and `git push` to it.)

### 6. Deploy on Vercel

1. Go to <https://vercel.com>, click **Add New → Project**.
2. Import your GitHub repo.
3. Framework preset: **Next.js** (auto-detected).
4. **Environment Variables** — paste in all five from `.env.example`:
    - `NEXT_PUBLIC_SUPABASE_URL`
    - `NEXT_PUBLIC_SUPABASE_ANON_KEY`
    - `SUPABASE_SERVICE_ROLE_KEY`
    - `SUPABASE_JWT_SECRET`
    - `ALLOWED_EMAIL_DOMAIN` (e.g., `cubopago.com`)
5. Click **Deploy**. First build takes ~2 minutes.
6. Once deployed, go back to Supabase **Auth → URL Configuration** and update
   the Site URL / Redirect URLs to use your real `*.vercel.app` URL.

### 7. Test it

1. Visit your deployment URL.
2. Click **Sign in with Google**.
3. Pick your `@cubopago.com` Google account.
4. You'll land on the upload page.
5. Drop a small daily CSV.
6. You should see a report within a few seconds.

---

## How privacy works

| Concern | What happens |
|---|---|
| Upload encryption | Vercel forces HTTPS — same protection as banking |
| File on disk | Held only in `/tmp` during the function call; wiped when the function returns. `/tmp` is per-invocation RAM-backed scratch space — there is no persistent disk |
| Logs | The function never logs CSV contents — only summary counts |
| Who can sign in | Restricted to `@cubopago.com` emails (set via `ALLOWED_EMAIL_DOMAIN`) |
| Session security | Supabase Auth handles tokens, refresh, and expiry |
| Watchlist | The only persistent data — merchant names, card BIN+last4, risk scores. No transactions, no client info |

---

## Local development (optional)

You only need this if you want to test changes before deploying.

```bash
# Install JS deps
npm install

# Copy env template and fill in your Supabase values
cp .env.example .env.local

# Run the dev server
npm run dev
```

Note: the Python serverless function only runs in production / preview
deployments. The local dev server runs the frontend; uploads will fail unless
you also run `vercel dev` (which runs both).

---

## Limitations of this Hobby-tier deployment

- **4 MB upload limit.** A daily CSV is well under this. A monthly CSV (~28 MB)
  will be rejected by the upload page — use the CLI locally for monthly runs.
- **10-second processing window.** Plenty for a daily file. Monthly files
  would time out anyway, even if they fit.
- **No file size warning until the user picks the file.** The page will reject
  oversized files before sending them, so no bandwidth is wasted.

If your team grows out of these limits, upgrading to Vercel Pro ($20/month)
gives you a 60-second timeout (configurable to 300s) and lets you raise the
upload limit. Code requires no changes.
