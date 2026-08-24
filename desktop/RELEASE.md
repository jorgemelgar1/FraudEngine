# How to release a new version

This is the full workflow for shipping a new version of the desktop app.
Every teammate's installed copy will auto-update on next launch.

## TL;DR (the four commands)

Every command below runs from the repo's `desktop` folder and uses only
relative paths, so it works wherever the repo lives. Start with:

```powershell
cd <your-clone>\desktop     # e.g. "C:\Users\Jorge Melgar\Documents\Cubo Pago\Claude Code Fraud Engine\desktop"
```

```powershell
# 1. Edit src-tauri/tauri.conf.json — bump "version" (e.g., "0.1.0" → "0.2.0")

# 2. (Conditional) Rebuild the Python sidecar if analyze.py changed:
#    (only needed if you edited the engine itself)
$repo = (Resolve-Path ..).Path
& .\python-src\.venv\Scripts\python.exe -m PyInstaller --onefile --noconfirm --clean `
  --name fraud-engine-sidecar `
  --distpath python-bin `
  --workpath python-build `
  --specpath python-build `
  --paths $repo `
  python-src\main.py
Copy-Item python-bin\fraud-engine-sidecar.exe `
  src-tauri\binaries\fraud-engine-sidecar-x86_64-pc-windows-msvc.exe -Force

# 3. Build the signed release
npm run release

# 4. Upload to GitHub — see "Step 4" below
```

The slow step is #3 — about 8–15 minutes the first time, ~3 minutes on
re-runs because Rust caches its work.

> **Why `python.exe -m PyInstaller` and not `pyinstaller.exe`?** The `.exe`
> shims inside a uv-created venv are trampolines with the venv's absolute
> path baked in. Move or rename the repo and every one of them breaks with
> `uv trampoline failed to canonicalize script path`. Invoking the module
> through `python.exe` sidesteps the shim entirely and keeps working after a
> move. See Troubleshooting below if you hit it anyway.

## Step-by-step

### 1. Bump the version

Open `src-tauri/tauri.conf.json`. Change the `"version"` field. Use
[semver](https://semver.org/lang/es/) loosely:

- Small fix or text change → `0.1.0` → `0.1.1`
- New feature → `0.1.0` → `0.2.0`
- Big rewrite → `0.1.0` → `1.0.0`

That's the only version source — `package.json` is read by npm but never
used as the app's display version.

### 2. (Conditional) Rebuild the Python sidecar

The desktop app's analyzer is a **frozen snapshot** of `analyze.py` at the
time the sidecar was last built — it doesn't auto-pick-up changes to the
file. So if you edited `analyze.py` (at the repo root) since the last
release, run the PyInstaller command from the TL;DR above to rebuild the
sidecar and copy the new binary into Tauri's `binaries/` folder.

If you only changed JS/TS/Rust/CSS, **skip this step** — the bundler picks
those changes up automatically.

### 3. Build the signed release

```powershell
cd <your-clone>\desktop
npm run release
```

This:
- Compiles the Rust + JS into a release-mode .exe
- Signs the .exe with the Tauri updater key. The private key file lives
  at `C:\Users\Jorge Melgar\.tauri\cubo-fraud-engine.key` and its password
  lives in a sibling file `cubo-fraud-engine.password` in the same folder.
  Neither file is in this repo. Back them up together.
- Generates `latest.json` — the manifest the auto-updater reads

When it finishes, three files end up in
`src-tauri/target/release/bundle/nsis/`:

```
Cubo Fraud Engine_0.X.0_x64-setup.exe
Cubo Fraud Engine_0.X.0_x64-setup.exe.sig
latest.json
```

If you ever see "Expected build output missing: ...exe.sig" in the output,
check that `bundle.createUpdaterArtifacts` is still `true` in
`tauri.conf.json` and that `C:\Users\Jorge Melgar\.tauri\` still has the
keypair.

### 4. Publish a GitHub release

1. Open <https://github.com/jorgemelgar1/FraudEngine/releases/new>.
2. **Choose a tag**: type the new version with a `v` prefix — e.g., `v0.2.0`.
   GitHub will say "Create new tag: v0.2.0 on publish" — that's correct.
3. **Target**: leave it on `main`.
4. **Title**: `Cubo Fraud Engine v0.2.0` (or similar).
5. **Description**: a short summary of what changed in this version.
6. **Attach binaries**: drag all THREE files from the `bundle/nsis/` folder:
   - `Cubo Fraud Engine_0.X.0_x64-setup.exe`
   - `Cubo Fraud Engine_0.X.0_x64-setup.exe.sig`
   - `latest.json`
7. Make sure **"Set as the latest release"** is checked.
8. Click **"Publish release"**.

That's it. The next time anyone with the app installed launches it, they'll
see "Actualización disponible · v0.X.0" in the header and one click
installs the new version.

## What teammates see when they get updated

After you publish, every install does this automatically:

1. App launches (regardless of any user action)
2. It hits the GitHub `/releases/latest/download/latest.json` endpoint
3. Sees a newer version available → shows a teal pill in the header:
   **"Actualización disponible · vX.Y.Z"**
4. User clicks the pill → downloads the new .exe in the background
5. Verifies the signature against the embedded public key
6. Installs over the old version → app relaunches on the new version

**No SmartScreen prompt for updates.** That's only on first install.

## Updating the install guide

If anything important changes for end users (new permission, new tab, new
setup step), edit [INSTALACION.md](INSTALACION.md) and update the Slack
message you send to teammates.

## Troubleshooting

**`uv trampoline failed to canonicalize script path`**
- The venv at `desktop/python-src/.venv` was created at a different absolute
  path than where the repo sits now (someone moved or renamed the folder).
  The `.exe` shims in `.venv\Scripts\` hardcode that old path.
- Quick fix: invoke through the interpreter instead of the shim —
  `& .\python-src\.venv\Scripts\python.exe -m PyInstaller ...` (that's what
  the TL;DR does).
- Proper fix: recreate the venv. From `desktop\python-src`:
  ```powershell
  Remove-Item .venv -Recurse -Force
  uv venv .venv --python 3.13
  $env:VIRTUAL_ENV = (Resolve-Path .venv).Path
  uv pip install -r requirements.txt
  ```

**Rust build errors mentioning a path the repo no longer lives at**
- e.g. `\\?\C:\Users\...\Desktop\Claude Code Fraud Engine\...`. Cargo caches
  absolute paths inside `target/`, and a repo move poisons them.
- Fix: `Remove-Item desktop\src-tauri\target -Recurse -Force`, then re-run
  `npm run release`. Costs ~5 extra minutes for a from-scratch Rust compile.

**"npm run release" fails immediately with "key not found"**
- The private key got moved or deleted. Check `C:\Users\Jorge Melgar\.tauri\cubo-fraud-engine.key`. If it's gone, you can't sign updates — every install would have to be done manually until you reinstall a new version with a new pubkey baked in. **Back this file up.**

**"Expected build output missing: ...exe.sig"**
- `bundle.createUpdaterArtifacts` is missing or false in `tauri.conf.json`. Set it to `true`.

**"The build did not produce a signed bundle"**
- Same root cause — the signing step didn't run. Fix `createUpdaterArtifacts` and re-run.

**Teammates report "Actualización disponible" but the install fails**
- Most likely the file in GitHub got renamed by GitHub's space-to-period rewrite and the URL in `latest.json` doesn't match. The release script handles this automatically. If you see it again, check `latest.json` for the right URL and re-upload only that file to the release.

**GitHub release shows the files but the endpoint returns 404**
- "Set as the latest release" wasn't checked. Edit the release and toggle it on.

## File / path reference

| Thing | Where |
|---|---|
| Tauri config (version, identifier, etc.) | `desktop/src-tauri/tauri.conf.json` |
| Updater public key (embedded in app) | `desktop/src-tauri/tauri.conf.json → plugins.updater.pubkey` |
| Updater private key (NEVER COMMIT) | `C:\Users\Jorge Melgar\.tauri\cubo-fraud-engine.key` |
| Updater private key password (NEVER COMMIT) | `C:\Users\Jorge Melgar\.tauri\cubo-fraud-engine.password` |
| Sidecar source | `desktop/python-src/main.py` |
| Sidecar binary used by builds | `desktop/src-tauri/binaries/fraud-engine-sidecar-x86_64-pc-windows-msvc.exe` |
| Release script | `desktop/scripts/build-release.mjs` |
| Release output | `desktop/src-tauri/target/release/bundle/nsis/` |
| Install guide (for teammates) | `desktop/INSTALACION.md` |
| End-user updater endpoint | <https://github.com/jorgemelgar1/FraudEngine/releases/latest/download/latest.json> |
