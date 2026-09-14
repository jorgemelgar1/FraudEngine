# Backups

Two halves, kept apart on purpose.

| | Where it lives | Why there |
|---|---|---|
| **Schema** (the shape of the database) | `supabase/schema-v1.0.0.sql`, in this repo | Harmless. No data in it. Being in git is the point - it is versioned alongside the code it matches. |
| **Data** (the actual rows) | `C:\Users\<you>\Cubo Pago Backups\`, encrypted, **outside this repo** | Card BINs, last-4s, merchant names and reviewer emails. This repo is public on GitHub. |

The data never goes in the repo, not even gitignored. `.gitignore` stops git,
but `.vercelignore` is a *separate* file with separate rules, and a `vercel`
CLI deploy uploads your working folder instead of cloning from GitHub. A file
that is not in the folder cannot be uploaded by either route.

---

## Take a backup

```powershell
.\scripts\backup-database.ps1
```

It asks for three things:

1. **Supabase URL and service-role key** - skipped automatically if `runner\.env` exists, which it usually does.
2. **A password, twice.** Put it in your password manager *before* you press enter. There is no recovery - lose the password and the backup is a brick.

Then it pulls every row, encrypts it, deletes the unencrypted copy, and
**re-opens the encrypted file to prove it works** before it says Done. You get
a file like:

```
C:\Users\<you>\Cubo Pago Backups\cubo-data_v1.0.0_2026-09-13_1042.cubobak
```

The version in the middle of the name is the git tag you were on, so a backup
can always be matched to the code that produced it.

## Look inside a backup (changes nothing)

```powershell
.\scripts\restore-database.ps1 -Path "C:\Users\<you>\Cubo Pago Backups\cubo-data_v1.0.0_2026-09-13_1042.cubobak"
```

Prints when it was taken and how many rows are in each table. Writes nothing.
This is the safe command - run it occasionally to confirm you still remember
the password.

## Actually restore

```powershell
.\scripts\restore-database.ps1 -Path "...\cubo-data_v1.0.0_2026-09-13_1042.cubobak" -Apply
```

Asks you to type `RESTORE` in capitals first.

It **upserts**: rows in the backup overwrite rows with the same key, and rows
created after the backup was taken are left alone rather than deleted. That is
deliberate - a restore that silently destroys a week of newer reviews is worse
than the problem it was run to fix. If a table must match the backup exactly,
empty that table yourself first, then run with `-Apply`.

## Rebuild the schema file after a release

```powershell
git tag -a v1.1.0 -m "..."
python scripts\build_schema_baseline.py
```

---

## What this protects against, and what it does not

**Does:** a bad migration during a v1.1 upgrade; a table emptied by mistake; a
stolen or resold laptop; a backup file copied somewhere careless.

**Does not:** someone who has the password. The encryption is AES-256 with the
key stretched from your password (PBKDF2-SHA256, 310,000 rounds) and an
HMAC-SHA256 over the whole file, so a single flipped bit on disk makes it
refuse to open rather than quietly decrypt to damaged SQL. None of that helps
if the password is on a sticky note.

**Also does not:** replace Supabase's own backups. On the free tier there are
none, so these files are the only copy - which is the argument for running
`backup-database.ps1` on a schedule rather than only before upgrades.

## Files

| File | What it is |
|---|---|
| `backup-database.ps1` | The one you run to take a backup |
| `restore-database.ps1` | The one you run to inspect or restore |
| `_crypto.ps1` | Encryption helpers. Not run directly |
| `dump_supabase.py` | Reads the rows out of Supabase |
| `restore_supabase.py` | Writes the rows back in |
| `build_schema_baseline.py` | Rebuilds `supabase/schema-<tag>.sql` |

## Checking the tooling still works

```powershell
powershell -ExecutionPolicy Bypass -File tests	est_backup_scripts.ps1
python tests	est_backup_pipeline.py
```

The first covers the PowerShell half — encryption, secure delete, reading
pasted input, and calling other programs. The second runs the dump and restore
against a stand-in Supabase, so paging, ordering and upsert behaviour are
exercised rather than assumed.

Both exist because this tooling shipped untested and then failed four times on
real use, each time in a different line of the same short script. Run them
after touching anything in `scripts/`.

`.cubobak` file layout: `CUBOBAK1` magic, PBKDF2 round count, 16-byte salt,
16-byte IV, AES-256-CBC ciphertext, HMAC-SHA256 tag. Encrypt-then-MAC, with
separate keys derived for encryption and authentication. Salt and IV are fresh
every time, so backing up the same data twice produces different bytes.
