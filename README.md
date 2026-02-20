# Verifier

This web application allows for consumers to trace the origin of a product to ensure authenticity. All records related to a product are protected cryptographically.

## Tech stack

- Python / Django
- PostgreSQL

## Project structure (important bits)

- `verifier/manage.py` — Django entrypoint
- `verifier/verifier/settings.py` — Django settings (includes DB config)
- `verifier/chain/` — main Django app
- `verifier/chain/migrations/` — database migrations

## Prerequisites

- Python 3.11+ (3.12 also works for most Django setups)
- PostgreSQL 14+ (or any reasonably recent version)
- (Recommended) `venv` for virtual environments

## Quickstart (local development)

### 1) Clone the repo

```bash
git clone https://github.com/TaffCodes/verifier.git
cd verifier
```

### 2) Create and activate a virtual environment

#### macOS / Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
```

#### Windows (PowerShell)
```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3) Install Python dependencies

This repository may not include a `requirements.txt` / `pyproject.toml` at the root. If it does, use one of the following:

- If `requirements.txt` exists:
  ```bash
  pip install -r requirements.txt
  ```
- If `pyproject.toml` exists:
  ```bash
  pip install .
  ```

If neither exists, you’ll need to install dependencies manually (at minimum):
```bash
pip install django psycopg2-binary
```

### 4) Set up PostgreSQL database

The repository currently hardcodes PostgreSQL settings in `verifier/verifier/settings.py`:

- DB name: `supplychain`
- DB user: `postgres`
- DB password: `aaabbb.`
- DB host: `localhost`
- DB port: `5432`

You can either:
- (A) create a local database/user matching those settings, or
- (B) change `settings.py` to match your local credentials.

#### Option A: Create DB that matches current settings

Log into Postgres and create the database:

```bash
psql -U postgres
```

Then in the `psql` prompt:

```sql
CREATE DATABASE supplychain;
-- If you want to set the password to match settings.py:
ALTER USER postgres WITH PASSWORD 'aaabbb.';
```

Exit:
```sql
\q
```

#### Option B (recommended): Use your own credentials

Edit `verifier/verifier/settings.py` and update:

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'supplychain',
        'USER': 'postgres',
        'PASSWORD': 'aaabbb.',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}
```

Tip: For a real project, move these to environment variables (`DATABASE_URL` or individual `DB_*` vars) instead of committing secrets.

### 5) Run migrations

From the repo root, run:

```bash
python verifier/manage.py migrate
```

This will apply migrations including the initial migration for the `chain` app (e.g. `verifier/chain/migrations/0001_initial.py`).

### 6) Create an admin user (optional but recommended)

```bash
python verifier/manage.py createsuperuser
```

### 7) Run the development server

```bash
python verifier/manage.py runserver
```

Then open:
- http://127.0.0.1:8000/

Admin (if enabled):
- http://127.0.0.1:8000/admin/

## Common commands

Run migrations:
```bash
python verifier/manage.py makemigrations
python verifier/manage.py migrate
```

Run Django shell:
```bash
python verifier/manage.py shell
```

Collect static files (production-ish):
```bash
python verifier/manage.py collectstatic
```

## Troubleshooting

### `psycopg2` / PostgreSQL driver errors
If you get errors installing `psycopg2`, try:
```bash
pip install psycopg2-binary
```

### Cannot connect to Postgres
Verify:
- Postgres is running
- Host/port are correct (`localhost:5432`)
- Credentials in `settings.py` match your DB user/password
- Database `supplychain` exists

### Migrations fail due to missing DB
Make sure you created the database first (`CREATE DATABASE supplychain;`) before running `migrate`.

## Security notes

- `SECRET_KEY` and database credentials appear to be hard-coded in `verifier/verifier/settings.py`.
- Do not use these values in production.
- Prefer environment-based configuration and `DEBUG = False` for production deployments.
