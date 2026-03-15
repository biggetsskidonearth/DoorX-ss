# DoorX API — Next.js + Prisma + Vercel

## Stack
- **Next.js 14** — API routes (Pages Router)
- **Prisma 5** — ORM + schema management
- **PostgreSQL** — Vercel Postgres (or Neon)
- **Vercel** — Deploy target

## API Routes

| Method | Route | Auth | Description |
|--------|-------|------|-------------|
| `POST` | `/api/keys/generate` | `x-doorx-internal` | Generate a key after gamepass verification |
| `POST` | `/api/keys/validate` | Public | Validate a key (called by DoorX program) |
| `POST` | `/api/keys/revoke` | `x-doorx-internal` | Revoke a key (admin) |
| `GET` | `/api/keys/lookup?robloxUserId=X` | `x-doorx-internal` | Look up keys for a user |
| `POST` | `/api/verify/gamepass` | Public | Server-side Roblox gamepass check |

## Setup

### 1. Clone & Install
```bash
npm install
```

### 2. Environment Variables
```bash
cp .env.example .env.local
# Fill in DATABASE_URL, DIRECT_URL, INTERNAL_API_SECRET, IP_HASH_SALT, ALLOWED_ORIGINS
```

### 3. Database Setup
```bash
# Push schema to your Postgres database
npm run db:push

# Or use migrations (recommended for production)
npx prisma migrate dev --name init
```

### 4. Run Locally
```bash
npm run dev
# API available at http://localhost:3000/api/...
```

## Deploy to Vercel

### Option A: Vercel CLI
```bash
npm i -g vercel
vercel login
vercel
# Follow prompts — add environment variables when asked
```

### Option B: GitHub Import
1. Push to GitHub
2. Go to [vercel.com/new](https://vercel.com/new)
3. Import your repo
4. Add environment variables in Settings
5. Click Deploy

### Adding Vercel Postgres
1. In Vercel Dashboard → Storage → Create → Postgres
2. Connect to your project
3. Copy the `DATABASE_URL` and `DIRECT_URL` into env vars

### Adding Neon (alternative free Postgres)
1. Create account at [neon.tech](https://neon.tech)
2. Create database → copy connection string
3. Use as `DATABASE_URL` (set `DIRECT_URL` to the same value without `?pgbouncer=true`)

## Security Architecture

- **IP hashing**: Raw IPs are never stored. SHA-256 + salt is stored instead.
- **Rate limiting**: Per-IP, per-action, enforced in database.
- **Lockdown**: IPs exceeding thresholds are locked in DB for 1 hour.
- **Key uniqueness**: `(robloxUserId, plan)` compound unique index prevents duplicate keys.
- **Immutable audit log**: Every action is logged with IP hash, user agent, and timestamp.
- **Internal secret**: Admin routes require `x-doorx-internal` header with secret token.

## Key Format
```
DoorX-{Plan}-{11 chars from unambiguous charset}
Examples:
  DoorX-Free-AB3K7MPQXE2
  DoorX-Normal-CFJH4RT6WNY
  DoorX-Premium-BDKM8PVXZQ3
```
Charset: `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` (no 0, O, 1, I, l for visual clarity)
