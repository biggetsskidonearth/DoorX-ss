// lib/security.ts — Shared security utilities
import { createHash, randomBytes } from 'crypto'
import { prisma } from './prisma'
import type { NextRequest } from 'next/server'

// ── IP Hashing (never store raw IPs) ─────────────────────────────────────────
export function hashIP(ip: string): string {
  const salt = process.env.IP_HASH_SALT || 'doorx-default-salt-change-in-production'
  return createHash('sha256').update(salt + ip).digest('hex')
}

// ── Get real IP from Vercel/proxy headers ─────────────────────────────────────
export function getRealIP(req: NextRequest): string {
  return (
    req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    req.headers.get('x-real-ip') ||
    req.headers.get('cf-connecting-ip') || // Cloudflare
    '0.0.0.0'
  )
}

// ── Rate Limiter ─────────────────────────────────────────────────────────────
interface RateLimitConfig {
  windowMs: number   // ms
  max: number        // max requests per window
}

export async function checkRateLimit(
  identifier: string,
  action: string,
  config: RateLimitConfig
): Promise<{ allowed: boolean; remaining: number; resetAt: Date }> {
  const key = `${identifier}:${action}`
  const now = new Date()
  const windowStart = new Date(now.getTime() - config.windowMs)
  const expiresAt = new Date(now.getTime() + config.windowMs)

  // Clean up expired records
  await prisma.rateLimit.deleteMany({ where: { expiresAt: { lt: now } } })

  const existing = await prisma.rateLimit.findUnique({ where: { identifier: key } })

  if (!existing || existing.windowStart < windowStart) {
    // New window — reset
    await prisma.rateLimit.upsert({
      where: { identifier: key },
      update: { count: 1, windowStart: now, expiresAt },
      create: { identifier: key, count: 1, windowStart: now, expiresAt },
    })
    return { allowed: true, remaining: config.max - 1, resetAt: expiresAt }
  }

  if (existing.count >= config.max) {
    return { allowed: false, remaining: 0, resetAt: existing.expiresAt }
  }

  await prisma.rateLimit.update({
    where: { identifier: key },
    data: { count: { increment: 1 } },
  })

  return { allowed: true, remaining: config.max - existing.count - 1, resetAt: existing.expiresAt }
}

// ── Lockdown Check ───────────────────────────────────────────────────────────
export async function isLockedDown(ipHash: string): Promise<boolean> {
  const ld = await prisma.lockdown.findUnique({ where: { ipHash } })
  if (!ld) return false
  if (ld.expiresAt < new Date()) {
    await prisma.lockdown.delete({ where: { ipHash } })
    return false
  }
  return true
}

export async function triggerLockdown(ipHash: string, reason: string, durationMs = 3_600_000) {
  const expiresAt = new Date(Date.now() + durationMs)
  await prisma.lockdown.upsert({
    where: { ipHash },
    update: { reason, expiresAt },
    create: { ipHash, reason, expiresAt },
  })
}

// ── Key Generation ────────────────────────────────────────────────────────────
const CHARSET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'

export function generateKeyString(plan: 'Free' | 'Normal' | 'Premium'): string {
  const bytes = randomBytes(22) // more than enough
  let chars = ''
  for (const b of bytes) {
    if (chars.length >= 11) break
    if (b < Math.floor(256 / CHARSET.length) * CHARSET.length) chars += CHARSET[b % CHARSET.length]
  }
  while (chars.length < 11) chars += CHARSET[randomBytes(1)[0] % CHARSET.length]
  return `DoorX-${plan}-${chars}`
}

// ── API Key Validation (for internal API routes) ──────────────────────────────
export function validateInternalToken(req: NextRequest): boolean {
  const token = req.headers.get('x-doorx-internal')
  return token === process.env.INTERNAL_API_SECRET
}

// ── Origin Check ─────────────────────────────────────────────────────────────
export function validateOrigin(req: NextRequest): boolean {
  const origin = req.headers.get('origin') || ''
  const allowed = (process.env.ALLOWED_ORIGINS || '').split(',').map(o => o.trim())
  return allowed.some(a => origin === a || origin.endsWith(a))
}
