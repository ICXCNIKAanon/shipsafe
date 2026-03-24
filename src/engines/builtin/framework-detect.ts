/**
 * ShipSafe Framework Detection System
 *
 * Reads a project's package.json and detects which framework is in use.
 * Returns a FrameworkProfile that rules can use to adjust behavior,
 * eliminating false positives from framework-specific patterns firing
 * on the wrong framework.
 */

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

// ── Types ──

export interface FrameworkProfile {
  name: string; // 'nextjs' | 'express' | 'fastify' | 'hono' | 'koa' | 'django' | 'flask' | 'fastapi' | 'unknown'
  isNextJs: boolean;
  isExpress: boolean;
  isFastify: boolean;
  isHono: boolean;
  isDjango: boolean;
  isFlask: boolean;
  isFastAPI: boolean;
  hasAuth: string | null; // 'clerk' | 'next-auth' | 'passport' | 'lucia' | null
  hasORM: string | null; // 'prisma' | 'drizzle' | 'sequelize' | 'typeorm' | 'knex' | null
  hasSupabase: boolean;
  hasStripe: boolean;
}

// ── Default (unknown) profile ──

function unknownProfile(): FrameworkProfile {
  return {
    name: 'unknown',
    isNextJs: false,
    isExpress: false,
    isFastify: false,
    isHono: false,
    isDjango: false,
    isFlask: false,
    isFastAPI: false,
    hasAuth: null,
    hasORM: null,
    hasSupabase: false,
    hasStripe: false,
  };
}

// ── Detection logic ──

/**
 * Detect the framework and ecosystem from a project's package.json.
 * For Python projects, falls back to reading requirements.txt / pyproject.toml.
 */
export async function detectFramework(projectDir: string): Promise<FrameworkProfile> {
  const profile = unknownProfile();

  // Try JavaScript/TypeScript project first (package.json)
  const jsDetected = await detectFromPackageJson(projectDir, profile);

  // If no JS framework found, try Python project
  if (!jsDetected) {
    await detectFromPython(projectDir, profile);
  }

  return profile;
}

// ── JavaScript/TypeScript detection (package.json) ──

async function detectFromPackageJson(projectDir: string, profile: FrameworkProfile): Promise<boolean> {
  let allDeps: Record<string, string>;

  try {
    const pkgPath = join(projectDir, 'package.json');
    const raw = await readFile(pkgPath, 'utf-8');
    const pkg = JSON.parse(raw) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
  } catch {
    return false; // No package.json or unreadable
  }

  // ── Framework detection (priority order — most specific first) ──

  if (allDeps['next']) {
    profile.name = 'nextjs';
    profile.isNextJs = true;
  } else if (allDeps['fastify']) {
    profile.name = 'fastify';
    profile.isFastify = true;
  } else if (allDeps['hono']) {
    profile.name = 'hono';
    profile.isHono = true;
  } else if (allDeps['express']) {
    profile.name = 'express';
    profile.isExpress = true;
  } else if (allDeps['koa']) {
    profile.name = 'koa';
  }

  // ── Auth detection ──

  if (allDeps['@clerk/nextjs'] || allDeps['@clerk/clerk-react'] || allDeps['@clerk/clerk-js']) {
    profile.hasAuth = 'clerk';
  } else if (allDeps['next-auth'] || allDeps['@auth/core']) {
    profile.hasAuth = 'next-auth';
  } else if (allDeps['passport']) {
    profile.hasAuth = 'passport';
  } else if (allDeps['lucia'] || allDeps['@lucia-auth/adapter-prisma'] || allDeps['lucia-auth']) {
    profile.hasAuth = 'lucia';
  }

  // ── ORM detection ──

  if (allDeps['@prisma/client'] || allDeps['prisma']) {
    profile.hasORM = 'prisma';
  } else if (allDeps['drizzle-orm']) {
    profile.hasORM = 'drizzle';
  } else if (allDeps['sequelize']) {
    profile.hasORM = 'sequelize';
  } else if (allDeps['typeorm']) {
    profile.hasORM = 'typeorm';
  } else if (allDeps['knex']) {
    profile.hasORM = 'knex';
  }

  // ── Ecosystem detection ──

  if (allDeps['@supabase/supabase-js'] || allDeps['@supabase/ssr']) {
    profile.hasSupabase = true;
  }
  if (allDeps['stripe'] || allDeps['@stripe/stripe-js']) {
    profile.hasStripe = true;
  }

  return true; // package.json was found
}

// ── Python detection (requirements.txt / pyproject.toml) ──

async function detectFromPython(projectDir: string, profile: FrameworkProfile): Promise<void> {
  let content = '';

  // Try requirements.txt first
  try {
    content = await readFile(join(projectDir, 'requirements.txt'), 'utf-8');
  } catch {
    // Try pyproject.toml
    try {
      content = await readFile(join(projectDir, 'pyproject.toml'), 'utf-8');
    } catch {
      // Try Pipfile
      try {
        content = await readFile(join(projectDir, 'Pipfile'), 'utf-8');
      } catch {
        return; // No Python dependency files found
      }
    }
  }

  const lower = content.toLowerCase();

  if (lower.includes('django')) {
    profile.name = 'django';
    profile.isDjango = true;
  } else if (lower.includes('fastapi')) {
    profile.name = 'fastapi';
    profile.isFastAPI = true;
  } else if (lower.includes('flask')) {
    profile.name = 'flask';
    profile.isFlask = true;
  }
}
