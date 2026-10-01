// Invariant: the Kratos public base URL is the portal's own public URL (single origin); KRATOS_PUBLIC_URL is not read.

import { test, beforeEach, afterEach } from 'vitest';
import assert from 'node:assert/strict';
import { kratosBase } from '../src/lib/kratos.ts';
import { publicUrl } from '../src/lib/config.ts';

const saved = process.env.KRATOS_PUBLIC_URL;

beforeEach(() => {
  delete process.env.KRATOS_PUBLIC_URL;
});

afterEach(() => {
  if (saved === undefined) delete process.env.KRATOS_PUBLIC_URL;
  else process.env.KRATOS_PUBLIC_URL = saved;
});

test('kratosBase: is OTHALA_PUBLIC_URL', () => {
  assert.equal(kratosBase(), publicUrl);
});

test('kratosBase: ignores KRATOS_PUBLIC_URL', () => {
  process.env.KRATOS_PUBLIC_URL = 'http://kratos:4433';
  assert.equal(kratosBase(), publicUrl);
});
