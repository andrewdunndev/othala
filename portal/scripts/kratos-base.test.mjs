// Invariant: the Kratos public base URL defaults to the portal's own public URL (single-origin) and KRATOS_PUBLIC_URL overrides it.

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

test('kratosBase: defaults to OTHALA_PUBLIC_URL when KRATOS_PUBLIC_URL is unset or blank', () => {
  assert.equal(kratosBase(), publicUrl);
  process.env.KRATOS_PUBLIC_URL = '  ';
  assert.equal(kratosBase(), publicUrl);
});

test('kratosBase: KRATOS_PUBLIC_URL overrides the default', () => {
  process.env.KRATOS_PUBLIC_URL = 'http://kratos:4433';
  assert.equal(kratosBase(), 'http://kratos:4433');
});
