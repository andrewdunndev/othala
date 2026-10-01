// Invariant: the Kratos public base URL is the internal service address; KRATOS_PUBLIC_URL in the environment is not read.

import { test, beforeEach, afterEach } from 'vitest';
import assert from 'node:assert/strict';
import { kratosBase } from '../src/lib/kratos.ts';

const saved = process.env.KRATOS_PUBLIC_URL;

beforeEach(() => {
  delete process.env.KRATOS_PUBLIC_URL;
});

afterEach(() => {
  if (saved === undefined) delete process.env.KRATOS_PUBLIC_URL;
  else process.env.KRATOS_PUBLIC_URL = saved;
});

test('kratosBase: is the internal Kratos public address', () => {
  assert.equal(kratosBase(), 'http://kratos:4433');
});

test('kratosBase: ignores KRATOS_PUBLIC_URL', () => {
  process.env.KRATOS_PUBLIC_URL = 'http://elsewhere:1';
  assert.equal(kratosBase(), 'http://kratos:4433');
});
