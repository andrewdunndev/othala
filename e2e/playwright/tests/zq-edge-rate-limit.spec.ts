// ZQ — the edge's per-client rate limit on the Kratos self-service paths trips, and only for that client.

import { test, expect, clientAddress } from '../fixtures';

test('ZQ1 — the 31st self-service call in a minute from one client is refused; another client is not', async ({
  request,
  playwright,
  baseURL,
}, testInfo) => {
  const statuses: number[] = [];
  for (let i = 0; i < 31; i++) {
    statuses.push((await request.get(`${baseURL}/sessions/whoami`, { maxRedirects: 0 })).status());
  }
  expect(statuses.slice(0, 30).filter((s) => s === 429), 'ZQ1: the first 30 calls fit the zone').toEqual([]);
  expect(statuses[30], 'ZQ1: othala_selfservice refuses the 31st call').toBe(429);

  const other = await playwright.request.newContext({
    extraHTTPHeaders: { 'X-Forwarded-For': clientAddress(`${testInfo.testId}:${testInfo.retry}:other`) },
  });
  try {
    const resp = await other.get(`${baseURL}/sessions/whoami`, { maxRedirects: 0 });
    expect(resp.status(), 'ZQ1: the zone keys on the client, so a second client still gets through').not.toBe(429);
  } finally {
    await other.dispose();
  }
});
