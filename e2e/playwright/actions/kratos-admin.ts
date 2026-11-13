/** A call to the Kratos admin API, e.g. `adminApi(url, 'DELETE', 'identities/<id>/credentials/totp')`. */
export async function adminApi(kratosAdminURL: string, method: string, path: string, body?: unknown): Promise<Response> {
  return fetch(`${kratosAdminURL}/admin/${path}`, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}
