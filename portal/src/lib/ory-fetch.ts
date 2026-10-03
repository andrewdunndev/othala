import { Configuration, IdentityApi, OAuth2Api, ResponseError } from '@ory/client-fetch';
import { HYDRA_ADMIN_URL, KRATOS_ADMIN_URL } from './constants';

export function timeoutFetch(ms = 10_000): typeof fetch {
  return (input, init) => {
    const timeout = AbortSignal.timeout(ms);
    const signal = init?.signal ? AbortSignal.any([init.signal, timeout]) : timeout;
    return fetch(input, { ...init, signal });
  };
}

export function kratosAdmin(): IdentityApi {
  return new IdentityApi(new Configuration({ basePath: KRATOS_ADMIN_URL, fetchApi: timeoutFetch() }));
}

export function hydraAdmin(): OAuth2Api {
  return new OAuth2Api(new Configuration({ basePath: HYDRA_ADMIN_URL, fetchApi: timeoutFetch() }));
}

export function isNotFound(err: unknown): boolean {
  return err instanceof ResponseError && err.response?.status === 404;
}
