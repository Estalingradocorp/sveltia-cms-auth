/**
 * List of supported OAuth providers.
 */
const supportedProviders = ['github', 'gitlab'];

/**
 * OAuth scopes for each provider: the scope to request when the client doesn’t ask for one, the
 * separator the provider expects between multiple scopes, and the scopes that may be requested.
 *
 * A client can ask for a narrower scope than the default — Sveltia CMS does this with its
 * `auth_scope` backend option, so a public repository doesn’t require access to a contributor’s
 * private ones — but only from this list. The endpoint is reachable by anyone, and a token minted
 * with a wider scope than the CMS needs keeps that scope for every later sign-in, so the request is
 * not taken on trust. Anything unrecognized falls back to the default, which is what an older
 * version of this worker granted regardless, so an unfamiliar client still signs in.
 *
 * GitHub’s `workflow` scope is wider than the default, so it’s only allowed when the
 * `GITHUB_ALLOW_WORKFLOW_SCOPE` environment variable is `true`: see {@link getScope}.
 * @type {Record<string, { default: string, separator: string, allowed: string[] }>}
 * @see https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps
 * @see https://docs.gitlab.com/api/oauth2/
 */
const providerScopes = {
  github: {
    default: 'repo,user',
    separator: ',',
    allowed: ['repo', 'public_repo', 'user', 'read:user', 'user:email'],
  },
  gitlab: {
    default: 'api',
    separator: ' ',
    allowed: ['api', 'read_api', 'read_user', 'read_repository', 'write_repository'],
  },
};

/**
 * Work out the OAuth scope to request from the given provider.
 * @param {string} provider - Backend name, e.g. `github`.
 * @param {string} [requested] - The `scope` parameter from the request, if any. Scopes may be
 * separated by commas or spaces, as the two providers differ.
 * @param {{ [key: string]: string }} env - Environment variables.
 * @returns {string} Scope to request.
 */
const getScope = (provider, requested, env) => {
  const { default: fallback, separator, allowed } = providerScopes[provider];
  let scopes = (requested ?? '').split(/[\s,]+/).filter(Boolean);
  const allowWorkflow = provider === 'github' && env.GITHUB_ALLOW_WORKFLOW_SCOPE === 'true';

  // The `workflow` scope lets a token change GitHub Actions workflows in every repository the user
  // can push to, so it takes the operator’s consent as well as the site’s. Without it, the scope is
  // left out rather than the request falling back to the default, which could be wider than what
  // was asked for, e.g. `repo` instead of `public_repo`
  if (!allowWorkflow && scopes.includes('workflow')) {
    // eslint-disable-next-line no-console
    console.warn(
      `Ignoring the "workflow" scope for ${provider}; set GITHUB_ALLOW_WORKFLOW_SCOPE to "true" ` +
        'to allow it.',
    );

    scopes = scopes.filter((scope) => scope !== 'workflow');
  }

  if (!scopes.length) {
    return fallback;
  }

  if (scopes.every((scope) => allowed.includes(scope) || (allowWorkflow && scope === 'workflow'))) {
    return scopes.join(separator);
  }

  // The default is wider than what was asked for, so a client that meant to narrow the scope
  // silently doesn’t. Leave a trace for whoever is running the worker
  // eslint-disable-next-line no-console
  console.warn(
    `Ignoring the unsupported "${requested}" scope for ${provider}; requesting "${fallback}".`,
  );

  return fallback;
};

/**
 * Escape the given string for safe use in a regular expression.
 * @param {string} str - Original string.
 * @returns {string} Escaped string.
 * @see https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions#escaping
 */
const escapeRegExp = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Convert the `ALLOWED_DOMAINS` environment variable into a list of anchored regular expression
 * sources. The sources are used both here and in the client-side script embedded in
 * {@link outputHTML}, so a hostname is matched by the exact same rules on either side.
 * @param {string} [allowedDomains] - Comma-separated list of hostnames, which may contain a
 * wildcard (`*`).
 * @returns {string[]} Regular expression sources. Empty if the variable is not configured.
 */
const getDomainPatterns = (allowedDomains) =>
  (allowedDomains ?? '')
    .split(/,/)
    .map((str) => str.trim())
    .filter(Boolean)
    // Escape the input, then replace a wildcard for regex
    .map((str) => `^${escapeRegExp(str).replaceAll('\\*', '.+')}$`);

/**
 * Serialize the given value for safe embedding in an inline `<script>` block.
 * @param {string | boolean | string[]} value - Value to be serialized.
 * @returns {string} JavaScript literal.
 */
const serialize = (value) => JSON.stringify(value ?? null).replaceAll('<', '\\u003c');

/**
 * Output HTML response that communicates with the window opener.
 * @param {object} args - Options.
 * @param {string} [args.provider] - Backend name, e,g. `github`.
 * @param {string} [args.token] - OAuth token.
 * @param {string} [args.error] - Error message when an OAuth token is not available.
 * @param {string} [args.errorCode] - Error code to be used to localize the error message in
 * Sveltia CMS.
 * @param {{ [key: string]: string }} [args.env] - Environment variables.
 * @returns {Response} Response with HTML.
 */
const outputHTML = ({ provider = 'unknown', token, error, errorCode, env = {} }) => {
  const state = error ? 'error' : 'success';
  const content = error ? { provider, error, errorCode } : { provider, token };

  return new Response(
    `
      <!doctype html><html><body><script>
        (() => {
          const trustedPatterns = ${serialize(getDomainPatterns(env.ALLOWED_DOMAINS))};
          const hasToken = ${serialize(!!token)};

          const isTrusted = (origin) => {
            try {
              const { hostname } = new URL(origin);

              return trustedPatterns.some((pattern) => new RegExp(pattern).test(hostname));
            } catch {
              return false;
            }
          };

          window.addEventListener('message', ({ data, origin }) => {
            if (data !== 'authorizing:${provider}') {
              return;
            }

            // Unlike the site_id parameter, which the caller supplies, the origin of a message
            // event is set by the browser and cannot be forged by the sender, so it’s the only
            // reliable indication of who opened this popup. An error carries no secret, so it’s
            // always passed through to keep the sign-in screen informative
            if (hasToken && trustedPatterns.length && !isTrusted(origin)) {
              return;
            }

            window.opener?.postMessage(
              'authorization:${provider}:${state}:${JSON.stringify(content)}',
              origin
            );
          });
          window.opener?.postMessage('authorizing:${provider}', '*');
        })();
      </script></body></html>
    `,
    {
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        // Delete CSRF token
        'Set-Cookie': `csrf-token=deleted; HttpOnly; Max-Age=0; Path=/; SameSite=Lax; Secure`,
      },
    },
  );
};

/**
 * Handle the `auth` method, which is the first request in the authorization flow.
 * @param {Request} request - HTTP request.
 * @param {{ [key: string]: string }} env - Environment variables.
 * @returns {Promise<Response>} HTTP response.
 */
const handleAuth = async (request, env) => {
  const { url } = request;
  const { origin, searchParams } = new URL(url);
  const { provider, site_id: domain, scope: requestedScope } = Object.fromEntries(searchParams);

  if (!provider || !supportedProviders.includes(provider)) {
    return outputHTML({
      env,
      error: 'Your Git backend is not supported by the authenticator.',
      errorCode: 'UNSUPPORTED_BACKEND',
    });
  }

  const scope = getScope(provider, requestedScope, env);

  const {
    ALLOWED_DOMAINS,
    GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET,
    GITHUB_HOSTNAME = 'github.com',
    GITLAB_CLIENT_ID,
    GITLAB_CLIENT_SECRET,
    GITLAB_HOSTNAME = 'gitlab.com',
  } = env;

  const domainPatterns = getDomainPatterns(ALLOWED_DOMAINS);

  // Check if the domain is whitelisted
  if (
    domainPatterns.length &&
    !domainPatterns.some((pattern) => new RegExp(pattern).test(domain ?? ''))
  ) {
    return outputHTML({
      env,
      provider,
      error: 'Your domain is not allowed to use the authenticator.',
      errorCode: 'UNSUPPORTED_DOMAIN',
    });
  }

  // Generate a random string for CSRF protection
  const csrfToken = globalThis.crypto.randomUUID().replaceAll('-', '');
  let authURL = '';

  // GitHub
  if (provider === 'github') {
    if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET) {
      return outputHTML({
        env,
        provider,
        error: 'OAuth app client ID or secret is not configured.',
        errorCode: 'MISCONFIGURED_CLIENT',
      });
    }

    const params = new URLSearchParams({
      client_id: GITHUB_CLIENT_ID,
      scope,
      state: csrfToken,
    });

    authURL = `https://${GITHUB_HOSTNAME}/login/oauth/authorize?${params.toString()}`;
  }

  // GitLab
  if (provider === 'gitlab') {
    if (!GITLAB_CLIENT_ID || !GITLAB_CLIENT_SECRET) {
      return outputHTML({
        env,
        provider,
        error: 'OAuth app client ID or secret is not configured.',
        errorCode: 'MISCONFIGURED_CLIENT',
      });
    }

    const params = new URLSearchParams({
      client_id: GITLAB_CLIENT_ID,
      redirect_uri: `${origin}/callback`,
      response_type: 'code',
      scope,
      state: csrfToken,
    });

    authURL = `https://${GITLAB_HOSTNAME}/oauth/authorize?${params.toString()}`;
  }

  // Redirect to the authorization server
  return new Response('', {
    status: 302,
    headers: {
      Location: authURL,
      // Cookie expires in 10 minutes; Use `SameSite=Lax` to make sure the cookie is sent by the
      // browser after redirect
      'Set-Cookie':
        `csrf-token=${provider}_${csrfToken}; ` +
        `HttpOnly; Path=/; Max-Age=600; SameSite=Lax; Secure`,
    },
  });
};

/**
 * Handle the `callback` method, which is the second request in the authorization flow.
 * @param {Request} request - HTTP request.
 * @param {{ [key: string]: string }} env - Environment variables.
 * @returns {Promise<Response>} HTTP response.
 */
const handleCallback = async (request, env) => {
  const { url, headers } = request;
  const { origin, searchParams } = new URL(url);
  const { code, state } = Object.fromEntries(searchParams);

  const [, provider, csrfToken] =
    headers.get('Cookie')?.match(/\bcsrf-token=([a-z-]+?)_([0-9a-f]{32})\b/) ?? [];

  if (!provider || !supportedProviders.includes(provider)) {
    return outputHTML({
      env,
      error: 'Your Git backend is not supported by the authenticator.',
      errorCode: 'UNSUPPORTED_BACKEND',
    });
  }

  if (!code || !state) {
    return outputHTML({
      env,
      provider,
      error: 'Failed to receive an authorization code. Please try again later.',
      errorCode: 'AUTH_CODE_REQUEST_FAILED',
    });
  }

  if (!csrfToken || state !== csrfToken) {
    return outputHTML({
      env,
      provider,
      error: 'Potential CSRF attack detected. Authentication flow aborted.',
      errorCode: 'CSRF_DETECTED',
    });
  }

  const {
    GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET,
    GITHUB_HOSTNAME = 'github.com',
    GITLAB_CLIENT_ID,
    GITLAB_CLIENT_SECRET,
    GITLAB_HOSTNAME = 'gitlab.com',
  } = env;

  let tokenURL = '';
  let requestBody = {};

  // GitHub
  if (provider === 'github') {
    if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET) {
      return outputHTML({
        env,
        provider,
        error: 'OAuth app client ID or secret is not configured.',
        errorCode: 'MISCONFIGURED_CLIENT',
      });
    }

    tokenURL = `https://${GITHUB_HOSTNAME}/login/oauth/access_token`;
    requestBody = {
      code,
      client_id: GITHUB_CLIENT_ID,
      client_secret: GITHUB_CLIENT_SECRET,
    };
  }

  if (provider === 'gitlab') {
    if (!GITLAB_CLIENT_ID || !GITLAB_CLIENT_SECRET) {
      return outputHTML({
        env,
        provider,
        error: 'OAuth app client ID or secret is not configured.',
        errorCode: 'MISCONFIGURED_CLIENT',
      });
    }

    tokenURL = `https://${GITLAB_HOSTNAME}/oauth/token`;
    requestBody = {
      code,
      client_id: GITLAB_CLIENT_ID,
      client_secret: GITLAB_CLIENT_SECRET,
      grant_type: 'authorization_code',
      redirect_uri: `${origin}/callback`,
    };
  }

  let response;
  let token = '';
  let error = '';

  try {
    response = await fetch(tokenURL, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestBody),
    });
  } catch {
    //
  }

  if (!response) {
    return outputHTML({
      env,
      provider,
      error: 'Failed to request an access token. Please try again later.',
      errorCode: 'TOKEN_REQUEST_FAILED',
    });
  }

  try {
    ({ access_token: token, error } = await response.json());
  } catch {
    return outputHTML({
      env,
      provider,
      error: 'Server responded with malformed data. Please try again later.',
      errorCode: 'MALFORMED_RESPONSE',
    });
  }

  return outputHTML({ env, provider, token, error });
};

const escapeHtml = (s) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const safeEqual = (a, b) => {
  const sa = String(a ?? '');
  const sb = String(b ?? '');
  if (sa.length !== sb.length) return false;
  let diff = 0;
  for (let i = 0; i < sa.length; i++) diff |= sa.charCodeAt(i) ^ sb.charCodeAt(i);
  return diff === 0;
};
const handleLoginForm = (request, env) => {
  const qs = new URLSearchParams(new URL(request.url).search);
  const provider = qs.get('provider') || 'github';
  const client = qs.get('client') || '';
  const redirect = qs.get('redirect') || '';
  const siteId = qs.get('site_id') || '';
  const hidden = (name, val) => val ? `<input type="hidden" name="${name}" value="${escapeHtml(val)}">` : '';
  return new Response(`<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Acceso al panel</title><style>body{font-family:system-ui;background:#faf8f5;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}.caja{background:#fff;border:1px solid #eee;padding:2rem;border-radius:12px;width:min(92vw,360px);box-shadow:0 4px 20px rgba(0,0,0,.06)}label{display:block;margin:12px 0 6px;font-size:14px}input{width:100%;padding:10px;border:1px solid #ddd;border-radius:8px;box-sizing:border-box}button{width:100%;margin-top:16px;padding:10px;background:#c0272d;color:#fff;border:0;border-radius:8px;cursor:pointer;font-weight:700}.err{color:#b00;margin-top:12px;font-size:14px}</style></head><body><form class="caja" method="post" action="/auth">${hidden('provider', provider)}${hidden('client', client)}${hidden('redirect', redirect)}${hidden('site_id', siteId)}<h1 style="font-size:20px;margin:0 0 4px">Panel de administración</h1><p style="margin:0 0 8px;color:#666;font-size:14px">Ingresá con tu usuario y contraseña.</p><label>Usuario<input name="user" autocomplete="username" required></label><label>Contraseña<input type="password" name="pass" autocomplete="current-password" required></label><button type="submit">Entrar</button></form></body></html>`, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
};
const handleLoginSubmit = async (request, env) => {
  const { ADMIN_USER, ADMIN_PASS, GITHUB_TOKEN, ALLOWED_DOMAINS } = env;
  if (!ADMIN_USER || !ADMIN_PASS || !GITHUB_TOKEN) {
    return outputHTML({ env, provider: 'github', error: 'Panel no configurado.', errorCode: 'MISCONFIGURED_CLIENT' });
  }
  let form;
  try { form = Object.fromEntries(await request.formData()); } catch { return new Response('Solicitud inválida', { status: 400 }); }
  const userOk = safeEqual(form.user ?? '', ADMIN_USER);
  const passOk = safeEqual(form.pass ?? '', ADMIN_PASS);
  if (!userOk || !passOk) {
    return new Response('Usuario o contraseña incorrectos', { status: 401, headers: { 'Content-Type': 'text/plain;charset=UTF-8' } });
  }
  const redirect = String(form.redirect || '');
  const client = String(form.client || '');
  if (client === 'editor' && redirect) {
    try {
      const target = new URL(redirect);
      const patterns = getDomainPatterns(ALLOWED_DOMAINS);
      const allowed = !patterns.length || patterns.some((p) => new RegExp(p).test(target.hostname));
      if (allowed) {
        const loc = `${target.origin}${target.pathname}#access_token=${encodeURIComponent(GITHUB_TOKEN)}`;
        return new Response('', { status: 302, headers: { Location: loc } });
      }
    } catch { // ignore, fallback to popup flow
    }
  }
  return outputHTML({ env, provider: 'github', token: GITHUB_TOKEN });
};

export default {
  /**
   * The main request handler.
   * @param {Request} request - HTTP request.
   * @param {{ [key: string]: string }} env - Environment variables.
   * @returns {Promise<Response>} HTTP response.
   * @see https://developers.cloudflare.com/workers/runtime-apis/fetch/
   * @see https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
   * @see https://docs.gitlab.com/ee/api/oauth2.html#authorization-code-flow
   */
  // Password mode: serve login form for Sveltia and editor without GitHub OAuth
  // All secrets come from env (ADMIN_USER, ADMIN_PASS, GITHUB_TOKEN), never from code.
  if (method === 'GET' && ['/auth', '/oauth/authorize'].includes(pathname)) {
    const qs = new URLSearchParams(new URL(url).search);
    if (qs.get('provider') === 'password' || qs.get('mode') === 'password' || qs.get('client') === 'editor') {
      return handleLoginForm(request, env);
    }
    return handleAuth(request, env);
  }

  if (method === 'POST' && ['/auth', '/login', '/editor-auth'].includes(pathname)) {
    return handleLoginSubmit(request, env);
  }

  if (method === 'GET' && ['/editor-auth', '/login'].includes(pathname)) {
    return handleLoginForm(request, env);
  }

  if (method === 'GET' && ['/callback', '/oauth/redirect'].includes(pathname)) {
    return handleCallback(request, env);
  }

    return new Response('', { status: 404 });
  },
};
