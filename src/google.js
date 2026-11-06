// Google's token address asks for the client secret, which an installed app cannot keep. This does
// only that step: the app keeps its own tokens and talks to YouTube itself, and nothing is stored.
const TIMEOUT_MS = 15_000;

export class Google {
  #config;

  constructor(config) {
    this.#config = config;
  }

  async #token(fields) {
    const answer = await fetch(this.#config.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: this.#config.clientId,
        client_secret: this.#config.clientSecret,
        ...fields,
      }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    const body = await answer.json().catch(() => ({}));
    if (answer.ok && typeof body.access_token === 'string') {
      return {
        status: 200,
        body: {
          access_token: body.access_token,
          expires_in: body.expires_in,
          ...(body.refresh_token ? { refresh_token: body.refresh_token } : {}),
        },
      };
    }
    // Only this says the person's sign-in is gone. Anything else is on our side or passing, and
    // must not sign anyone out.
    if (body.error === 'invalid_grant') return { status: 400, body: { error: 'invalid_grant' } };
    const name = /^[a-z_]{1,40}$/.test(body.error ?? '') ? body.error : 'unknown';
    console.error(`google refused: ${answer.status} ${name}`);
    return { status: 502, body: { error: 'failed' } };
  }

  exchange({ code, verifier, redirect }) {
    return this.#token({
      grant_type: 'authorization_code',
      code,
      code_verifier: verifier,
      redirect_uri: redirect,
    });
  }

  refresh(refreshToken) {
    return this.#token({ grant_type: 'refresh_token', refresh_token: refreshToken });
  }
}
