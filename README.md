# MultiStream relay

Servidor pequeno que recebe o que a aplicação de computador MultiStream não consegue receber: os webhooks do Kick e o TikTok LIVE. Depois entrega tudo à aplicação de cada pessoa por WebSocket. Guarda também os segredos das apps do Kick e da Google, para não irem no instalador.

## Publicação

Cada alteração é testada. **O que chega ao `main` e passa nos testes vai para o Fly.io automaticamente** ([workflow](.github/workflows/ci-deploy.yml)).

Só é preciso preparar isto uma vez, no terminal, com o [`fly`](https://fly.io/docs/flyctl/install/) instalado e depois de `fly auth login`:

```powershell
fly apps create multistream-relay-ttd
fly volumes create relay_data --app multistream-relay-ttd --region iad --size 1
fly secrets set --app multistream-relay-ttd PUBLIC_URL=https://multistream-relay-ttd.fly.dev KICK_CLIENT_ID=... KICK_CLIENT_SECRET=... DATA_KEY=...
fly tokens create deploy --app multistream-relay-ttd
```

Guarda o resultado do último comando como segredo do repositório, sem o colar em mais lado nenhum:

```powershell
gh secret set FLY_API_TOKEN --repo Gutelvam/chatServer
```

Para gerar a `DATA_KEY`:

```powershell
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Enquanto `FLY_API_TOKEN` não existir, os testes correm e a publicação é ignorada com um aviso. Depois de o criar, publica em **Actions > CI and deploy > Run workflow**.

**Este repositório é público:** nunca coloques segredos nos ficheiros. Vivem nos segredos do Fly.io e do GitHub.

A criação da app no Kick e os limites de cada plataforma estão em `docs/platform-apps.md`, no repositório da aplicação.

## Valores

| Nome | Obrigatório | O que é |
|---|---|---|
| `PUBLIC_URL` | Sim | O endereço público, sem `/` no fim |
| `DATA_KEY` | Sim | 32 bytes em hexadecimal, que cifram os logins guardados |
| `DATA_DIR` | Não | Onde guardar os dados. Por omissão, `/data` |
| `KICK_CLIENT_ID`, `KICK_CLIENT_SECRET` | Para o Kick | A app criada no Kick |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | Para o YouTube | A app criada na Google. O `scripts/move-google-secret.ps1` do repositório da aplicação coloca-os aqui. É o cliente usado pelas apps que não dizem qual usam |
| `GOOGLE_CLIENT_ID_2`, `GOOGLE_CLIENT_SECRET_2` | Opcional | Um segundo cliente da Google, para mudar de cliente sem desligar ninguém: as apps que enviam `client_id` igual a este usam-no |
| `TIKTOK_CLIENT_KEY`, `TIKTOK_CLIENT_SECRET` | Para o login com o TikTok | A app no TikTok for Developers (Login Kit for Desktop). É a usada pelas apps que não dizem qual usam |
| `TIKTOK_CLIENT_KEY_2`, `TIKTOK_CLIENT_SECRET_2` | Opcional | Uma segunda app do TikTok (por exemplo sandbox e produção ao mesmo tempo): as apps que enviam `client_key` igual a esta usam-na |
| `TIKTOK_ENABLED` | Para o TikTok | `1` para ligar. Sem isto, a biblioteca não oficial nem é carregada |
| `TIKTOK_MAX_ROOMS` | Não | Canais do TikTok ao mesmo tempo. Por omissão, 20 |
| `TIKTOK_SIGN_API_KEY` | Não | Chave do serviço de assinaturas |

## Endereços

| Pedido | Para quê |
|---|---|
| `GET /health` | Verificar se está de pé |
| `GET /kick/login?state&return[&code_challenge]` | Começar o login. `return` só aceita `http://127.0.0.1:<porta>/`. `code_challenge` (opcional, S256 base64url) obriga o `claim` a trazer o `code_verifier` |
| `GET /kick/callback` | Regresso do Kick |
| `POST /kick/claim` | A aplicação troca o código de uso único (2 min) pela sessão (`{code, code_verifier?}`). Sessões sem uso por 90 dias expiram |
| `POST /kick/webhook` | Eventos do Kick |
| `POST /kick/chat` | Enviar uma mensagem, com a sessão |
| `DELETE /kick/session` | Terminar sessão |
| `POST /google/token` | Troca o código do login da Google por tokens, juntando o segredo. Não guarda nada |
| `POST /google/refresh` | Renova o acesso ao YouTube, da mesma forma |
| `POST /tiktok/token` | Troca o código do login do TikTok por tokens, juntando o segredo (`{code, code_verifier, redirect_uri, client_key?}`). Devolve só `access_token`, `expires_in`, `refresh_token`, `refresh_expires_in` e `open_id`. Não guarda nada |
| `POST /tiktok/refresh` | Renova o acesso ao TikTok (`{refresh_token, client_key?}`) |
| `POST /tiktok/revoke` | Termina o login no TikTok (`{token, client_key?}`) |
| WS `/kick/stream` | Mensagens e eventos da conta, com a sessão |
| WS `/tiktok/stream?username=` | Mensagens e eventos de um canal do TikTok |

## Testes

```
npm ci
npm test
```

Correm contra simuladores, sem internet nem contas.

`test/frames.json` é o formato das mensagens. A aplicação tem uma cópia em `crates/ms-chat/tests/relay_frames.json`: **ao mudar o formato, muda as duas**.
