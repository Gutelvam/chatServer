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
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | Para o YouTube | A app criada na Google. O `scripts/move-google-secret.ps1` do repositório da aplicação coloca-os aqui |
| `TIKTOK_ENABLED` | Para o TikTok | `1` para ligar. Sem isto, a biblioteca não oficial nem é carregada |
| `TIKTOK_MAX_ROOMS` | Não | Canais do TikTok ao mesmo tempo. Por omissão, 20 |
| `TIKTOK_SIGN_API_KEY` | Não | Chave do serviço de assinaturas |

## Endereços

| Pedido | Para quê |
|---|---|
| `GET /health` | Verificar se está de pé |
| `GET /kick/login?state&return` | Começar o login. `return` só aceita `http://127.0.0.1:<porta>/` |
| `GET /kick/callback` | Regresso do Kick |
| `POST /kick/claim` | A aplicação troca o código de uso único pela sessão |
| `POST /kick/webhook` | Eventos do Kick |
| `POST /kick/chat` | Enviar uma mensagem, com a sessão |
| `DELETE /kick/session` | Terminar sessão |
| `POST /google/token` | Troca o código do login da Google por tokens, juntando o segredo. Não guarda nada |
| `POST /google/refresh` | Renova o acesso ao YouTube, da mesma forma |
| WS `/kick/stream` | Mensagens e eventos da conta, com a sessão |
| WS `/tiktok/stream?username=` | Mensagens e eventos de um canal do TikTok |

## Testes

```
npm ci
npm test
```

Correm contra simuladores, sem internet nem contas.

`test/frames.json` é o formato das mensagens. A aplicação tem uma cópia em `crates/ms-chat/tests/relay_frames.json`: **ao mudar o formato, muda as duas**.
