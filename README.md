# golang-fiber-jwt-auth

Go Fiber REST API with JWT auth. Postgres for users, Redis for
refresh-token revocation. Hexagonal architecture
(`handler/service/repository`).

## Run

```
docker-compose up
```

## Endpoints

```
POST /auth/register   {"email", "password"}
POST /auth/login      {"email", "password"} -> access_token, refresh_token
POST /auth/refresh     {"refresh_token"} -> new access_token
POST /auth/logout      {"refresh_token"}
GET  /me               Authorization: Bearer <access_token>
```

```json
{ "code": 200, "message": "login successful", "data": { "...": "..." } }
```

`code` mirrors the HTTP status, `data` is `null` when empty.

## Design notes

- JWT via `golang-jwt/jwt/v5` (`token/` package), HS256 only - the signing
  method allowlist rejects anything else before the signature is checked.
- Access and refresh tokens use separate secrets plus a `typ` claim, so one
  can't be replayed as the other.
- Access TTL 15m, refresh TTL 7d. Refresh token's `jti` is stored in Redis;
  revoke = delete that key. Logout takes the refresh token, not the access
  token.
- `token/` sits outside the ports/adapters split - a thin wrapper around
  the JWT library, no swappable backend.
- Not done on purpose: no refresh-token rotation, no revoke-all-sessions, no
  admin seeding (promote via `UPDATE users SET role='admin' WHERE email=...`).
- See `auth_integration_test.go` for the full register -> login -> logout ->
  replay-refresh(401) flow.

## Tests

```
go test ./...
go generate ./...   # regenerate repository mocks
```
