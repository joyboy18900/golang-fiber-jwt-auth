# golang-fiber-jwt-auth

Go Fiber REST API with hand-rolled JWT auth (no JWT library). Postgres for
users, Redis for refresh-token revocation. Personal reference project -
hexagonal architecture (`handler/service/repository`), built to look back at
later.

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

Every response, success or error, uses the same envelope:

```json
{ "code": 200, "message": "login successful", "data": { "...": "..." } }
```

`code` mirrors the HTTP status. `data` is `null` when there is nothing to
return (e.g. logout).

## Design notes

- JWT is hand-rolled (`token/` package, `crypto/hmac`), not a library. `alg`
  is checked before the signature, rejects anything but `HS256`.
- Access and refresh tokens use separate secrets plus a `typ` claim, so one
  can't be replayed as the other.
- Access TTL 15m, refresh TTL 7d. Refresh token's `jti` is stored in Redis;
  revoke = delete that key. Logout takes the refresh token, not the access
  token.
- `token/` sits outside the ports/adapters split - pure crypto, no swappable
  backend.
- Not done on purpose: no refresh-token rotation, no revoke-all-sessions, no
  admin seeding (promote via `UPDATE users SET role='admin' WHERE email=...`).
- See `auth_integration_test.go` for the full register -> login -> logout ->
  replay-refresh(401) flow.

## Tests

```
go test ./...
go generate ./...   # regenerate repository mocks
```
