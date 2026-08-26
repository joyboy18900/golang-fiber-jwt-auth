# golang-fiber-jwt-auth

Go Fiber REST API with JWT auth. Postgres for users, Redis for
refresh-token revocation.

## Run

```
docker-compose up
```

## Endpoints

```
POST /auth/register
POST /auth/login
POST /auth/refresh
POST /auth/logout
GET  /me
```

See `curl/flow.md` for full request/response examples.

## Key Technical Takeaways / Gotchas

- JWT via `golang-jwt/jwt/v5` (`token/` package), HS256-only signing-method
  allowlist - rejects anything else before the signature is checked.
- Separate access/refresh secrets plus a `typ` claim, so one can't be
  replayed as the other.
- Access TTL 15m, refresh TTL 7d. Refresh token's `jti` lives in Redis;
  revoke = delete that key. Logout takes the refresh token, not the
  access token.
- Reusing a refresh token after logout is rejected (401) - the `jti` is
  gone from Redis, so replay fails the same check a legitimate expiry
  would. See `auth_integration_test.go` for the full flow.
- `token/` sits outside the ports/adapters split - a thin wrapper around
  the JWT library, no swappable backend.

## Not done on purpose

- No refresh-token rotation, no revoke-all-sessions.
- No admin seeding (promote via
  `UPDATE users SET role='admin' WHERE email=...`).

## Tests

```
go test ./...
go generate ./...   # regenerate repository mocks
```

See `curl/flow.md` for a manual walkthrough of every endpoint.
