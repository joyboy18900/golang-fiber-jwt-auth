# golang-fiber-jwt-auth

A REST API in Go Fiber demonstrating hand-rolled JWT authentication (no JWT
library) over a small user domain: register, login, refresh, logout, and a
protected profile route. User records live in Postgres, refresh-token
revocation state lives in Redis.

## Running it

```
docker-compose up
```

This starts Postgres, Redis, and the app on `:8080`. The users table
migration is applied automatically on Postgres's first boot.

Endpoints:

```
POST /auth/register   {"email": "...", "password": "..."}
POST /auth/login      {"email": "...", "password": "..."}
POST /auth/refresh     {"refresh_token": "..."}
POST /auth/logout      {"refresh_token": "..."}
GET  /me               Authorization: Bearer <access_token>
```

## Architecture

Flat ports-and-adapters layout: `handler/` (Fiber routes), `service/`
(business logic), `repository/` (Postgres + Redis adapters), `errs/` and
`logs/` for cross-cutting concerns. `token/` sits outside that split on
purpose: JWT encode/decode/sign/verify is pure cryptographic logic with no
swappable backend, so it isn't a port/adapter pair, just a plain package.

## JWT design

The token package builds a JWT by hand: `header.payload.signature`, each
segment JSON-marshaled then base64url-encoded without padding. The signature
is an HMAC-SHA256 over the raw `header.payload` string, verified with
`hmac.Equal` (constant-time, not a plain `==`).

Two details matter more than they look:

- `Verify` decodes and checks the header's `alg` field *before* touching the
  signature, and rejects anything other than `"HS256"` outright. This is the
  concrete defense against algorithm-confusion attacks (e.g. a token claiming
  `"alg":"none"`), which is exactly the class of bug a JWT library normally
  hides from you.
- Access and refresh tokens are signed with two different secrets, and each
  token carries a `typ` claim (`"access"` or `"refresh"`) that `Verify` checks
  against the caller's expectation. A token issued for one purpose cannot be
  replayed as the other, even if one of the two checks were ever removed by
  mistake.

## TTL choice

Access tokens: 15 minutes. Refresh tokens: 7 days.

An access token is stateless: once issued, nothing can revoke it before it
expires on its own. Keeping its TTL short bounds how long a leaked token
stays useful. A refresh token is long-lived because it is checked against
Redis on every use, so it can be revoked at any time regardless of its
remaining TTL.

## How revocation works

A JWT cannot be revoked by itself, no matter how it is signed. Revocation
here works by tracking the refresh token's `jti` (a random ID minted at
login) as a key in Redis, with a value of the owning user's ID and a TTL
matching the token's own expiry.

- Login: generate `jti`, store `jti -> user_id` in Redis.
- Refresh: verify the token's signature and expiry, then look the `jti` up
  in Redis. A miss means "revoked or expired" and returns `401` either way -
  the caller cannot distinguish the two.
- Logout: verify the token, then delete its `jti` from Redis.

The access token itself is never checked against Redis. Only the refresh
token is trackable, which is also why `/auth/logout` takes a refresh token,
not an access token, in its request body.

## Reuse after logout

Walking through what the integration test (`TestAuthFlow_RevokedRefreshTokenIsRejected`)
proves:

1. Register, then log in. Capture the returned refresh token.
2. Refresh with that token before logging out: succeeds (`200`), establishing
   the contrast.
3. Log out with that same refresh token: its `jti` is deleted from Redis.
4. Replay the exact same refresh token at `/auth/refresh`: rejected (`401`),
   because the `jti` no longer exists in Redis.

One residual risk worth naming: an access token issued before logout stays
valid until its own (short) TTL elapses, since access tokens are not tracked
anywhere. Logout only guarantees the refresh token can no longer mint new
access tokens.

## Role-based access

`GET /me` returns the caller's ID and role, read from the access token's
claims via `JWTMiddleware`. A separate `RequireRole(roles...)` middleware
exists as a reusable building block for gating any future route by role
(the "user vs admin" case in the API's scope is demonstrated only through
`/me`, not by adding a route the current API doesn't otherwise need).

New accounts always start with `role = "user"`. Promoting one to admin is a
manual step, since there is no seeding of a hardcoded credential in the
migration:

```sql
UPDATE users SET role = 'admin' WHERE email = 'someone@example.com';
```

## Scope decisions

A few things this project deliberately does not do, to keep it a focused
demonstration rather than a production auth service:

- No refresh-token rotation: `/auth/refresh` returns a new access token only,
  the refresh token itself is reused until it expires or is revoked.
- No "revoke all sessions" - logout revokes the one refresh token it is
  given, not every session belonging to that user.
- No admin-seeding mechanism - promote a user manually via SQL, as above.

## Testing

```
go test ./...
```

- `token/token_test.go`: round-trip generate/verify, tampered-payload
  detection, expiry, wrong-type rejection, algorithm-confusion rejection.
- `service/auth_service_test.go`: table-driven, gomock mocks of both
  repository ports.
- `handler/middleware_test.go`: the JWT middleware and role check against a
  minimal Fiber app, using hand-crafted tokens.
- `auth_integration_test.go`: the full register -> login -> logout -> replay
  flow against real routes and real service logic, backed by in-memory fakes
  instead of Postgres/Redis.

Regenerate repository mocks after changing either repository port:

```
go generate ./...
```
