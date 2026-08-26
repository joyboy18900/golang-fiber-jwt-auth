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

## Tests

```
go test ./...
go generate ./...   # regenerate repository mocks
```

See `curl/flow.md` for a manual walkthrough of every endpoint.
