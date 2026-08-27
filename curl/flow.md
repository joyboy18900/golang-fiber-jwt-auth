# Manual test flow

Full walkthrough for exercising the API by hand, from starting the stack to
tearing it down.

## Start

```bash
docker compose up -d --build
docker compose ps
docker compose logs app --tail 20   # should show "server started on port 8080"
```

## 1. Register

```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"demo-flow@example.com","password":"password123"}'
```

```json
{ "code": 201, "message": "user registered successfully", "data": { "id": 1, "email": "demo-flow@example.com", "role": "user" } }
```

## 2. Login

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"demo-flow@example.com","password":"password123"}'
```

```json
{ "code": 200, "message": "login successful", "data": { "access_token": "...", "refresh_token": "..." } }
```

Save both tokens from `data`. The rest of the flow needs them.

## 3. Call a protected route

```bash
curl http://localhost:8080/me -H "Authorization: Bearer <access_token>"
```

```json
{ "code": 200, "message": "user profile retrieved successfully", "data": { "id": 1, "role": "user" } }
```

## 4. Refresh the access token

```bash
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'
```

```json
{ "code": 200, "message": "token refreshed successfully", "data": { "access_token": "..." } }
```

## 5. Logout (revokes the refresh token)

```bash
curl -X POST http://localhost:8080/auth/logout \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'
```

```json
{ "code": 200, "message": "logged out successfully", "data": null }
```

## 6. Replay the revoked refresh token - must be rejected

```bash
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<same refresh_token as step 5>"}'
```

```json
{ "code": 401, "message": "refresh token revoked or expired", "data": null }
```

## 7. Other rejection cases worth checking

An access token used where a refresh token is expected:

```bash
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<access_token>"}'
```

```json
{ "code": 401, "message": "invalid refresh token", "data": null }
```

`/me` with no `Authorization` header:

```bash
curl http://localhost:8080/me
```

```json
{ "code": 401, "message": "missing bearer token", "data": null }
```

## Stop

```bash
docker compose down
```
