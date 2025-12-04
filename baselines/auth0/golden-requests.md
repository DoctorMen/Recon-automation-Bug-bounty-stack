# Auth0 Golden Request Library

## Purpose
Baseline requests for Auth0 bug bounty testing. These are clean, working requests that can be modified for IDOR/BOLA testing.

## Client Management Endpoints

### List Clients (GET)
```http
GET /api/v2/clients?page=0&per_page=10 HTTP/1.1
Host: manage.cic-bug-bounty.auth0app.com
Authorization: Bearer {ACCESS_TOKEN}
Content-Type: application/json
```

### Get Single Client (GET)
```http
GET /api/v2/clients/{client_id} HTTP/1.1
Host: manage.cic-bug-bounty.auth0app.com
Authorization: Bearer {ACCESS_TOKEN}
Content-Type: application/json
```

### Update Client (PATCH)
```http
PATCH /api/v2/clients/{client_id} HTTP/1.1
Host: manage.cic-bug-bounty.auth0app.com
Authorization: Bearer {ACCESS_TOKEN}
Content-Type: application/json

{
  "name": "Updated Client Name"
}
```

## User Management Endpoints

### Get Users (GET)
```http
GET /api/v2/users?page=0&per_page=10 HTTP/1.1
Host: manage.cic-bug-bounty.auth0app.com
Authorization: Bearer {ACCESS_TOKEN}
Content-Type: application/json
```

### Get Single User (GET)
```http
GET /api/v2/users/{user_id} HTTP/1.1
Host: manage.cic-bug-bounty.auth0app.com
Authorization: Bearer {ACCESS_TOKEN}
Content-Type: application/json
```

## Organization Management

### List Organizations (GET)
```http
GET /api/v2/organizations?page=0&per_page=10 HTTP/1.1
Host: manage.cic-bug-bounty.auth0app.com
Authorization: Bearer {ACCESS_TOKEN}
Content-Type: application/json
```

### Get Organization (GET)
```http
GET /api/v2/organizations/{organization_id} HTTP/1.1
Host: manage.cic-bug-bounty.auth0app.com
Authorization: Bearer {ACCESS_TOKEN}
Content-Type: application/json
```

## FGA (Fine-Grained Authorization) Endpoints

### List Authorization Models
```http
GET /v1/stores/{store_id}/authorization-models HTTP/1.1
Host: api.us1.fga.dev
Authorization: Bearer {FGA_TOKEN}
Content-Type: application/json
```

### Check Authorization
```http
POST /v1/stores/{store_id}/check HTTP/1.1
Host: api.us1.fga.dev
Authorization: Bearer {FGA_TOKEN}
Content-Type: application/json

{
  "tuple_key": {
    "user": "user:{user_id}",
    "relation": "can_read",
    "object": "document:{document_id}"
  }
}
```

## IDOR Testing Templates

### Same-Tenant ID Swap
1. Use List endpoint to get valid IDs from your tenant
2. Extract IDs from JSON response
3. Swap into single resource endpoints
4. Test access control bypass

### Cross-Tenant ID Swap
1. Get IDs from different tenants/organizations
2. Test if you can access other tenant's resources
3. Look for missing tenant validation

## Notes
- Always use valid tokens from your test accounts
- Test with both admin and regular user permissions
- Document which IDs belong to which tenant
- Save successful requests as templates for future testing
