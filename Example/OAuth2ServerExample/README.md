# Vapor OAuth2 Example

This is a complete example of implementing OAuth2 using the Vapor OAuth library. It demonstrates the full OAuth2 authorization code flow with a sample client and interactive demo.

## Features

- ✅ OAuth2 Authorization Code Flow
- ✅ Token endpoint with access and refresh tokens
- ✅ User info endpoint
- ✅ Token introspection and revocation
- ✅ Interactive web demo
- ✅ Sample OAuth client configuration

## Quick Start

1. **Build and run the application:**
   ```bash
   swift run
   ```

2. **Access the demo:**
   - Open your browser and go to `http://localhost:8080/demo`
   - This will show an interactive OAuth2 demo page

3. **Test the API endpoints:**
   - Server info: `GET http://localhost:8080/oauth/info`
   - List clients: `GET http://localhost:8080/oauth/clients`

## OAuth2 Endpoints

The application provides the following OAuth2 endpoints:

- **Authorization:** `GET /oauth/authorize`
- **Token:** `POST /oauth/token`
- **User Info:** `GET /oauth/userinfo`
- **Token Introspection:** `POST /oauth/introspect`
- **Token Revocation:** `POST /oauth/revoke`
- **Client Registration:** `POST /oauth/register`

## Sample Client

A sample OAuth client is pre-configured for testing:

- **Client ID:** `sample-client`
- **Client Secret:** `sample-secret`
- **Redirect URI:** `http://localhost:8080/callback`
- **Scopes:** `read`, `write`
- **Grant Types:** `authorization_code`, `refresh_token`

## OAuth2 Flow Example

### 1. Authorization Request
```
GET /oauth/authorize?response_type=code&client_id=sample-client&redirect_uri=http://localhost:8080/callback&scope=read%20write&state=random-state
```

### 2. Token Exchange
```bash
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic c2FtcGxlLWNsaWVudDpzYW1wbGUtc2VjcmV0" \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=http://localhost:8080/callback"
```

### 3. Access Protected Resource
```bash
curl -H "Authorization: Bearer ACCESS_TOKEN" \
  http://localhost:8080/oauth/userinfo
```

## Project Structure

```
Sources/ExampleApp/
├── Controllers/
│   ├── OAuthController.swift    # Additional OAuth endpoints
│   └── TodoController.swift     # Example API endpoints
├── Models/
│   └── Todo.swift              # Example data model
├── configure.swift             # App configuration with OAuth setup
├── routes.swift               # Route registration
└── entrypoint.swift           # Application entry point

Public/
└── demo.html                  # Interactive OAuth demo page
```

## Configuration

The OAuth2 configuration is set up in `configure.swift`:

```swift
app.oauth.configuration = OAuthConfiguration(
    authorizationEndpoint: "/oauth/authorize",
    tokenEndpoint: "/oauth/token",
    clientRegistrationEndpoint: "/oauth/register",
    revocationEndpoint: "/oauth/revoke",
    introspectionEndpoint: "/oauth/introspect"
)
```

## Security Notes

⚠️ **This is an example application for demonstration purposes:**

- The sample client credentials are hardcoded and should not be used in production
- In a real application, clients should be stored in a database
- Token validation and user authentication should be properly implemented
- HTTPS should be used in production environments

## Development

To modify or extend this example:

1. **Add new OAuth clients:** Modify the `configureOAuth` function in `configure.swift`
2. **Customize user info:** Update the `userinfo` endpoint in `OAuthController.swift`
3. **Add new scopes:** Update the scope configuration in the OAuth setup
4. **Implement user authentication:** Add proper user management and authentication

## Testing

The demo page at `http://localhost:8080/demo` provides an interactive way to test the OAuth2 flow. You can also use tools like:

- **Postman** for API testing
- **curl** for command-line testing
- **OAuth2 playground** for flow validation

## Dependencies

- **Vapor:** Web framework
- **Fluent:** ORM for database operations
- **FluentSQLiteDriver:** SQLite database driver
- **VaporOAuth:** OAuth2 implementation library
