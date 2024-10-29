# Vapor OAuth

A robust OAuth2 Provider Library for Vapor 4, implementing RFC 6749, RFC 6750, RFC 7662, RFC 8628, and RFC 7009 specifications with comprehensive test coverage.

## Features

- Full implementation of modern OAuth2 grant types:
  - Authorization Code Grant with PKCE support (recommended for all clients)
  - Device Authorization Grant (RFC 8628) for browserless devices
  - Client Credentials Grant for server-to-server authentication
  - Token Revocation (RFC 7009) for enhanced security
- Token Introspection support (RFC 7662) for microservices architecture
- OAuth 2.0 Authorization Server Metadata (RFC 8414)
- Extensive test coverage ensuring specification compliance
- Built for Vapor 4 with Swift concurrency support
- Secure defaults with CSRF protection and PKCE

## Installation

Add the library to your `Package.swift` dependencies:

```swift
dependencies: [
    ...,
    .package(url: "https://github.com/dewonderstruck/vapor-oauth", from: "main"))
]
```

Next import the library into where you set up your `Droplet`:

```swift
import VaporOAuth
```

Then add the provider to your `Config`:

```swift
try addProvider(VaporOAuth.Provider(codeManager: MyCodeManager(), tokenManager: MyTokenManager(), clientRetriever: MyClientRetriever(), authorizeHandler: MyAuthHandler(), userManager: MyUserManager(), validScopes: ["view_profile", "edit_profile"], resourceServerRetriever: MyResourceServerRetriever()))
```

To integrate the library, you need to set up a number of things, which implement the various protocols required:

* `CodeManager` - this is responsible for generating and managing OAuth Codes. It is only required for the Authorization Code flow, so if you do not want to support this grant, you can leave out this parameter and use the default implementation
* `TokenManager` - this is responsible for generating and managing Access and Refresh Tokens. You can either store these in memory, in Fluent, or with any backend.
* `ClientRetriever` - this is responsible for getting all of the clients you want to support in your app. If you want to be able to dynamically add clients then you will need to make sure you can do that with your implementation. If you only want to support a set group of clients, you can use the `StaticClientRetriever` which is provided for you
* `AuthorizeHandler` - this is responsible for allowing users to allow/deny authorization requests. See below for more details. If you do not want to support this grant type you can exclude this parameter and use the default implementation
* `UserManager` - this is responsible for authenticating and getting users for the Password Credentials flow. If you do not want to support this flow, you can exclude this parameter and use the default implementation.
* `validScopes` - this is an optional array of scopes that you wish to support in your system.
* `ResourceServerRetriever` - this is only required if using the Token Introspection Endpoint and is what is used to authenticate resource servers trying to access the endpoint

Note that there are a number of default implementations for the different required protocols for Fluent in the [Vapor OAuth Fluent package](https://github.com/brokenhandsio/vapor-oauth-fluent).

The Provider will then register endpoints for authorization and tokens at `/oauth/authorize` and `/oauth/token`

## Protecting Endpoints

Vapor OAuth has a helper extension on `Request` to allow you to easily protect your API routes. For instance, let's say that you want to ensure that one route is accessed only with tokens with the `profile` scope, you can do:

```swift
try request.oauth.assertScopes(["profile"])
```

This will throw a 401 error if the token is not valid or does not contain the `profile` scope. This is so common, that there is a dedicated `OAuth2ScopeMiddleware` for this behaviour. You just need to initialise this with an array of scopes that must be required for that `protect` group. If you initialise it with a `nil` array, then it will just make sure that the token is valid.

You can also get the user with `try request.oauth.user()`.

### Protecting Resource Servers With Remote Auth Server

If you have resource servers that are not the same server as the OAuth server that you wish to protect using the Token Introspection Endpoint, things are slightly different. See the [Token Introspection](#token-introspection) section for more information.

## OAuth 2.0 Authorization Server Metadata

Vapor OAuth implements RFC 8414 which provides a standardized way to expose OAuth 2.0 authorization server metadata. The metadata is available at the well-known URI:

```
/.well-known/oauth-authorization-server
```

The response includes essential information about the authorization server's capabilities and endpoints:

```json
{
    "issuer": "https://your-domain.com",
    "authorization_endpoint": "https://your-domain.com/oauth/authorize",
    "token_endpoint": "https://your-domain.com/oauth/token",
    "device_authorization_endpoint": "https://your-domain.com/oauth/device_authorization",
    "token_revocation_endpoint": "https://your-domain.com/oauth/revoke",
    "token_introspection_endpoint": "https://your-domain.com/oauth/token_info",
    "jwks_uri": "https://your-domain.com/.well-known/jwks.json",
    "response_types_supported": ["code", "token"],
    "grant_types_supported": [
        "authorization_code",
        "client_credentials",
        "refresh_token",
        "urn:ietf:params:oauth:grant-type:device_code"
    ],
    "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
    "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]
}
```

## Grant Types

### Authorization Code Grant with PKCE

The Authorization Code flow with PKCE is the most secure and recommended flow for all OAuth2 clients. Here's how it works in detail:

1. The client application (like a mobile app or web app) generates a PKCE code verifier and challenge:
   - Creates a random code verifier (e.g., `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`)
   - Generates a code challenge by hashing the verifier using SHA-256 and base64url encoding it
   ```swift
   let codeVerifier = String.random(length: 128)  // Random string
   let codeChallenge = SHA256.hash(codeVerifier).base64URLEncoded()
   ```

2. The client redirects the user to your Vapor OAuth server:
   ```
   GET /oauth/authorize?
     response_type=code
     &client_id=CLIENT_ID
     &redirect_uri=https://client-app.com/callback
     &scope=read_profile write_profile
     &state=xyz123
     &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
     &code_challenge_method=S256
   ```
   
   At this point, your Vapor app:
   - Validates the client_id and redirect_uri
   - Authenticates the user (shows login if needed)
   - Displays a consent screen showing what permissions the app is requesting
   - Stores the code challenge for later verification

3. After user approval, your server generates an authorization code and redirects back:
   ```
   HTTP/1.1 302 Found
   Location: https://client-app.com/callback?
     code=SplxlOBeZQQYbYS6WxSbIA
     &state=xyz123
   ```
   
   The authorization code:
   - Is short-lived (typically 60 seconds)
   - Can only be used once
   - Is bound to the client_id and redirect_uri
   - Is associated with the code challenge

4. The client exchanges the code for tokens:
   ```
   POST /oauth/token
   Content-Type: application/x-www-form-urlencoded
   Authorization: Basic base64(client_id:client_secret)
   
   grant_type=authorization_code
   &code=SplxlOBeZQQYbYS6WxSbIA
   &redirect_uri=https://client-app.com/callback
   &code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
   ```

   Your server:
   - Validates the authorization code hasn't expired or been used
   - Verifies the code_verifier matches the stored code_challenge
   - Issues access and refresh tokens

   Response:
   ```json
   {
     "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
     "token_type": "bearer",
     "expires_in": 3600,
     "refresh_token": "8xLOxBtZp8",
     "scope": "read_profile write_profile"
   }
   ```

5. The client can now use the access token to make API requests:
   ```
   GET /api/profile
   Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
   ```

### Device Authorization Grant

The Device Authorization Grant is designed for devices that either lack a browser or have limited input capabilities. Think of smart TVs, gaming consoles, or CLI applications. Here's the detailed flow:

1. The device initiates the flow by requesting a device code:
   ```
   POST /oauth/device_authorization
   Content-Type: application/x-www-form-urlencoded
   Authorization: Basic base64(client_id:client_secret)
   
   scope=read_profile write_profile
   ```

   Your server generates both a device code and a user code:
   ```json
   {
     "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
     "user_code": "WDJB-MJHT",
     "verification_uri": "https://example.com/device",
     "verification_uri_complete": "https://example.com/device?user_code=WDJB-MJHT",
     "expires_in": 1800,
     "interval": 5
   }
   ```

2. The device displays the user code and verification URI to the user:
   ```
   Please visit https://example.com/device
   And enter code: WDJB-MJHT
   ```

3. Meanwhile, the user:
   - Opens a browser on another device
   - Visits the verification URI
   - Enters the user code
   - Authenticates (if not already logged in)
   - Approves the requested permissions

4. The device polls for the token:
   ```
   POST /oauth/token
   Authorization: Basic base64(client_id:client_secret)
   Content-Type: application/x-www-form-urlencoded

   grant_type=urn:ietf:params:oauth:grant-type:device_code
   &device_code=GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS
   ```

   Possible responses:
   - `authorization_pending`: User hasn't approved yet
   - `slow_down`: Client is polling too frequently
   - `expired_token`: Device code has expired
   - `access_denied`: User denied the request
   - Success: Returns access and refresh tokens

   Success response:
   ```json
   {
     "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
     "token_type": "bearer",
     "expires_in": 3600,
     "refresh_token": "8xLOxBtZp8",
     "scope": "read_profile write_profile"
   }
   ```

### Token Revocation

The Token Revocation endpoint (RFC 7009) allows clients to notify the authorization server that a token is no longer needed:

```
POST /oauth/revoke
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

token=ACCESS-TOKEN&token_type_hint=access_token
```

Parameters:
- `token`: REQUIRED. The token to be revoked
- `token_type_hint`: OPTIONAL. Either "access_token" or "refresh_token"


The server will respond with:
- 200 OK if the token was revoked or if it didn't exist
- 401 Unauthorized for invalid client credentials
- 400 Bad Request for invalid requests

### Token Introspection

If running a microservices architecture it is useful to have a single server that handles authorization, which all the other resource servers query. To do this, you can use the Token Introspection Endpoint extension. In Vapor OAuth, this adds an endpoint you can post tokens tokens at `/oauth/token_info`.

You can send a POST request to this endpoint with a single parameter, `token`, which contains the OAuth token you want to check. If it is valid and active, then it will return a JSON payload, that looks similar to:

```json
{
    "active": true,
    "client_id": "ABDED0123456",
    "scope": "email profile",
    "exp": 1503445858,
    "user_id": "12345678",
    "username": "hansolo",
    "email_address": "hansolo@therebelalliance.com"
}
```

If the token has expired or does not exist then it will simply return:

```json
{
    "active": false
}
```

This endpoint is protected using HTTP Basic Authentication so you need to send an `Authorization: Basic abc` header with the request. This will check the `ResourceServerRetriever` for the username and password sent.

**Note:** as per [the spec](https://tools.ietf.org/html/rfc7662#section-4) - the token introspection endpoint MUST be protected by HTTPS - this means the server must be behind a TLS certificate (commonly known as SSL). Vapor OAuth leaves this up to the integrating library to implement.

### Protecting Endpoints

To protect resources on other servers with OAuth using the Token Introspection endpoint, you either need to use the `OAuth2TokenIntrospectionMiddleware` on your routes that you want to protect, or you need to manually set up the `Helper` object (the middleware does this for you). Both the middleware and helper setup require:

* `tokenIntrospectionEndpoint` - the endpoint where the token can be validated
* `client` - the `Droplet`'s client to send the token validation request with
* `resourceServerUsername` - the username of the resource server
* `resourceServerPassword` - the password of the resource server

Once either of these has been set up, you can then call `request.oauth.user()` or `request.oauth.assertScopes()` like normal.

### Deprecated Grant Types

The following grant types are deprecated and should be avoided:

- **Implicit Grant**: Deprecated due to security concerns around returning access tokens in the URL fragment. Use Authorization Code flow with PKCE instead.
- **Password Grant**: Deprecated as it exposes user credentials directly to the client application. Use Authorization Code flow with PKCE instead.

## Security Considerations

1. Always use HTTPS in production
2. Implement rate limiting for token endpoints
3. Use PKCE even for confidential clients
4. Implement proper token storage on the client side
5. Use short-lived access tokens with refresh tokens
6. Implement proper scope validation

## Implementation Details

### Required Middleware

1. **Sessions Middleware**
   The Authorization Code and Device Authorization flows require `SessionsMiddleware` for CSRF protection:
   ```swift
   app.middleware.use(app.sessions.middleware)
   ```

2. **CORS Middleware** (if supporting browser-based clients)
   ```swift
   let corsConfiguration = CORSMiddleware.Configuration(
       allowedOrigin: .all,
       allowedMethods: [.GET, .POST],
       allowedHeaders: [
           .accept,
           .authorization,
           .contentType,
           .origin,
           .xRequestedWith,
       ]
   )
   app.middleware.use(CORSMiddleware(configuration: corsConfiguration))
   ```

### Authorization Handler Implementation

Your `AuthorizeHandler` implementation is crucial for the Authorization Code flow. Here's a complete example:

```swift
struct MyAuthHandler: AuthorizeHandler {
    let view: ViewRenderer
    let clientRetriever: ClientRetriever
    
    func handleAuthorizationRequest(
        _ request: Request,
        authorizationRequestObject: AuthorizationRequestObject
    ) async throws -> Response {
        // Check if user is authenticated
        guard let user = request.auth.get(User.self) else {
            // Store the OAuth redirect in session
            request.session.data["oauth_redirect"] = request.url.string
            
            // Redirect to login
            return request.redirect(to: "/login")
        }
        
        // Get client details for consent screen
        let client = try await clientRetriever.getClient(
            clientID: authorizationRequestObject.clientID
        )
        
        // Render consent screen
        return try await view.render("oauth/consent", [
            "csrf_token": authorizationRequestObject.csrfToken,
            "client_name": client.name,
            "scopes": authorizationRequestObject.scope,
            "redirect_uri": authorizationRequestObject.redirectURI.string
        ])
    }
}
```

The consent template should include:
```html
<form method="POST" action="/oauth/authorize">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <input type="hidden" name="approve" value="true">
    <!-- Display scopes and client info -->
    <button type="submit">Approve</button>
    <button type="submit" name="approve" value="false">Deny</button>
</form>
```

### Token Manager Implementation

Your `TokenManager` needs to handle token generation, storage, and validation:

```swift
struct MyTokenManager: TokenManager {
    func generateAccessToken(
        clientID: String,
        userID: String?,
        scopes: [String]?,
        expiryTime: Int
    ) async throws -> OAuthAccessToken {
        let token = OAuthAccessToken(
            tokenString: UUID().uuidString,
            clientID: clientID,
            userID: userID,
            scopes: scopes,
            expiryTime: Date().addingTimeInterval(TimeInterval(expiryTime))
        )
        
        try await saveToken(token)
        return token
    }
    
    func generateRefreshToken(
        clientID: String,
        userID: String?,
        scopes: [String]?
    ) async throws -> OAuthRefreshToken {
        // Similar implementation
    }
    
    // Additional required methods...
}
```

### Code Manager Implementation

For the Authorization Code flow, implement `CodeManager`:

```swift
struct MyCodeManager: CodeManager {
    func generateCode(
        userID: String,
        clientID: String,
        redirectURI: String,
        scopes: [String]?,
        codeChallenge: String?,
        codeChallengeMethod: String?
    ) async throws -> String {
        let code = OAuthCode(
            codeID: UUID().uuidString,
            clientID: clientID,
            redirectURI: redirectURI,
            userID: userID,
            expiryDate: Date().addingTimeInterval(60), // 60 second expiry
            scopes: scopes,
            codeChallenge: codeChallenge,
            codeChallengeMethod: codeChallengeMethod
        )
        
        try await saveCode(code)
        return code.codeID
    }
    
    // Additional required methods...
}
```

### Device Code Manager Implementation

For the Device Authorization flow:

```swift
struct MyDeviceCodeManager: DeviceCodeManager {
    func generateDeviceCode(
        clientID: String,
        scopes: [String]?,
        verificationURI: String,
        verificationURIComplete: String?
    ) async throws -> OAuthDeviceCode? {
        let deviceCode = OAuthDeviceCode(
            deviceCode: UUID().uuidString,
            userCode: generateUserCode(), // e.g., "WDJB-MJHT"
            clientID: clientID,
            scopes: scopes,
            expiryDate: Date().addingTimeInterval(1800), // 30 minute expiry
            interval: 5, // 5 second polling interval
            verificationURI: verificationURI,
            verificationURIComplete: verificationURIComplete
        )
        
        try await saveDeviceCode(deviceCode)
        return deviceCode
    }
    
    // Additional required methods...
}
```

### Rate Limiting

Implement rate limiting for sensitive endpoints:

```swift
app.grouped(
    RateLimiter(
        maxRequests: 5,
        window: .minute
    )
).post("oauth", "token") { ... }
```

### Error Handling

Implement proper OAuth error responses:

```swift
struct OAuthError: AbortError {
    var status: HTTPStatus
    var reason: String
    var description: String
    var error: String
    
    static func invalidRequest(
        description: String
    ) -> OAuthError {
        OAuthError(
            status: .badRequest,
            reason: "invalid_request",
            description: description,
            error: "invalid_request"
        )
    }
    
    // Additional error types...
}
```

### Security Headers

Add security headers to all responses:

```swift
app.middleware.use(SecurityHeadersMiddleware(
    contentSecurityPolicy: "default-src 'self'",
    xFrameOptions: "DENY",
    xContentTypeOptions: "nosniff",
    referrerPolicy: "strict-origin-when-cross-origin"
))
```
