import NIOSSL
import Fluent
import FluentSQLiteDriver
import Vapor
import VaporOAuth
import Leaf

// configures your application
public func configure(_ app: Application) async throws {
    // uncomment to serve files from /Public folder
    app.middleware.use(FileMiddleware(publicDirectory: app.directory.publicDirectory))

    // Configure sessions middleware
    app.middleware.use(app.sessions.middleware)
    
    // Add OAuth user bridge middleware
    app.middleware.use(OAuthUserBridgeMiddleware())

    // Configure Leaf templating
    app.views.use(.leaf)
    app.leaf.cache.isEnabled = app.environment.isRelease

    app.databases.use(DatabaseConfigurationFactory.sqlite(.file("db.sqlite")), as: .sqlite)

    // Configure sessions
    app.sessions.use(.fluent(.sqlite))
    app.sessions.configuration.cookieName = "vapor-session"

    // Register migrations
    app.migrations.add(CreateTodo())
    app.migrations.add(CreateUser())
    app.migrations.add(CreateSession())
    app.migrations.add(CreateOAuthAccessToken())
    app.migrations.add(CreateOAuthRefreshToken())
    app.migrations.add(CreateOAuthClient())
    app.migrations.add(CreateOAuthCode())
    app.migrations.add(CreateOAuthDeviceCode())
    app.migrations.add(CreateOAuthResourceServer())
    
    // Run migrations first
    try await app.autoMigrate().get()
    
    // Register services
    app.authService(AuthService(db: app.db))
    app.sessionService(SessionService(db: app.db))
    
    // Configure OAuth2 after migrations are complete
    try await configureOAuth(app)

    // register routes
    try routes(app)
}

private func configureOAuth(_ app: Application) async throws {
    // Set up OAuth configuration (PKCE and CSRF are enabled by default in vapor-oauth)
    app.oauth = OAuthConfiguration(deviceVerificationURI: "http://localhost:8080/device")
    
    // Register OAuth services using Vapor's service pattern
    app.oauthTokenManager = FluentTokenManager(db: app.db)
    app.oauthClientRetriever = FluentClientRetriever(db: app.db)
    app.oauthCodeManager = FluentCodeManager(db: app.db)
    app.oauthDeviceCodeManager = FluentDeviceCodeManager(db: app.db)
    app.oauthResourceServerRetriever = FluentResourceServerRetriever(db: app.db)
    
    // Create OAuth helper
    let oAuthHelper = OAuthHelper(
        assertScopes: { scopes, req in
            // For demo, always allow scopes
        },
        user: { req in
            // Get user from session
            guard let sessionToken = req.cookies["session_token"]?.string,
                  let userID = try await req.sessionService.validateSession(sessionToken),
                  let user = try await User.find(userID, on: req.db) else {
                // Return anonymous user if no session
                return OAuthUser(
                    userID: "anonymous",
                    username: "anonymous",
                    emailAddress: "anonymous@example.com",
                    password: "password"
                )
            }
            
            // Convert User to OAuthUser
            return user.toOAuthUser()
        }
    )
    
    // Create custom metadata provider
    let metadataProvider = CustomServerMetadataProvider(
        issuer: "http://localhost:8080",
        validScopes: ["read", "write", "admin"]
    )
    
    // Initialize OAuth2 server with all security features
    let oauth2 = OAuth2(
        codeManager: app.oauthCodeManager,
        tokenManager: app.oauthTokenManager,
        deviceCodeManager: app.oauthDeviceCodeManager,
        clientRetriever: app.oauthClientRetriever,
        authorizeHandler: OAuthAuthorizationHandler(),
        validScopes: ["read", "write", "admin"],
        resourceServerRetriever: app.oauthResourceServerRetriever,
        oAuthHelper: oAuthHelper,
        metadataProvider: metadataProvider
    )
    
    // Register the OAuth2 lifecycle handler
    app.lifecycle.use(oauth2)
    
    // Seed the database with a sample client after OAuth is configured
    try await seedSampleClient(on: app.db)
    
    // Seed with a demo user
    try await seedDemoUser(on: app.db)
}

private func seedSampleClient(on db: any Database) async throws {
    // Check if sample client already exists
    let existingClient = try await OAuthClientModel.query(on: db)
        .filter(\.$clientID == "sample-client")
        .first()
    
    if existingClient == nil {
        let sampleClient = OAuthClientModel(
            clientID: "sample-client",
            clientSecret: "sample-secret",
            redirectURIs: ["http://localhost:8080/callback"],
            validScopes: ["read", "write"],
            confidentialClient: true,
            firstParty: false,
            allowedGrantType: "authorization_code"
        )
        
        try await sampleClient.save(on: db)
    }
    
    // Check if device client already exists
    let existingDeviceClient = try await OAuthClientModel.query(on: db)
        .filter(\.$clientID == "device-client")
        .first()
    
    if existingDeviceClient == nil {
        let deviceClient = OAuthClientModel(
            clientID: "device-client",
            clientSecret: "device-secret",
            redirectURIs: ["http://localhost:8080/callback"],
            validScopes: ["read", "write"],
            confidentialClient: true,
            firstParty: false,
            allowedGrantType: "device_code"
        )
        
        try await deviceClient.save(on: db)
    }
    
    // Check if client credentials client already exists
    let existingClientCredentialsClient = try await OAuthClientModel.query(on: db)
        .filter(\.$clientID == "client-credentials-client")
        .first()
    
    if existingClientCredentialsClient == nil {
        let clientCredentialsClient = OAuthClientModel(
            clientID: "client-credentials-client",
            clientSecret: "client-credentials-secret",
            redirectURIs: [], // Client credentials doesn't use redirect URIs
            validScopes: ["read", "write", "admin"],
            confidentialClient: true,
            firstParty: false,
            allowedGrantType: "client_credentials"
        )
        
        try await clientCredentialsClient.save(on: db)
    }
    
    // Check if refresh token client already exists
    let existingRefreshTokenClient = try await OAuthClientModel.query(on: db)
        .filter(\.$clientID == "refresh-token-client")
        .first()
    
    if existingRefreshTokenClient == nil {
        let refreshTokenClient = OAuthClientModel(
            clientID: "refresh-token-client",
            clientSecret: "refresh-token-secret",
            redirectURIs: ["http://localhost:8080/callback"],
            validScopes: ["read", "write", "admin"],
            confidentialClient: true,
            firstParty: false,
            allowedGrantType: "authorization_code" // Refresh tokens come from auth code flow
        )
        
        try await refreshTokenClient.save(on: db)
    }
    
    // Check if resource server already exists
    let existingResourceServer = try await OAuthResourceServerModel.query(on: db)
        .filter(\.$username == "resource-server")
        .first()
    
    if existingResourceServer == nil {
        let resourceServer = OAuthResourceServerModel(
            username: "resource-server",
            password: "resource-server-secret"
        )
        
        try await resourceServer.save(on: db)
    }
}

private func seedDemoUser(on db: any Database) async throws {
    // Check if demo user already exists
    let existingUser = try await User.query(on: db)
        .filter(\.$username == "demo")
        .first()
    
    if existingUser == nil {
        let hashedPassword = try Bcrypt.hash("password123")
        let demoUser = User(
            username: "demo",
            email: "demo@example.com",
            passwordHash: hashedPassword,
            firstName: "Demo",
            lastName: "User"
        )
        
        try await demoUser.save(on: db)
    }
}

struct OAuthUserSessionAuthenticator: AsyncSessionAuthenticator {
    public typealias User = OAuthUser

    public func authenticate(sessionID: String, for request: Vapor.Request) async throws {
        let user = OAuthUser(
            userID: "1",
            username: "marius",
            emailAddress: "marius.seufzer@code.berlin",
            password: "password"
        )
        request.auth.login(user)
    }
}

extension OAuthUser: SessionAuthenticatable {
    public var sessionID: String { self.id ?? "" }
}

// Custom metadata provider for the OAuth server
struct CustomServerMetadataProvider: ServerMetadataProvider {
    let issuer: String
    let validScopes: [String]
    
    func getMetadata() async throws -> OAuthServerMetadata {
        let baseURL = issuer.hasSuffix("/") ? String(issuer.dropLast()) : issuer
        
        return OAuthServerMetadata(
            // Required metadata fields per RFC 8414
            issuer: issuer,
            authorizationEndpoint: "\(baseURL)/oauth/authorize",
            tokenEndpoint: "\(baseURL)/oauth/token",
            jwksUri: "\(baseURL)/.well-known/jwks.json",
            responseTypesSupported: ["code", "token"],
            subjectTypesSupported: ["public"],
            idTokenSigningAlgValuesSupported: ["RS256"],
            
            // Recommended metadata fields
            scopesSupported: validScopes,
            tokenEndpointAuthMethodsSupported: ["client_secret_basic", "client_secret_post"],
            grantTypesSupported: [
                "authorization_code",
                "client_credentials", 
                "refresh_token",
                "password",
                "urn:ietf:params:oauth:grant-type:device_code"
            ],
            userinfoEndpoint: "\(baseURL)/oauth/userinfo",
            registrationEndpoint: nil,
            claimsSupported: ["sub", "name", "email", "scope"],
            
            // Optional metadata fields
            tokenIntrospectionEndpoint: "\(baseURL)/oauth/token_info",
            tokenRevocationEndpoint: "\(baseURL)/oauth/revoke",
            serviceDocumentation: "\(baseURL)/demo",
            uiLocalesSupported: ["en-US"],
            opPolicyUri: "\(baseURL)/policy",
            opTosUri: "\(baseURL)/terms",
            revocationEndpointAuthMethodsSupported: ["client_secret_basic", "client_secret_post"],
            revocationEndpointAuthSigningAlgValuesSupported: nil,
            introspectionEndpointAuthMethodsSupported: ["client_secret_basic"],
            introspectionEndpointAuthSigningAlgValuesSupported: nil,
            codeChallengeMethodsSupported: ["S256", "plain"],
            deviceAuthorizationEndpoint: "\(baseURL)/oauth/device_authorization"
        )
    }
}