import XCTVapor

@testable import VaporOAuth

class MetadataEndpointTests: XCTestCase {
    var app: Application!
    let issuer = "https://auth.example.com"
    let jwksEndpoint = "https://auth.example.com/.well-known/jwks.json"

    override func setUp() async throws {
        app = try await Application.make(.testing)
    }

    override func tearDown() async throws {
        try await app.asyncShutdown()
        try await super.tearDown()
    }

    // MARK: - RFC Compliance Tests

    func testRequiredRFCFields() async throws {
        // Create a JWT configuration to enable JWKS endpoint
        let jwtConfig = await JWTConfiguration.hmac(
            issuer: issuer,
            secret: "test-secret-key",
            useJWT: true
        )

        let oauthProvider = OAuth2(
            tokenManager: FakeTokenManager(),
            clientRetriever: StaticClientRetriever(clients: []),
            oAuthHelper: .local(
                tokenAuthenticator: TokenAuthenticator(),
                userManager: FakeUserManager(),
                tokenManager: FakeTokenManager()
            ),
            metadataProvider: DefaultServerMetadataProvider(
                issuer: issuer,
                validScopes: nil,
                clientRetriever: StaticClientRetriever(clients: []),
                hasCodeManager: true,
                hasDeviceCodeManager: false,
                hasTokenIntrospection: false,
                hasUserManager: true,
                jwksEndpoint: jwksEndpoint,
                jwtConfiguration: jwtConfig
            )
        )

        app.lifecycle.use(oauthProvider)

        // Manually trigger the lifecycle handler since testable() doesn't do it
        try await oauthProvider.didBoot(app)

        let _ = try app.testable(method: .running)

        try await app.test(.GET, ".well-known/oauth-authorization-server") { response in
            XCTAssertEqual(response.status, .ok)
            XCTAssertEqual(response.headers.contentType, .json)

            let metadata = try response.content.decode(OAuthServerMetadata.self)

            // Required fields per RFC 8414
            XCTAssertEqual(metadata.issuer, issuer)
            XCTAssertEqual(metadata.authorizationEndpoint, "\(issuer)/oauth/authorize")
            XCTAssertEqual(metadata.tokenEndpoint, "\(issuer)/oauth/token")
            XCTAssertEqual(metadata.jwksUri, jwksEndpoint)
            XCTAssertFalse(metadata.responseTypesSupported.isEmpty)
            XCTAssertFalse(metadata.subjectTypesSupported.isEmpty)
            XCTAssertFalse(metadata.idTokenSigningAlgValuesSupported.isEmpty)
        }
    }

    func testFullConfigurationWithAllFeatures() async throws {
        let validScopes = ["profile", "email"]

        // Create a JWT configuration to enable JWKS endpoint
        let jwtConfig = await JWTConfiguration.hmac(
            issuer: issuer,
            secret: "test-secret-key",
            useJWT: true
        )

        let oauthProvider = OAuth2(
            codeManager: FakeCodeManager(),
            tokenManager: FakeTokenManager(),
            deviceCodeManager: FakeDeviceCodeManager(),
            clientRetriever: StaticClientRetriever(clients: []),
            authorizeHandler: FakeAuthorizationHandler(),
            userManager: FakeUserManager(),
            validScopes: validScopes,
            resourceServerRetriever: FakeResourceServerRetriever(),
            oAuthHelper: .local(
                tokenAuthenticator: TokenAuthenticator(),
                userManager: FakeUserManager(),
                tokenManager: FakeTokenManager()
            ),
            metadataProvider: DefaultServerMetadataProvider(
                issuer: issuer,
                validScopes: validScopes,
                clientRetriever: StaticClientRetriever(clients: []),
                hasCodeManager: true,
                hasDeviceCodeManager: true,
                hasTokenIntrospection: true,
                hasUserManager: true,
                jwksEndpoint: jwksEndpoint,
                jwtConfiguration: jwtConfig
            )
        )

        app.lifecycle.use(oauthProvider)

        // Manually trigger the lifecycle handler since testable() doesn't do it
        try await oauthProvider.didBoot(app)

        let _ = try app.testable(method: .running)

        try await app.test(.GET, ".well-known/oauth-authorization-server") { response in
            let metadata = try response.content.decode(OAuthServerMetadata.self)

            // Verify all supported features are included
            XCTAssertEqual(
                Set(metadata.grantTypesSupported ?? []),
                [
                    OAuthFlowType.authorization.rawValue,
                    OAuthFlowType.clientCredentials.rawValue,
                    OAuthFlowType.deviceCode.rawValue,
                    OAuthFlowType.refresh.rawValue,
                    OAuthFlowType.password.rawValue,  // Note: Password grant is deprecated in OAuth 2.1
                ])

            XCTAssertEqual(metadata.scopesSupported, validScopes)
            XCTAssertEqual(Set(metadata.responseTypesSupported), ["code", "token"])
            XCTAssertEqual(metadata.codeChallengeMethodsSupported, ["S256", "plain"])

            // Verify all endpoints are present
            XCTAssertEqual(metadata.tokenIntrospectionEndpoint, "\(issuer)/oauth/token_info")
            XCTAssertEqual(metadata.tokenRevocationEndpoint, "\(issuer)/oauth/revoke")
            XCTAssertEqual(metadata.deviceAuthorizationEndpoint, "\(issuer)/oauth/device_authorization")
        }
    }

    // MARK: - Custom Override Tests

    func testCustomMetadataProvider() async throws {
        // Custom metadata provider with non-standard endpoints and configurations
        struct CustomMetadataProvider: ServerMetadataProvider {
            func getMetadata() async throws -> OAuthServerMetadata {
                return OAuthServerMetadata(
                    issuer: "https://custom.example.com",
                    authorizationEndpoint: "https://auth.custom.example.com/v2/authorize",
                    tokenEndpoint: "https://api.custom.example.com/v2/token",
                    jwksUri: "https://keys.custom.example.com/v2/jwks",
                    responseTypesSupported: ["code", "jwt"],
                    subjectTypesSupported: ["pairwise"],
                    idTokenSigningAlgValuesSupported: ["ES256", "PS256"],

                    // Recommended fields with custom values
                    scopesSupported: ["custom.read", "custom.write"],
                    tokenEndpointAuthMethodsSupported: ["private_key_jwt", "client_secret_jwt"],
                    grantTypesSupported: ["authorization_code", "custom_grant"],
                    userinfoEndpoint: "https://api.custom.example.com/v2/userinfo",
                    registrationEndpoint: "https://api.custom.example.com/v2/register",
                    claimsSupported: ["sub", "custom_claim"],

                    // Optional fields with custom configurations
                    tokenIntrospectionEndpoint: "https://api.custom.example.com/v2/introspect",
                    tokenRevocationEndpoint: "https://api.custom.example.com/v2/revoke",
                    serviceDocumentation: "https://docs.custom.example.com",
                    uiLocalesSupported: ["en-US", "es-ES"],
                    opPolicyUri: "https://custom.example.com/policy",
                    opTosUri: "https://custom.example.com/terms",
                    revocationEndpointAuthMethodsSupported: ["private_key_jwt"],
                    revocationEndpointAuthSigningAlgValuesSupported: ["ES256"],
                    introspectionEndpointAuthMethodsSupported: ["private_key_jwt"],
                    introspectionEndpointAuthSigningAlgValuesSupported: ["ES256"],
                    codeChallengeMethodsSupported: ["S256"],
                    deviceAuthorizationEndpoint: "https://api.custom.example.com/v2/device"
                )
            }
        }

        let oauthProvider = OAuth2(
            tokenManager: FakeTokenManager(),
            clientRetriever: StaticClientRetriever(clients: []),
            oAuthHelper: .local(
                tokenAuthenticator: TokenAuthenticator(),
                userManager: FakeUserManager(),
                tokenManager: FakeTokenManager()
            ),
            metadataProvider: CustomMetadataProvider()
        )

        app.lifecycle.use(oauthProvider)

        // Manually trigger the lifecycle handler since testable() doesn't do it
        try await oauthProvider.didBoot(app)

        let _ = try app.testable(method: .running)

        try await app.test(.GET, ".well-known/oauth-authorization-server") { response in
            XCTAssertEqual(response.status, .ok)

            let metadata = try response.content.decode(OAuthServerMetadata.self)

            // Verify custom issuer and endpoints
            XCTAssertEqual(metadata.issuer, "https://custom.example.com")
            XCTAssertEqual(metadata.authorizationEndpoint, "https://auth.custom.example.com/v2/authorize")
            XCTAssertEqual(metadata.tokenEndpoint, "https://api.custom.example.com/v2/token")
            XCTAssertEqual(metadata.jwksUri, "https://keys.custom.example.com/v2/jwks")

            // Verify custom response types and subject types
            XCTAssertEqual(Set(metadata.responseTypesSupported), ["code", "jwt"])
            XCTAssertEqual(metadata.subjectTypesSupported, ["pairwise"])

            // Verify custom scopes and grant types
            XCTAssertEqual(metadata.scopesSupported, ["custom.read", "custom.write"])
            XCTAssertEqual(Set(metadata.grantTypesSupported ?? []), ["authorization_code", "custom_grant"])

            // Verify custom endpoints
            XCTAssertEqual(metadata.userinfoEndpoint, "https://api.custom.example.com/v2/userinfo")
            XCTAssertEqual(metadata.registrationEndpoint, "https://api.custom.example.com/v2/register")

            // Verify custom auth methods
            XCTAssertEqual(Set(metadata.tokenEndpointAuthMethodsSupported ?? []), ["private_key_jwt", "client_secret_jwt"])

            // Verify additional custom fields
            XCTAssertEqual(metadata.serviceDocumentation, "https://docs.custom.example.com")
            XCTAssertEqual(metadata.uiLocalesSupported, ["en-US", "es-ES"])
        }
    }
    // MARK: - Error Cases
    func testMetadataEndpointRequiredHeaders() async throws {
        let oauthProvider = OAuth2(
            tokenManager: FakeTokenManager(),
            clientRetriever: StaticClientRetriever(clients: []),
            oAuthHelper: .local(
                tokenAuthenticator: TokenAuthenticator(),
                userManager: FakeUserManager(),
                tokenManager: FakeTokenManager()
            )
        )

        app.lifecycle.use(oauthProvider)

        // Manually trigger the lifecycle handler since testable() doesn't do it
        try await oauthProvider.didBoot(app)

        let _ = try app.testable(method: .running)

        try await app.test(.GET, ".well-known/oauth-authorization-server") { response in
            // Verify content type
            XCTAssertEqual(response.headers.contentType, .json)

            // Verify cache control headers
            let cacheControl = response.headers[.cacheControl].first
            XCTAssertNotNil(cacheControl)
            XCTAssertTrue(cacheControl?.contains("no-store") ?? false)
            XCTAssertTrue(cacheControl?.contains("no-cache") ?? false)
            XCTAssertTrue(cacheControl?.contains("must-revalidate") ?? false)

            // Verify pragma header
            XCTAssertEqual(response.headers[.pragma].first, "no-cache")
        }
    }
}
