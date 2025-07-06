import JWTKit
import XCTVapor

@testable import VaporOAuth

class JWTIntegrationTests: XCTestCase {

    var app: Application!
    var jwtConfiguration: JWTConfiguration!
    var tokenManager: JWTTokenManager!
    var fakeClientGetter: FakeClientGetter!
    var fakeCodeManager: FakeCodeManager!

    override func setUp() async throws {
        jwtConfiguration = await JWTConfiguration.hmac(
            issuer: "test-issuer",
            secret: "test-secret-key-for-jwt-signing",
            useJWT: true
        )

        let storage = InMemoryTokenStorage()
        tokenManager = JWTTokenManager(configuration: jwtConfiguration, storage: storage)
        fakeClientGetter = FakeClientGetter()
        fakeCodeManager = FakeCodeManager()

        app = try await TestDataBuilder.getOAuth2Application(
            codeManager: fakeCodeManager,
            tokenManager: tokenManager,
            clientRetriever: fakeClientGetter,
            jwtConfiguration: jwtConfiguration
        )
    }

    override func tearDown() async throws {
        try await app.asyncShutdown()
        try await super.tearDown()
    }

    // MARK: - JWT Authorization Code Flow Tests

    func testJWTAuthorizationCodeFlow() async throws {
        let clientID = "test-client"
        let clientSecret = "test-secret"
        let userID = "test-user"
        let scope = "read write"

        // Create test client
        let client = OAuthClient(
            clientID: clientID,
            redirectURIs: ["http://localhost:8080/callback"],
            clientSecret: clientSecret,
            allowedGrantType: .authorization
        )

        // Register the test client in the shared app's client retriever
        fakeClientGetter.validClients[clientID] = client

        // Use the main app instance instead of creating a new one
        guard let testApp = app else {
            XCTFail("App not initialized")
            return
        }

        // Step 1: Authorization request
        let authResponse = try await testApp.sendRequest(
            .GET,
            "/oauth/authorize?response_type=code&client_id=\(clientID)&redirect_uri=http://localhost:8080/callback&scope=\(scope)"
        )

        XCTAssertEqual(authResponse.status, .ok)

        // Step 2: Get authorization code (simulate user consent)
        let code = try await fakeCodeManager.generateCode(
            userID: userID,
            clientID: clientID,
            redirectURI: "http://localhost:8080/callback",
            scopes: scope.components(separatedBy: " "),
            codeChallenge: nil,
            codeChallengeMethod: nil
        )

        // Step 3: Token exchange
        let tokenResponse = try await testApp.sendRequest(
            .POST,
            "/oauth/token",
            beforeRequest: { req in
                req.headers.contentType = .urlEncodedForm
                try req.content.encode([
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": clientID,
                    "client_secret": clientSecret,
                    "redirect_uri": "http://localhost:8080/callback",
                ])
            }
        )

        XCTAssertEqual(tokenResponse.status, HTTPStatus.ok)

        let tokenData = try tokenResponse.content.decode(TokenResponse.self)
        XCTAssertNotNil(tokenData.accessToken)
        XCTAssertNotNil(tokenData.refreshToken)
        XCTAssertEqual(tokenData.tokenType, "bearer")
        XCTAssertEqual(tokenData.expiresIn, 3600)
        XCTAssertEqual(tokenData.scope, scope)

        // Verify the access token is a JWT
        XCTAssertTrue(tokenData.accessToken!.contains("."))

        // Verify the JWT can be decoded
        let payload = try await jwtConfiguration.keyCollection.verify(tokenData.accessToken!, as: JWTAccessToken.self)

        XCTAssertEqual(payload.iss.value, jwtConfiguration.issuer)
        XCTAssertEqual(payload.sub.value, userID)
        XCTAssertEqual(payload.aud.value, [clientID])
        XCTAssertEqual(payload.scope, scope)
        XCTAssertEqual(payload.clientID, clientID)
        XCTAssertEqual(payload.tokenType, "Bearer")

        // No cleanup needed since we're using the main app instance
    }

    func testJWTClientCredentialsFlow() async throws {
        let clientID = "test-client"
        let clientSecret = "test-secret"
        let scope = "read write"

        // Create test client
        let client = OAuthClient(
            clientID: clientID,
            redirectURIs: [],
            clientSecret: clientSecret,
            confidential: true,
            allowedGrantType: .clientCredentials
        )

        // Create a new app with the client retriever
        let _ = StaticClientRetriever(clients: [client])

        // Use the main app instance instead of creating a new one
        // This avoids the shutdown issue with .running method
        guard let testApp = app else {
            XCTFail("App not initialized")
            return
        }

        fakeClientGetter.validClients[clientID] = client

        // Token request
        let tokenResponse = try await testApp.sendRequest(
            .POST,
            "/oauth/token",
            beforeRequest: { req in
                req.headers.contentType = .urlEncodedForm
                try req.content.encode([
                    "grant_type": "client_credentials",
                    "client_id": clientID,
                    "client_secret": clientSecret,
                    "scope": scope,
                ])
            }
        )

        XCTAssertEqual(tokenResponse.status, .ok)

        let tokenData = try tokenResponse.content.decode(TokenResponse.self)
        XCTAssertNotNil(tokenData.accessToken)
        XCTAssertNil(tokenData.refreshToken)  // Client credentials flow doesn't return refresh tokens
        XCTAssertEqual(tokenData.tokenType, "bearer")
        XCTAssertEqual(tokenData.expiresIn, 3600)
        XCTAssertEqual(tokenData.scope, scope)

        // Verify the access token is a JWT
        XCTAssertTrue(tokenData.accessToken!.contains("."))

        // Verify the JWT can be decoded
        let payload = try await jwtConfiguration.keyCollection.verify(tokenData.accessToken!, as: JWTAccessToken.self)

        XCTAssertEqual(payload.iss.value, jwtConfiguration.issuer)
        XCTAssertEqual(payload.sub.value, "")  // Empty subject for client credentials
        XCTAssertEqual(payload.aud.value, [clientID])
        XCTAssertEqual(payload.scope, scope)
        XCTAssertEqual(payload.clientID, clientID)
        XCTAssertEqual(payload.tokenType, "Bearer")

        // No cleanup needed since we're using the main app instance
    }

    func testJWTRefreshTokenFlow() async throws {
        let clientID = "test-client"
        let clientSecret = "test-secret"
        let userID = "test-user"
        let scope = "read write"

        // Create test client
        let client = OAuthClient(
            clientID: clientID,
            redirectURIs: ["http://localhost:8080/callback"],
            clientSecret: clientSecret,
            confidential: true,
            allowedGrantType: .authorization
        )

        // Register the test client in the shared app's client retriever
        fakeClientGetter.validClients[clientID] = client

        // Use the main app instance instead of creating a new one
        guard let testApp = app else {
            XCTFail("App not initialized")
            return
        }

        // Generate initial tokens
        let (_, refreshToken) = try await tokenManager.generateAccessRefreshTokens(
            clientID: clientID,
            userID: userID,
            scopes: scope.components(separatedBy: " "),
            accessTokenExpiryTime: 3600
        )

        // Refresh token request
        let tokenResponse = try await testApp.sendRequest(
            .POST,
            "/oauth/token",
            beforeRequest: { req in
                req.headers.contentType = .urlEncodedForm
                try req.content.encode([
                    "grant_type": "refresh_token",
                    "refresh_token": refreshToken.tokenString,
                    "client_id": clientID,
                    "client_secret": clientSecret,
                ])
            }
        )

        XCTAssertEqual(tokenResponse.status, .ok)

        let tokenData = try tokenResponse.content.decode(TokenResponse.self)
        XCTAssertNotNil(tokenData.accessToken)
        XCTAssertNotNil(tokenData.refreshToken)
        XCTAssertEqual(tokenData.tokenType, "bearer")
        XCTAssertEqual(tokenData.expiresIn, 3600)
        XCTAssertEqual(tokenData.scope, scope)

        // Verify the new access token is a JWT
        XCTAssertTrue(tokenData.accessToken!.contains("."))

        // Verify the JWT can be decoded
        let payload = try await jwtConfiguration.keyCollection.verify(tokenData.accessToken!, as: JWTAccessToken.self)

        XCTAssertEqual(payload.iss.value, jwtConfiguration.issuer)
        XCTAssertEqual(payload.sub.value, userID)
        XCTAssertEqual(payload.aud.value, [clientID])
        XCTAssertEqual(payload.scope, scope)
        XCTAssertEqual(payload.clientID, clientID)
        XCTAssertEqual(payload.tokenType, "Bearer")

        // No cleanup needed since we're using the main app instance
    }

    func testJWKSEndpoint() async throws {
        // Test JWKS endpoint
        let jwksResponse = try await app.sendRequest(.GET, "/.well-known/jwks.json")

        XCTAssertEqual(jwksResponse.status, .ok)

        let jwks = try jwksResponse.content.decode(JWKS.self)

        // For HMAC keys, JWKS should be empty (as per RFC 7517 security best practices)
        // HMAC keys are symmetric and should not be exposed in JWKS
        XCTAssertEqual(jwks.keys.count, 0)

        // Verify the response structure is valid JWKS
        XCTAssertNotNil(jwks.keys)
    }

    func testJWKSEndpointWithMultipleKeys() async throws {
        // Create a multi-key configuration with RSA + ECDSA
        let multiKeyConfig = try await JWTConfiguration.multiKey(
            issuer: "test-issuer",
            rsaPrivateKeyPEM: TestDataBuilder.rsaPrivateKeyPEM,
            ecdsaPrivateKeyPEM: TestDataBuilder.ecdsaPrivateKeyPEM,
            useJWT: true
        )

        let multiKeyApp = try await TestDataBuilder.getOAuth2Application(
            tokenManager: tokenManager,
            jwtConfiguration: multiKeyConfig
        )

        // Test JWKS endpoint
        let jwksResponse = try await multiKeyApp.sendRequest(.GET, "/.well-known/jwks.json")
        XCTAssertEqual(jwksResponse.status, .ok)

        let jwks = try jwksResponse.content.decode(JWKS.self)
        // Should have 2 public JWKs (RSA + ECDSA)
        XCTAssertEqual(jwks.keys.count, 2)

        let rsaKeys = jwks.keys.filter { $0.keyType == .rsa }
        let ecdsaKeys = jwks.keys.filter { $0.keyType == .ecdsa }

        XCTAssertEqual(rsaKeys.count, 1)
        XCTAssertEqual(ecdsaKeys.count, 1)

        // Verify the response structure is valid JWKS
        XCTAssertNotNil(jwks.keys)

        // Cleanup
        try await multiKeyApp.asyncShutdown()
    }

    func testJWKSEndpointDisabled() async throws {
        // Create app with JWT disabled
        let disabledConfig = JWTConfiguration.disabled
        let disabledApp = try await TestDataBuilder.getOAuth2Application(
            tokenManager: tokenManager,
            jwtConfiguration: disabledConfig
        )

        // Test JWKS endpoint should return 404
        let jwksResponse = try await disabledApp.sendRequest(.GET, "/.well-known/jwks.json")
        XCTAssertEqual(jwksResponse.status, .notFound)

        // Cleanup - ensure proper shutdown
        try await disabledApp.asyncShutdown()
    }

    func testSimpleClientCredentialsFlow() async throws {
        let clientID = "test-client"
        let clientSecret = "test-secret"
        let scope = "read write"

        // Create test client
        let client = OAuthClient(
            clientID: clientID,
            redirectURIs: [],
            clientSecret: clientSecret,
            confidential: true,
            allowedGrantType: .clientCredentials
        )

        // Register the test client in the shared app's client retriever
        fakeClientGetter.validClients[clientID] = client

        // Use the main app instance instead of creating a new one
        guard let testApp = app else {
            XCTFail("App not initialized")
            return
        }

        // Token request
        let tokenResponse = try await testApp.sendRequest(
            .POST,
            "/oauth/token",
            beforeRequest: { req in
                req.headers.contentType = .urlEncodedForm
                try req.content.encode([
                    "grant_type": "client_credentials",
                    "client_id": clientID,
                    "client_secret": clientSecret,
                    "scope": scope,
                ])
            }
        )

        XCTAssertEqual(tokenResponse.status, .ok)

        let tokenData = try tokenResponse.content.decode(TokenResponse.self)
        XCTAssertNotNil(tokenData.accessToken)
        XCTAssertNil(tokenData.refreshToken)  // Client credentials flow doesn't return refresh tokens
        XCTAssertEqual(tokenData.tokenType, "bearer")
        XCTAssertEqual(tokenData.expiresIn, 3600)
        XCTAssertEqual(tokenData.scope, scope)

        // No cleanup needed since we're using the main app instance
    }
}

// MARK: - Test Helpers

struct TokenResponse: Content {
    let accessToken: String?
    let refreshToken: String?
    let tokenType: String
    let expiresIn: Int
    let scope: String?

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case scope
    }
}
