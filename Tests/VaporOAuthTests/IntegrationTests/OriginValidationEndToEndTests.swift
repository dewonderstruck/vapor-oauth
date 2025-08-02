import XCTVapor

@testable import VaporOAuth

final class OriginValidationEndToEndTests: XCTestCase {

    // MARK: - Properties

    var app: Application!
    var fakeClientRetriever: FakeClientGetter!
    var capturingAuthorizeHandler: CapturingAuthoriseHandler!
    var fakeCodeManager: FakeCodeManager!
    var fakeTokenManager: FakeTokenManager!
    var fakeSessions: FakeSessions!

    let scope1 = "email"
    let scope2 = "profile"
    let scope3 = "admin"
    let sessionID = "e2e-session-id"
    let csrfToken = "e2e-csrf-token"
    let testUser = TestDataBuilder.anyOAuthUser()

    // MARK: - Setup & Teardown

    override func setUp() async throws {
        fakeClientRetriever = FakeClientGetter()
        capturingAuthorizeHandler = CapturingAuthoriseHandler()
        fakeCodeManager = FakeCodeManager()
        fakeTokenManager = FakeTokenManager()

        fakeSessions = FakeSessions(
            sessions: [SessionID(string: sessionID): SessionData(initialData: ["CSRFToken": csrfToken])]
        )

        app = try TestDataBuilder.getOAuth2Application(
            codeManager: fakeCodeManager,
            tokenManager: fakeTokenManager,
            clientRetriever: fakeClientRetriever,
            authorizeHandler: capturingAuthorizeHandler,
            validScopes: [scope1, scope2, scope3],
            sessions: fakeSessions,
            registeredUsers: [testUser]
        )
    }

    override func tearDown() async throws {
        try await app.asyncShutdown()
        try await super.tearDown()
    }

    // MARK: - Full Authorization Code Flow End-to-End Tests

    func testFullAuthorizationCodeFlow_WithValidOrigin_CompleteEndToEnd() async throws {
        // Given - Client with authorized origins
        let clientID = "auth-code-client"
        let clientSecret = "auth-code-secret"
        let redirectURI = "https://app.example.com/callback"
        let authorizedOrigins = ["https://app.example.com", "*.staging.example.com"]
        
        let client = OAuthClient(
            clientID: clientID,
            redirectURIs: [redirectURI],
            clientSecret: clientSecret,
            validScopes: [scope1, scope2],
            allowedGrantType: .authorization,
            authorizedOrigins: authorizedOrigins
        )
        fakeClientRetriever.validClients[clientID] = client
        
        let testCode = "full-e2e-code"
        fakeCodeManager.generatedCode = testCode
        fakeTokenManager.accessTokenToReturn = "full-e2e-access-token"
        fakeTokenManager.refreshTokenToReturn = "full-e2e-refresh-token"

        // Step 1: Authorization request (GET) with valid origin
        let authGetResponse = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "code",
            clientID: clientID,
            redirectURI: redirectURI,
            scope: "\(scope1) \(scope2)",
            state: "e2e-state",
            origin: "https://app.example.com"
        )

        XCTAssertEqual(authGetResponse.status, .ok, "Authorization GET request should succeed with valid origin")

        // Step 2: User approves authorization (POST) with same valid origin
        let authPostResponse = try await TestDataBuilder.getPostAuthResponseWithOrigin(
            with: app,
            clientID: clientID,
            redirectURI: redirectURI,
            origin: "https://app.example.com",
            approve: true,
            state: "e2e-state",
            scope: "\(scope1) \(scope2)",
            user: testUser,
            csrfToken: csrfToken,
            sessionID: sessionID
        )

        XCTAssertEqual(authPostResponse.status, .seeOther, "Authorization POST should redirect with code")
        let location = authPostResponse.headers.location?.value ?? ""
        XCTAssertTrue(location.contains("code=\(testCode)"), "Should contain authorization code")
        XCTAssertTrue(location.contains("state=e2e-state"), "Should preserve state parameter")

        // Step 3: Exchange code for token (no origin validation needed for token endpoint)
        let tokenResponse = try await TestDataBuilder.getTokenRequestResponse(
            with: app,
            grantType: "authorization_code",
            clientID: clientID,
            clientSecret: clientSecret,
            redirectURI: redirectURI,
            code: testCode
        )

        XCTAssertEqual(tokenResponse.status, .ok, "Token exchange should succeed")
        
        struct TokenResponse: Decodable {
            let accessToken: String?
            let refreshToken: String?
            let tokenType: String?
            let expiresIn: Int?
            let scope: String?
            
            enum CodingKeys: String, CodingKey {
                case accessToken = "access_token"
                case refreshToken = "refresh_token"
                case tokenType = "token_type"
                case expiresIn = "expires_in"
                case scope
            }
        }
        
        let tokenData = try JSONDecoder().decode(TokenResponse.self, from: tokenResponse.body)
        XCTAssertEqual(tokenData.accessToken, "full-e2e-access-token")
        XCTAssertEqual(tokenData.refreshToken, "full-e2e-refresh-token")
        XCTAssertEqual(tokenData.tokenType, "bearer")
        XCTAssertEqual(tokenData.expiresIn, 3600)
        XCTAssertEqual(tokenData.scope, "\(scope1) \(scope2)")
    }

    func testFullAuthorizationCodeFlow_WithInvalidOrigin_RejectsAtEachStep() async throws {
        // Given - Client with authorized origins
        let clientID = "auth-code-reject-client"
        let redirectURI = "https://app.example.com/callback"
        let authorizedOrigins = ["https://app.example.com"]
        
        let client = OAuthClient(
            clientID: clientID,
            redirectURIs: [redirectURI],
            clientSecret: "secret",
            validScopes: [scope1],
            allowedGrantType: .authorization,
            authorizedOrigins: authorizedOrigins
        )
        fakeClientRetriever.validClients[clientID] = client

        // Step 1: Authorization request (GET) with invalid origin should be rejected
        let authGetResponse = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "code",
            clientID: clientID,
            redirectURI: redirectURI,
            scope: scope1,
            state: "reject-state",
            origin: "https://malicious.com"
        )

        XCTAssertEqual(authGetResponse.status, .seeOther, "Should redirect with error")
        let getLocation = authGetResponse.headers.location?.value ?? ""
        XCTAssertTrue(getLocation.contains("error=unauthorized_client"), "Should contain unauthorized_client error")
        XCTAssertTrue(getLocation.contains("state=reject-state"), "Should preserve state in error response")

        // Step 2: Authorization POST with invalid origin should also be rejected
        let authPostResponse = try await TestDataBuilder.getPostAuthResponseWithOrigin(
            with: app,
            clientID: clientID,
            redirectURI: redirectURI,
            origin: "https://malicious.com",
            approve: true,
            state: "reject-post-state",
            scope: scope1,
            user: testUser,
            csrfToken: csrfToken,
            sessionID: sessionID
        )

        XCTAssertEqual(authPostResponse.status, .seeOther, "POST should also redirect with error")
        let postLocation = authPostResponse.headers.location?.value ?? ""
        XCTAssertTrue(postLocation.contains("error=unauthorized_client"), "POST should contain unauthorized_client error")
        XCTAssertTrue(postLocation.contains("state=reject-post-state"), "Should preserve state in POST error response")
    }

    func testFullAuthorizationCodeFlow_WithWildcardOrigin_WorksCorrectly() async throws {
        // Given - Client with wildcard authorized origins
        let clientID = "wildcard-client"
        let redirectURI = "https://app.example.com/callback"
        let authorizedOrigins = ["*.example.com"]
        
        let client = OAuthClient(
            clientID: clientID,
            redirectURIs: [redirectURI],
            clientSecret: "wildcard-secret",
            validScopes: [scope1, scope2],
            allowedGrantType: .authorization,
            authorizedOrigins: authorizedOrigins
        )
        fakeClientRetriever.validClients[clientID] = client
        
        fakeCodeManager.generatedCode = "wildcard-code"
        fakeTokenManager.accessTokenToReturn = "wildcard-access-token"

        // Test various subdomain patterns that should work
        let validOrigins = [
            "https://app.example.com",
            "https://api.example.com", 
            "https://staging.example.com",
            "https://v2-api.example.com"
        ]

        for (index, origin) in validOrigins.enumerated() {
            let state = "wildcard-state-\(index)"
            
            // Step 1: GET request should succeed
            let getResponse = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
                with: app,
                responseType: "code",
                clientID: clientID,
                redirectURI: redirectURI,
                scope: scope1,
                state: state,
                origin: origin
            )
            
            XCTAssertEqual(getResponse.status, .ok, "GET should succeed for origin: \(origin)")
            
            // Step 2: POST request should succeed
            let postResponse = try await TestDataBuilder.getPostAuthResponseWithOrigin(
                with: app,
                clientID: clientID,
                redirectURI: redirectURI,
                origin: origin,
                approve: true,
                state: state,
                scope: scope1,
                user: testUser,
                csrfToken: csrfToken,
                sessionID: sessionID
            )
            
            XCTAssertEqual(postResponse.status, .seeOther, "POST should succeed for origin: \(origin)")
            let location = postResponse.headers.location?.value ?? ""
            XCTAssertTrue(location.contains("code=wildcard-code"), "Should contain code for origin: \(origin)")
        }

        // Test invalid origins that should be rejected
        let invalidOrigins = [
            "https://example.com.evil.com",
            "https://notexample.com",
            "https://app.different.com"
        ]

        for invalidOrigin in invalidOrigins {
            let response = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
                with: app,
                responseType: "code",
                clientID: clientID,
                redirectURI: redirectURI,
                scope: scope1,
                state: "invalid-test",
                origin: invalidOrigin
            )
            
            XCTAssertEqual(response.status, .seeOther, "Should reject invalid origin: \(invalidOrigin)")
            let location = response.headers.location?.value ?? ""
            XCTAssertTrue(location.contains("error=unauthorized_client"), "Should contain error for origin: \(invalidOrigin)")
        }
    }

    // MARK: - Full Implicit Grant Flow End-to-End Tests

    func testFullImplicitFlow_WithValidOrigin_CompleteEndToEnd() async throws {
        // Given - Client configured for implicit grant with authorized origins
        let clientID = "implicit-client"
        let redirectURI = "https://spa.example.com/callback"
        let authorizedOrigins = ["https://spa.example.com", "https://app.example.com"]
        
        let client = OAuthClient(
            clientID: clientID,
            redirectURIs: [redirectURI],
            validScopes: [scope1, scope2],
            allowedGrantType: .implicit,
            authorizedOrigins: authorizedOrigins
        )
        fakeClientRetriever.validClients[clientID] = client
        
        fakeTokenManager.accessTokenToReturn = "implicit-access-token"

        // Step 1: Authorization request (GET) with valid origin
        let authGetResponse = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "token",
            clientID: clientID,
            redirectURI: redirectURI,
            scope: "\(scope1) \(scope2)",
            state: "implicit-state",
            origin: "https://spa.example.com"
        )

        XCTAssertEqual(authGetResponse.status, .ok, "Implicit GET request should succeed with valid origin")

        // Step 2: User approves authorization (POST) - should get token directly
        let authPostResponse = try await TestDataBuilder.getPostAuthResponseWithOrigin(
            with: app,
            clientID: clientID,
            redirectURI: redirectURI,
            responseType: "token",
            origin: "https://spa.example.com",
            approve: true,
            state: "implicit-state",
            scope: "\(scope1) \(scope2)",
            user: testUser,
            csrfToken: csrfToken,
            sessionID: sessionID
        )

        XCTAssertEqual(authPostResponse.status, .seeOther, "Implicit POST should redirect with token")
        let location = authPostResponse.headers.location?.value ?? ""
        XCTAssertTrue(location.contains("#"), "Implicit grant should use fragment")
        XCTAssertTrue(location.contains("access_token=implicit-access-token"), "Should contain access token")
        XCTAssertTrue(location.contains("token_type=bearer"), "Should specify bearer token type")
        XCTAssertTrue(location.contains("state=implicit-state"), "Should preserve state parameter")
        XCTAssertTrue(location.contains("scope=\(scope1)+\(scope2)"), "Should include granted scopes")
        XCTAssertFalse(location.contains("refresh_token"), "Implicit grant should not include refresh token")
    }

    func testFullImplicitFlow_WithInvalidOrigin_RejectsRequest() async throws {
        // Given - Client configured for implicit grant with authorized origins
        let clientID = "implicit-reject-client"
        let redirectURI = "https://spa.example.com/callback"
        let authorizedOrigins = ["https://spa.example.com"]
        
        let client = OAuthClient(
            clientID: clientID,
            redirectURIs: [redirectURI],
            validScopes: [scope1],
            allowedGrantType: .implicit,
            authorizedOrigins: authorizedOrigins
        )
        fakeClientRetriever.validClients[clientID] = client

        // Step 1: Authorization request (GET) with invalid origin should be rejected
        let authGetResponse = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "token",
            clientID: clientID,
            redirectURI: redirectURI,
            scope: scope1,
            state: "implicit-reject-state",
            origin: "https://malicious.com"
        )

        XCTAssertEqual(authGetResponse.status, .seeOther, "Should redirect with error")
        let getLocation = authGetResponse.headers.location?.value ?? ""
        XCTAssertTrue(getLocation.contains("error=unauthorized_client"), "Should contain unauthorized_client error")
        XCTAssertTrue(getLocation.contains("state=implicit-reject-state"), "Should preserve state in error response")

        // Step 2: Authorization POST with invalid origin should also be rejected
        let authPostResponse = try await TestDataBuilder.getPostAuthResponseWithOrigin(
            with: app,
            clientID: clientID,
            redirectURI: redirectURI,
            responseType: "token",
            origin: "https://malicious.com",
            approve: true,
            state: "implicit-post-reject-state",
            scope: scope1,
            user: testUser,
            csrfToken: csrfToken,
            sessionID: sessionID
        )

        XCTAssertEqual(authPostResponse.status, .seeOther, "POST should also redirect with error")
        let postLocation = authPostResponse.headers.location?.value ?? ""
        XCTAssertTrue(postLocation.contains("error=unauthorized_client"), "POST should contain unauthorized_client error")
        XCTAssertTrue(postLocation.contains("state=implicit-post-reject-state"), "Should preserve state in POST error response")
    }

    // MARK: - Client Credentials Flow Tests

    func testClientCredentialsFlow_WithOriginValidation_WorksCorrectly() async throws {
        // Given - Confidential client configured for client credentials
        let clientID = "client-creds-client"
        let clientSecret = "client-creds-secret"
        
        let client = OAuthClient(
            clientID: clientID,
            redirectURIs: nil,
            clientSecret: clientSecret,
            validScopes: [scope1, scope2],
            confidential: true,
            allowedGrantType: .clientCredentials,
            authorizedOrigins: nil // Client credentials typically don't need origin validation
        )
        fakeClientRetriever.validClients[clientID] = client
        
        fakeTokenManager.accessTokenToReturn = "client-creds-access-token"
        fakeTokenManager.refreshTokenToReturn = "client-creds-refresh-token"

        // Client credentials flow - direct token request (no authorization step)
        let tokenResponse = try await TestDataBuilder.getTokenRequestResponse(
            with: app,
            grantType: "client_credentials",
            clientID: clientID,
            clientSecret: clientSecret,
            scope: "\(scope1) \(scope2)"
        )

        XCTAssertEqual(tokenResponse.status, .ok, "Client credentials flow should succeed")
        
        struct TokenResponse: Decodable {
            let accessToken: String?
            let refreshToken: String?
            let tokenType: String?
            let expiresIn: Int?
            let scope: String?
            
            enum CodingKeys: String, CodingKey {
                case accessToken = "access_token"
                case refreshToken = "refresh_token"
                case tokenType = "token_type"
                case expiresIn = "expires_in"
                case scope
            }
        }
        
        let tokenData = try JSONDecoder().decode(TokenResponse.self, from: tokenResponse.body)
        XCTAssertEqual(tokenData.accessToken, "client-creds-access-token")
        XCTAssertEqual(tokenData.refreshToken, "client-creds-refresh-token")
        XCTAssertEqual(tokenData.tokenType, "bearer")
        XCTAssertEqual(tokenData.expiresIn, 3600)
        XCTAssertEqual(tokenData.scope, "\(scope1) \(scope2)")
    }

    // MARK: - Mixed Client Scenarios Tests

    func testMixedClientScenarios_SomeWithOriginsSomeWithout_WorksCorrectly() async throws {
        // Given - Multiple clients with different origin configurations
        let secureClientID = "secure-client"
        let legacyClientID = "legacy-client"
        let publicClientID = "public-client"
        
        // Secure client with origin validation
        let secureClient = OAuthClient(
            clientID: secureClientID,
            redirectURIs: ["https://secure.example.com/callback"],
            clientSecret: "secure-secret",
            validScopes: [scope1, scope2],
            allowedGrantType: .authorization,
            authorizedOrigins: ["https://secure.example.com", "*.secure.example.com"]
        )
        
        // Legacy client without origin validation (backward compatibility)
        let legacyClient = OAuthClient(
            clientID: legacyClientID,
            redirectURIs: ["https://legacy.example.com/callback"],
            clientSecret: "legacy-secret",
            validScopes: [scope1],
            allowedGrantType: .authorization,
            authorizedOrigins: nil
        )
        
        // Public client with empty origins (also backward compatible)
        let publicClient = OAuthClient(
            clientID: publicClientID,
            redirectURIs: ["https://public.example.com/callback"],
            validScopes: [scope1],
            allowedGrantType: .implicit,
            authorizedOrigins: []
        )
        
        fakeClientRetriever.validClients[secureClientID] = secureClient
        fakeClientRetriever.validClients[legacyClientID] = legacyClient
        fakeClientRetriever.validClients[publicClientID] = publicClient
        
        fakeCodeManager.generatedCode = "mixed-scenario-code"
        fakeTokenManager.accessTokenToReturn = "mixed-scenario-token"

        // Test 1: Secure client with valid origin should succeed
        let secureValidResponse = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "code",
            clientID: secureClientID,
            redirectURI: "https://secure.example.com/callback",
            scope: scope1,
            state: "secure-valid",
            origin: "https://secure.example.com"
        )
        XCTAssertEqual(secureValidResponse.status, .ok, "Secure client with valid origin should succeed")

        // Test 2: Secure client with invalid origin should fail
        let secureInvalidResponse = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "code",
            clientID: secureClientID,
            redirectURI: "https://secure.example.com/callback",
            scope: scope1,
            state: "secure-invalid",
            origin: "https://malicious.com"
        )
        XCTAssertEqual(secureInvalidResponse.status, .seeOther, "Secure client with invalid origin should fail")
        XCTAssertTrue(
            secureInvalidResponse.headers.location?.value.contains("error=unauthorized_client") ?? false,
            "Should contain unauthorized_client error"
        )

        // Test 3: Secure client with wildcard subdomain should succeed
        let secureWildcardResponse = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "code",
            clientID: secureClientID,
            redirectURI: "https://secure.example.com/callback",
            scope: scope1,
            state: "secure-wildcard",
            origin: "https://api.secure.example.com"
        )
        XCTAssertEqual(secureWildcardResponse.status, .ok, "Secure client with wildcard subdomain should succeed")

        // Test 4: Legacy client with any origin should succeed (backward compatibility)
        let legacyAnyOriginResponse = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "code",
            clientID: legacyClientID,
            redirectURI: "https://legacy.example.com/callback",
            scope: scope1,
            state: "legacy-any",
            origin: "https://any-domain.com"
        )
        XCTAssertEqual(legacyAnyOriginResponse.status, .ok, "Legacy client should accept any origin")

        // Test 5: Legacy client without origin header should succeed
        let legacyNoOriginResponse = try await TestDataBuilder.getAuthRequestResponse(
            with: app,
            responseType: "code",
            clientID: legacyClientID,
            redirectURI: "https://legacy.example.com/callback",
            scope: scope1,
            state: "legacy-no-origin"
        )
        XCTAssertEqual(legacyNoOriginResponse.status, .ok, "Legacy client should work without origin header")

        // Test 6: Public client (empty origins) with any origin should succeed
        let publicAnyOriginResponse = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "token",
            clientID: publicClientID,
            redirectURI: "https://public.example.com/callback",
            scope: scope1,
            state: "public-any",
            origin: "https://any-domain.com"
        )
        XCTAssertEqual(publicAnyOriginResponse.status, .ok, "Public client with empty origins should accept any origin")
    }

    // MARK: - All Grant Types with Origin Validation Tests

    func testAllGrantTypes_WithOriginValidation_WorkCorrectly() async throws {
        // Given - Clients configured for different grant types
        let authCodeClientID = "all-grants-auth-code"
        let implicitClientID = "all-grants-implicit"
        let clientCredsClientID = "all-grants-client-creds"
        
        let commonOrigins = ["https://app.example.com", "*.staging.example.com"]
        let commonRedirectURI = "https://app.example.com/callback"
        
        // Authorization Code client
        let authCodeClient = OAuthClient(
            clientID: authCodeClientID,
            redirectURIs: [commonRedirectURI],
            clientSecret: "auth-code-secret",
            validScopes: [scope1, scope2],
            allowedGrantType: .authorization,
            authorizedOrigins: commonOrigins
        )
        
        // Implicit Grant client
        let implicitClient = OAuthClient(
            clientID: implicitClientID,
            redirectURIs: [commonRedirectURI],
            validScopes: [scope1, scope2],
            allowedGrantType: .implicit,
            authorizedOrigins: commonOrigins
        )
        
        // Client Credentials client (no origin validation needed)
        let clientCredsClient = OAuthClient(
            clientID: clientCredsClientID,
            redirectURIs: nil,
            clientSecret: "client-creds-secret",
            validScopes: [scope1, scope2],
            confidential: true,
            allowedGrantType: .clientCredentials,
            authorizedOrigins: nil
        )
        
        fakeClientRetriever.validClients[authCodeClientID] = authCodeClient
        fakeClientRetriever.validClients[implicitClientID] = implicitClient
        fakeClientRetriever.validClients[clientCredsClientID] = clientCredsClient
        
        fakeCodeManager.generatedCode = "all-grants-code"
        fakeTokenManager.accessTokenToReturn = "all-grants-access-token"
        fakeTokenManager.refreshTokenToReturn = "all-grants-refresh-token"

        // Test 1: Authorization Code Grant with valid origin
        let authCodeResponse = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "code",
            clientID: authCodeClientID,
            redirectURI: commonRedirectURI,
            scope: scope1,
            state: "auth-code-test",
            origin: "https://app.example.com"
        )
        XCTAssertEqual(authCodeResponse.status, .ok, "Authorization code grant should work with valid origin")

        // Test 2: Authorization Code Grant with wildcard origin
        let authCodeWildcardResponse = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "code",
            clientID: authCodeClientID,
            redirectURI: commonRedirectURI,
            scope: scope1,
            state: "auth-code-wildcard-test",
            origin: "https://api.staging.example.com"
        )
        XCTAssertEqual(authCodeWildcardResponse.status, .ok, "Authorization code grant should work with wildcard origin")

        // Test 3: Authorization Code Grant with invalid origin
        let authCodeInvalidResponse = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "code",
            clientID: authCodeClientID,
            redirectURI: commonRedirectURI,
            scope: scope1,
            state: "auth-code-invalid-test",
            origin: "https://malicious.com"
        )
        XCTAssertEqual(authCodeInvalidResponse.status, .seeOther, "Authorization code grant should reject invalid origin")
        XCTAssertTrue(
            authCodeInvalidResponse.headers.location?.value.contains("error=unauthorized_client") ?? false,
            "Should contain unauthorized_client error"
        )

        // Test 4: Implicit Grant with valid origin
        let implicitResponse = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "token",
            clientID: implicitClientID,
            redirectURI: commonRedirectURI,
            scope: scope1,
            state: "implicit-test",
            origin: "https://app.example.com"
        )
        XCTAssertEqual(implicitResponse.status, .ok, "Implicit grant should work with valid origin")

        // Test 5: Implicit Grant with invalid origin
        let implicitInvalidResponse = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "token",
            clientID: implicitClientID,
            redirectURI: commonRedirectURI,
            scope: scope1,
            state: "implicit-invalid-test",
            origin: "https://malicious.com"
        )
        XCTAssertEqual(implicitInvalidResponse.status, .seeOther, "Implicit grant should reject invalid origin")
        XCTAssertTrue(
            implicitInvalidResponse.headers.location?.value.contains("error=unauthorized_client") ?? false,
            "Should contain unauthorized_client error"
        )

        // Test 6: Client Credentials Grant (no origin validation)
        let clientCredsResponse = try await TestDataBuilder.getTokenRequestResponse(
            with: app,
            grantType: "client_credentials",
            clientID: clientCredsClientID,
            clientSecret: "client-creds-secret",
            scope: scope1
        )
        XCTAssertEqual(clientCredsResponse.status, .ok, "Client credentials grant should work without origin validation")
    }

    // MARK: - Token Refresh with Origin Validation Tests

    func testTokenRefresh_WithOriginValidation_WorksCorrectly() async throws {
        // Given - Client with origin validation and existing refresh token
        let clientID = "refresh-client"
        let clientSecret = "refresh-secret"
        let refreshTokenString = "existing-refresh-token"
        
        let client = OAuthClient(
            clientID: clientID,
            redirectURIs: ["https://app.example.com/callback"],
            clientSecret: clientSecret,
            validScopes: [scope1, scope2],
            confidential: true,
            allowedGrantType: .authorization,
            authorizedOrigins: ["https://app.example.com"]
        )
        fakeClientRetriever.validClients[clientID] = client
        
        // Set up existing refresh token
        let existingRefreshToken = FakeRefreshToken(
            tokenString: refreshTokenString,
            clientID: clientID,
            userID: testUser.id,
            scopes: [scope1, scope2]
        )
        fakeTokenManager.refreshTokens[refreshTokenString] = existingRefreshToken
        fakeTokenManager.accessTokenToReturn = "new-access-token"
        // Note: Refresh token flows should not return new refresh tokens per OAuth 2.0 standards

        // Token refresh request (no origin validation needed for refresh)
        let refreshResponse = try await TestDataBuilder.getTokenRequestResponse(
            with: app,
            grantType: "refresh_token",
            clientID: clientID,
            clientSecret: clientSecret,
            refreshToken: refreshTokenString
        )

        XCTAssertEqual(refreshResponse.status, .ok, "Token refresh should succeed")
        
        struct TokenResponse: Decodable {
            let accessToken: String?
            let refreshToken: String?
            let tokenType: String?
            let expiresIn: Int?
            let scope: String?
            
            enum CodingKeys: String, CodingKey {
                case accessToken = "access_token"
                case refreshToken = "refresh_token"
                case tokenType = "token_type"
                case expiresIn = "expires_in"
                case scope
            }
        }
        
        let tokenData = try JSONDecoder().decode(TokenResponse.self, from: refreshResponse.body)
        XCTAssertEqual(tokenData.accessToken, "new-access-token")
        XCTAssertNil(tokenData.refreshToken, "Refresh token flows should not return new refresh tokens")
        XCTAssertEqual(tokenData.tokenType, "bearer")
        XCTAssertEqual(tokenData.expiresIn, 3600)
        XCTAssertEqual(tokenData.scope, "\(scope1) \(scope2)")
    }

    // MARK: - Error Handling and Edge Cases Tests

    func testOriginValidation_WithMissingOriginHeader_HandledCorrectly() async throws {
        // Given - Client that requires origin validation
        let clientID = "missing-origin-client"
        let redirectURI = "https://app.example.com/callback"
        
        let client = OAuthClient(
            clientID: clientID,
            redirectURIs: [redirectURI],
            validScopes: [scope1],
            allowedGrantType: .authorization,
            authorizedOrigins: ["https://app.example.com"]
        )
        fakeClientRetriever.validClients[clientID] = client

        // Request without Origin header
        let response = try await TestDataBuilder.getAuthRequestResponse(
            with: app,
            responseType: "code",
            clientID: clientID,
            redirectURI: redirectURI,
            scope: scope1,
            state: "missing-origin-state"
        )

        XCTAssertEqual(response.status, .seeOther, "Should redirect with error when origin is missing")
        let location = response.headers.location?.value ?? ""
        XCTAssertTrue(location.contains("error=invalid_request"), "Should contain invalid_request error")
        XCTAssertTrue(location.contains("error_description=Origin+header+required"), "Should indicate origin header is required")
        XCTAssertTrue(location.contains("state=missing-origin-state"), "Should preserve state parameter")
    }

    func testOriginValidation_WithComplexWildcardPatterns_WorksSecurely() async throws {
        // Given - Client with various wildcard patterns
        let clientID = "complex-wildcard-client"
        let redirectURI = "https://app.example.com/callback"
        
        let client = OAuthClient(
            clientID: clientID,
            redirectURIs: [redirectURI],
            validScopes: [scope1],
            allowedGrantType: .authorization,
            authorizedOrigins: [
                "*.api.example.com",
                "*.staging.example.com",
                "https://specific.example.com"
            ]
        )
        fakeClientRetriever.validClients[clientID] = client

        // Test cases: (origin, shouldSucceed, description)
        let testCases: [(String, Bool, String)] = [
            ("https://v1.api.example.com", true, "Single level subdomain should match *.api.example.com"),
            ("https://v2.api.example.com", true, "Different subdomain should match *.api.example.com"),
            ("https://test.staging.example.com", true, "Should match *.staging.example.com"),
            ("https://specific.example.com", true, "Should match exact domain"),
            ("https://api.example.com", true, "Root domain should match *.api.example.com (current implementation)"),
            ("https://staging.example.com", true, "Root domain should match *.staging.example.com (current implementation)"),
            ("https://malicious.com", false, "Completely different domain should fail"),
            ("https://example.com.evil.com", false, "Domain suffix attack should fail"),
            ("https://api.example.com.evil.com", false, "Subdomain suffix attack should fail")
        ]

        for (origin, shouldSucceed, description) in testCases {
            let response = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
                with: app,
                responseType: "code",
                clientID: clientID,
                redirectURI: redirectURI,
                scope: scope1,
                state: "wildcard-test",
                origin: origin
            )

            if shouldSucceed {
                XCTAssertEqual(response.status, .ok, "\(description) - origin: \(origin)")
            } else {
                XCTAssertEqual(response.status, .seeOther, "\(description) - origin: \(origin)")
                let location = response.headers.location?.value ?? ""
                XCTAssertTrue(location.contains("error=unauthorized_client"), "\(description) - origin: \(origin)")
            }
        }
    }

    // MARK: - Performance and Stress Tests
    /*
    func testOriginValidation_WithMultipleClients_PerformsWell() async throws {
        // Given - Multiple clients with different origin configurations
        let clientCount = 10
        var clients: [String: OAuthClient] = [:]
        
        for i in 0..<clientCount {
            let clientID = "perf-client-\(i)"
            let client = OAuthClient(
                clientID: clientID,
                redirectURIs: ["https://app\(i).example.com/callback"],
                validScopes: [scope1],
                allowedGrantType: .authorization,
                authorizedOrigins: ["https://app\(i).example.com", "*.staging\(i).example.com"]
            )
            clients[clientID] = client
        }
        
        fakeClientRetriever.validClients.merge(clients) { _, new in new }

        // Test concurrent requests to different clients
        let startTime = Date()
        
        try await withThrowingTaskGroup(of: Void.self) { group in
            for i in 0..<clientCount {
                group.addTask {
                    let clientID = "perf-client-\(i)"
                    let origin = "https://app\(i).example.com"
                    
                    let response = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
                        with: self.app,
                        responseType: "code",
                        clientID: clientID,
                        redirectURI: "https://app\(i).example.com/callback",
                        scope: self.scope1,
                        state: "perf-test-\(i)",
                        origin: origin
                    )
                    
                    XCTAssertEqual(response.status, .ok, "Client \(i) should succeed")
                }
            }
            
            try await group.waitForAll()
        }
        
        let endTime = Date()
        let duration = endTime.timeIntervalSince(startTime)
        
        // Performance assertion - should complete within reasonable time
        XCTAssertLessThan(duration, 5.0, "Origin validation for \(clientCount) clients should complete within 5 seconds")
    }
    */
}
