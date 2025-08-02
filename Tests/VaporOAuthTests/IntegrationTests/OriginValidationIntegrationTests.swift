import XCTVapor

@testable import VaporOAuth

final class OriginValidationIntegrationTests: XCTestCase {

    // MARK: - Properties

    var app: Application!
    var fakeClientRetriever: FakeClientGetter!
    var capturingAuthorizeHandler: CapturingAuthoriseHandler!
    var fakeCodeManager: FakeCodeManager!
    var fakeTokenManager: FakeTokenManager!
    var fakeSessions: FakeSessions!

    static let clientID = "origin-integration-client"
    static let redirectURI = "https://api.example.com/callback"
    static let implicitClientID = "implicit-origin-client"
    static let implicitRedirectURI = "https://spa.example.com/callback"

    let scope1 = "email"
    let scope2 = "profile"
    let sessionID = "integration-session-id"
    let csrfToken = "integration-csrf-token"

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
            validScopes: [scope1, scope2],
            sessions: fakeSessions,
            registeredUsers: [TestDataBuilder.anyOAuthUser()]
        )
    }

    override func tearDown() async throws {
        try await app.asyncShutdown()
        try await super.tearDown()
    }

    // MARK: - Successful Authorization with Valid Origins Tests

    func testAuthorizationCodeFlow_WithValidExactOrigin_Succeeds() async throws {
        // Given
        let authorizedOrigins = ["https://example.com", "https://app.example.com"]
        let client = createAuthorizationClient(authorizedOrigins: authorizedOrigins)
        fakeClientRetriever.validClients[Self.clientID] = client
        fakeCodeManager.generatedCode = "valid-origin-code"

        // When - GET request to authorization endpoint
        let getResponse = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "code",
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            scope: scope1,
            state: "test-state",
            origin: "https://example.com"
        )

        // Then - Should show authorization page
        XCTAssertEqual(getResponse.status, .ok)

        // When - POST request to approve authorization
        let postResponse = try await TestDataBuilder.getPostAuthResponseWithOrigin(
            with: app,
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            origin: "https://example.com",
            approve: true,
            state: "test-state",
            scope: scope1,
            user: TestDataBuilder.anyOAuthUser(),
            csrfToken: csrfToken,
            sessionID: sessionID
        )

        // Then - Should redirect with authorization code
        XCTAssertEqual(postResponse.status, .seeOther)
        let location = postResponse.headers.location?.value ?? ""
        XCTAssertTrue(location.contains("code=valid-origin-code"))
        XCTAssertTrue(location.contains("state=test-state"))
    }

    func testAuthorizationCodeFlow_WithValidWildcardOrigin_Succeeds() async throws {
        // Given
        let authorizedOrigins = ["*.example.com"]
        let client = createAuthorizationClient(authorizedOrigins: authorizedOrigins)
        fakeClientRetriever.validClients[Self.clientID] = client
        fakeCodeManager.generatedCode = "wildcard-origin-code"

        // When - GET request with subdomain origin
        let getResponse = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "code",
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            scope: scope1,
            state: "wildcard-state",
            origin: "https://app.example.com"
        )

        // Then - Should show authorization page
        XCTAssertEqual(getResponse.status, .ok)

        // When - POST request to approve authorization
        let postResponse = try await TestDataBuilder.getPostAuthResponseWithOrigin(
            with: app,
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            origin: "https://app.example.com",
            approve: true,
            state: "wildcard-state",
            scope: scope1,
            user: TestDataBuilder.anyOAuthUser(),
            csrfToken: csrfToken,
            sessionID: sessionID
        )

        // Then - Should redirect with authorization code
        XCTAssertEqual(postResponse.status, .seeOther)
        let location = postResponse.headers.location?.value ?? ""
        XCTAssertTrue(location.contains("code=wildcard-origin-code"))
        XCTAssertTrue(location.contains("state=wildcard-state"))
    }

    func testImplicitGrant_WithValidOrigin_Succeeds() async throws {
        // Given
        let authorizedOrigins = ["https://spa.example.com"]
        let client = createImplicitClient(authorizedOrigins: authorizedOrigins)
        fakeClientRetriever.validClients[Self.implicitClientID] = client

        // When - GET request to authorization endpoint
        let getResponse = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "token",
            clientID: Self.implicitClientID,
            redirectURI: Self.implicitRedirectURI,
            scope: scope1,
            state: "implicit-state",
            origin: "https://spa.example.com"
        )

        // Then - Should show authorization page
        XCTAssertEqual(getResponse.status, .ok)

        // When - POST request to approve authorization
        let postResponse = try await TestDataBuilder.getPostAuthResponseWithOrigin(
            with: app,
            clientID: Self.implicitClientID,
            redirectURI: Self.implicitRedirectURI,
            responseType: "token",
            origin: "https://spa.example.com",
            approve: true,
            state: "implicit-state",
            scope: scope1,
            user: TestDataBuilder.anyOAuthUser(),
            csrfToken: csrfToken,
            sessionID: sessionID
        )

        // Then - Should redirect with access token in fragment
        XCTAssertEqual(postResponse.status, .seeOther)
        let location = postResponse.headers.location?.value ?? ""
        XCTAssertTrue(location.contains("#access_token=") || location.contains("access_token="))
        XCTAssertTrue(location.contains("token_type=bearer"))
        XCTAssertTrue(location.contains("state=implicit-state"))
    }

    // MARK: - Authorization Rejection with Invalid Origins Tests

    func testAuthorizationCodeFlow_WithInvalidOrigin_RejectsAtGETRequest() async throws {
        // Given
        let authorizedOrigins = ["https://example.com"]
        let client = createAuthorizationClient(authorizedOrigins: authorizedOrigins)
        fakeClientRetriever.validClients[Self.clientID] = client

        // When - GET request with invalid origin
        let response = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "code",
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            scope: scope1,
            state: "invalid-state",
            origin: "https://malicious.com"
        )

        // Then - Should redirect with error
        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(
            response.headers.location?.value,
            "\(Self.redirectURI)?error=unauthorized_client&error_description=Origin+not+authorized+for+this+client&state=invalid-state"
        )
    }

    func testAuthorizationCodeFlow_WithInvalidOrigin_RejectsAtPOSTRequest() async throws {
        // Given
        let authorizedOrigins = ["https://example.com"]
        let client = createAuthorizationClient(authorizedOrigins: authorizedOrigins)
        fakeClientRetriever.validClients[Self.clientID] = client

        // When - POST request with invalid origin (bypassing GET validation)
        let response = try await TestDataBuilder.getPostAuthResponseWithOrigin(
            with: app,
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            origin: "https://malicious.com",
            approve: true,
            state: "post-invalid-state",
            scope: scope1,
            user: TestDataBuilder.anyOAuthUser(),
            csrfToken: csrfToken,
            sessionID: sessionID
        )

        // Then - Should redirect with error
        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(
            response.headers.location?.value,
            "\(Self.redirectURI)?error=unauthorized_client&error_description=Origin+not+authorized+for+this+client&state=post-invalid-state"
        )
    }

    func testImplicitGrant_WithInvalidOrigin_RejectsRequest() async throws {
        // Given
        let authorizedOrigins = ["https://spa.example.com"]
        let client = createImplicitClient(authorizedOrigins: authorizedOrigins)
        fakeClientRetriever.validClients[Self.implicitClientID] = client

        // When - GET request with invalid origin
        let response = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "token",
            clientID: Self.implicitClientID,
            redirectURI: Self.implicitRedirectURI,
            scope: scope1,
            state: "implicit-invalid-state",
            origin: "https://malicious.com"
        )

        // Then - Should redirect with error
        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(
            response.headers.location?.value,
            "\(Self.implicitRedirectURI)?error=unauthorized_client&error_description=Origin+not+authorized+for+this+client&state=implicit-invalid-state"
        )
    }

    // MARK: - Missing Origin Header Tests

    func testAuthorizationCodeFlow_WithMissingOrigin_RejectsRequest() async throws {
        // Given
        let authorizedOrigins = ["https://example.com"]
        let client = createAuthorizationClient(authorizedOrigins: authorizedOrigins)
        fakeClientRetriever.validClients[Self.clientID] = client

        // When - GET request without Origin header
        let response = try await TestDataBuilder.getAuthRequestResponse(
            with: app,
            responseType: "code",
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            scope: scope1,
            state: "missing-origin-state"
        )

        // Then - Should redirect with error
        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(
            response.headers.location?.value,
            "\(Self.redirectURI)?error=invalid_request&error_description=Origin+header+required&state=missing-origin-state"
        )
    }

    func testImplicitGrant_WithMissingOrigin_RejectsRequest() async throws {
        // Given
        let authorizedOrigins = ["https://spa.example.com"]
        let client = createImplicitClient(authorizedOrigins: authorizedOrigins)
        fakeClientRetriever.validClients[Self.implicitClientID] = client

        // When - GET request without Origin header
        let response = try await TestDataBuilder.getAuthRequestResponse(
            with: app,
            responseType: "token",
            clientID: Self.implicitClientID,
            redirectURI: Self.implicitRedirectURI,
            scope: scope1,
            state: "implicit-missing-origin-state"
        )

        // Then - Should redirect with error
        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(
            response.headers.location?.value,
            "\(Self.implicitRedirectURI)?error=invalid_request&error_description=Origin+header+required&state=implicit-missing-origin-state"
        )
    }

    func testAuthorizationPOST_WithMissingOrigin_RejectsRequest() async throws {
        // Given
        let authorizedOrigins = ["https://example.com"]
        let client = createAuthorizationClient(authorizedOrigins: authorizedOrigins)
        fakeClientRetriever.validClients[Self.clientID] = client

        // When - POST request without Origin header
        let response = try await TestDataBuilder.getPostAuthResponseWithOrigin(
            with: app,
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            origin: nil, // No origin header
            approve: true,
            state: "post-missing-origin-state",
            scope: scope1,
            user: TestDataBuilder.anyOAuthUser(),
            csrfToken: csrfToken,
            sessionID: sessionID
        )

        // Then - Should redirect with error
        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(
            response.headers.location?.value,
            "\(Self.redirectURI)?error=invalid_request&error_description=Origin+header+required&state=post-missing-origin-state"
        )
    }

    // MARK: - Multiple Authorized Origins Tests

    func testAuthorizationFlow_WithMultipleAuthorizedOrigins_ValidatesCorrectly() async throws {
        // Given
        let authorizedOrigins = [
            "https://example.com",
            "https://app.example.com", 
            "*.staging.example.com",
            "http://localhost:3000"
        ]
        let client = createAuthorizationClient(authorizedOrigins: authorizedOrigins)
        fakeClientRetriever.validClients[Self.clientID] = client
        fakeCodeManager.generatedCode = "multi-origin-code"

        // Test each valid origin
        let validOrigins = [
            "https://example.com",
            "https://app.example.com",
            "https://api.staging.example.com",
            "http://localhost:3000"
        ]

        for (index, origin) in validOrigins.enumerated() {
            // When - GET request with valid origin
            let getResponse = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
                with: app,
                responseType: "code",
                clientID: Self.clientID,
                redirectURI: Self.redirectURI,
                scope: scope1,
                state: "multi-state-\(index)",
                origin: origin
            )

            // Then - Should show authorization page
            XCTAssertEqual(getResponse.status, .ok, "Failed for origin: \(origin)")

            // When - POST request to approve
            let postResponse = try await TestDataBuilder.getPostAuthResponseWithOrigin(
                with: app,
                clientID: Self.clientID,
                redirectURI: Self.redirectURI,
                origin: origin,
                approve: true,
                state: "multi-state-\(index)",
                scope: scope1,
                user: TestDataBuilder.anyOAuthUser(),
                csrfToken: csrfToken,
                sessionID: sessionID
            )

            // Then - Should succeed
            XCTAssertEqual(postResponse.status, .seeOther, "Failed for origin: \(origin)")
            XCTAssertTrue(
                postResponse.headers.location?.value.contains("code=multi-origin-code") ?? false,
                "Failed for origin: \(origin)"
            )
        }

        // Test invalid origin
        let invalidResponse = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "code",
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            scope: scope1,
            state: "multi-invalid-state",
            origin: "https://malicious.com"
        )

        XCTAssertEqual(invalidResponse.status, .seeOther)
        XCTAssertEqual(
            invalidResponse.headers.location?.value,
            "\(Self.redirectURI)?error=unauthorized_client&error_description=Origin+not+authorized+for+this+client&state=multi-invalid-state"
        )
    }

    // MARK: - Wildcard Pattern Matching Tests

    func testWildcardPatternMatching_InRealAuthorizationFlow() async throws {
        // Given
        let authorizedOrigins = ["*.example.com"]
        let client = createAuthorizationClient(authorizedOrigins: authorizedOrigins)
        fakeClientRetriever.validClients[Self.clientID] = client
        fakeCodeManager.generatedCode = "wildcard-test-code"

        // Test various subdomain patterns
        let testCases: [(String, Bool, String)] = [
            ("https://example.com", true, "root domain should match"),
            ("https://app.example.com", true, "single subdomain should match"),
            ("https://api.app.example.com", true, "nested subdomain should match"),
            ("https://staging-v2.example.com", true, "hyphenated subdomain should match"),
            ("https://example.com.evil.com", false, "domain suffix attack should fail"),
            ("https://notexample.com", false, "different domain should fail"),
            ("https://app.different.com", false, "different base domain should fail")
        ]

        for (origin, shouldSucceed, description) in testCases {
            // When
            let response = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
                with: app,
                responseType: "code",
                clientID: Self.clientID,
                redirectURI: Self.redirectURI,
                scope: scope1,
                state: "wildcard-test",
                origin: origin
            )

            // Then
            if shouldSucceed {
                XCTAssertEqual(response.status, .ok, "\(description) - origin: \(origin)")
            } else {
                XCTAssertEqual(response.status, .seeOther, "\(description) - origin: \(origin)")
                XCTAssertTrue(
                    response.headers.location?.value.contains("error=unauthorized_client") ?? false,
                    "\(description) - origin: \(origin)"
                )
            }
        }
    }

    // MARK: - Backward Compatibility Tests

    func testBackwardCompatibility_ClientWithNilAuthorizedOrigins_AllowsAnyOrigin() async throws {
        // Given
        let client = createAuthorizationClient(authorizedOrigins: nil)
        fakeClientRetriever.validClients[Self.clientID] = client
        fakeCodeManager.generatedCode = "backward-compat-code"

        // When - Request without Origin header (old behavior)
        let responseWithoutOrigin = try await TestDataBuilder.getAuthRequestResponse(
            with: app,
            responseType: "code",
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            scope: scope1,
            state: "no-origin-state"
        )

        // Then - Should succeed (backward compatibility)
        XCTAssertEqual(responseWithoutOrigin.status, .ok)

        // When - Request with any origin
        let responseWithOrigin = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "code",
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            scope: scope1,
            state: "any-origin-state",
            origin: "https://any-domain.com"
        )

        // Then - Should also succeed
        XCTAssertEqual(responseWithOrigin.status, .ok)

        // When - Complete the flow with POST
        let postResponse = try await TestDataBuilder.getPostAuthResponseWithOrigin(
            with: app,
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            origin: "https://any-domain.com",
            approve: true,
            state: "any-origin-state",
            scope: scope1,
            user: TestDataBuilder.anyOAuthUser(),
            csrfToken: csrfToken,
            sessionID: sessionID
        )

        // Then - Should complete successfully
        XCTAssertEqual(postResponse.status, .seeOther)
        let location = postResponse.headers.location?.value ?? ""
        XCTAssertTrue(location.contains("code=backward-compat-code"))
        XCTAssertTrue(location.contains("state=any-origin-state"))
    }

    func testBackwardCompatibility_ClientWithEmptyAuthorizedOrigins_AllowsAnyOrigin() async throws {
        // Given
        let client = createAuthorizationClient(authorizedOrigins: [])
        fakeClientRetriever.validClients[Self.clientID] = client
        fakeCodeManager.generatedCode = "empty-origins-code"

        // When - Request without Origin header
        let responseWithoutOrigin = try await TestDataBuilder.getPostAuthResponseWithOrigin(
            with: app,
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            origin: nil,
            approve: true,
            state: "empty-origins-state",
            scope: scope1,
            user: TestDataBuilder.anyOAuthUser(),
            csrfToken: csrfToken,
            sessionID: sessionID
        )

        // Then - Should succeed
        XCTAssertEqual(responseWithoutOrigin.status, .seeOther)
        let location = responseWithoutOrigin.headers.location?.value ?? ""
        XCTAssertTrue(location.contains("code=empty-origins-code"))
        XCTAssertTrue(location.contains("state=empty-origins-state"))
    }

    func testBackwardCompatibility_MixedClientConfiguration_WorksCorrectly() async throws {
        // Given - One client with origin validation, one without
        let secureClientID = "secure-client"
        let legacyClientID = "legacy-client"
        
        fakeClientRetriever.validClients[secureClientID] = OAuthClient(
            clientID: secureClientID,
            redirectURIs: [Self.redirectURI],
            allowedGrantType: .authorization,
            authorizedOrigins: ["https://secure.com"]
        )
        
        fakeClientRetriever.validClients[legacyClientID] = OAuthClient(
            clientID: legacyClientID,
            redirectURIs: [Self.redirectURI],
            allowedGrantType: .authorization,
            authorizedOrigins: nil
        )
        
        fakeCodeManager.generatedCode = "mixed-config-code"

        // When - Secure client with valid origin
        let secureValidResponse = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "code",
            clientID: secureClientID,
            redirectURI: Self.redirectURI,
            scope: scope1,
            state: "secure-valid",
            origin: "https://secure.com"
        )

        // Then - Should succeed
        XCTAssertEqual(secureValidResponse.status, .ok)

        // When - Secure client with invalid origin
        let secureInvalidResponse = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "code",
            clientID: secureClientID,
            redirectURI: Self.redirectURI,
            scope: scope1,
            state: "secure-invalid",
            origin: "https://malicious.com"
        )

        // Then - Should fail
        XCTAssertEqual(secureInvalidResponse.status, .seeOther)
        XCTAssertTrue(
            secureInvalidResponse.headers.location?.value.contains("error=unauthorized_client") ?? false
        )

        // When - Legacy client with any origin
        let legacyResponse = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "code",
            clientID: legacyClientID,
            redirectURI: Self.redirectURI,
            scope: scope1,
            state: "legacy-any",
            origin: "https://any-domain.com"
        )

        // Then - Should succeed (backward compatibility)
        XCTAssertEqual(legacyResponse.status, .ok)
    }

    // MARK: - Full OAuth Flow Integration Tests

    func testFullAuthorizationCodeFlow_WithOriginValidation_EndToEnd() async throws {
        // Given
        let authorizedOrigins = ["https://client.example.com"]
        let client = OAuthClient(
            clientID: "full-flow-client",
            redirectURIs: ["https://client.example.com/callback"],
            clientSecret: "client-secret",
            validScopes: [scope1, scope2],
            allowedGrantType: .authorization,
            authorizedOrigins: authorizedOrigins
        )
        fakeClientRetriever.validClients["full-flow-client"] = client
        
        let testCode = "full-flow-code"
        fakeCodeManager.generatedCode = testCode
        
        // Step 1: Authorization request (GET)
        let authGetResponse = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "code",
            clientID: "full-flow-client",
            redirectURI: "https://client.example.com/callback",
            scope: "\(scope1) \(scope2)",
            state: "full-flow-state",
            origin: "https://client.example.com"
        )

        XCTAssertEqual(authGetResponse.status, .ok)

        // Step 2: User approves authorization (POST)
        let authPostResponse = try await TestDataBuilder.getPostAuthResponseWithOrigin(
            with: app,
            clientID: "full-flow-client",
            redirectURI: "https://client.example.com/callback",
            origin: "https://client.example.com",
            approve: true,
            state: "full-flow-state",
            scope: "\(scope1) \(scope2)",
            user: TestDataBuilder.anyOAuthUser(),
            csrfToken: csrfToken,
            sessionID: sessionID
        )

        XCTAssertEqual(authPostResponse.status, .seeOther)
        let location = authPostResponse.headers.location?.value ?? ""
        XCTAssertTrue(location.contains("code=\(testCode)"))
        XCTAssertTrue(location.contains("state=full-flow-state"))

        // Step 3: Exchange code for token
        let tokenResponse = try await TestDataBuilder.getTokenRequestResponse(
            with: app,
            grantType: "authorization_code",
            clientID: "full-flow-client",
            clientSecret: "client-secret",
            redirectURI: "https://client.example.com/callback",
            code: testCode
        )

        XCTAssertEqual(tokenResponse.status, .ok)
    }

    func testFullImplicitFlow_WithOriginValidation_EndToEnd() async throws {
        // Given
        let authorizedOrigins = ["https://spa.example.com"]
        let client = OAuthClient(
            clientID: "implicit-flow-client",
            redirectURIs: ["https://spa.example.com/callback"],
            validScopes: [scope1],
            allowedGrantType: .implicit,
            authorizedOrigins: authorizedOrigins
        )
        fakeClientRetriever.validClients["implicit-flow-client"] = client

        // Step 1: Authorization request (GET)
        let authGetResponse = try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: "token",
            clientID: "implicit-flow-client",
            redirectURI: "https://spa.example.com/callback",
            scope: scope1,
            state: "implicit-flow-state",
            origin: "https://spa.example.com"
        )

        XCTAssertEqual(authGetResponse.status, .ok)

        // Step 2: User approves authorization (POST)
        let authPostResponse = try await TestDataBuilder.getPostAuthResponseWithOrigin(
            with: app,
            clientID: "implicit-flow-client",
            redirectURI: "https://spa.example.com/callback",
            responseType: "token",
            origin: "https://spa.example.com",
            approve: true,
            state: "implicit-flow-state",
            scope: scope1,
            user: TestDataBuilder.anyOAuthUser(),
            csrfToken: csrfToken,
            sessionID: sessionID
        )

        XCTAssertEqual(authPostResponse.status, .seeOther)
        let location = authPostResponse.headers.location?.value ?? ""
        XCTAssertTrue(location.contains("https://spa.example.com/callback#"))
        XCTAssertTrue(location.contains("access_token="))
        XCTAssertTrue(location.contains("token_type=bearer"))
        XCTAssertTrue(location.contains("state=implicit-flow-state"))
    }

    // MARK: - Helper Methods

    private func createAuthorizationClient(authorizedOrigins: [String]?) -> OAuthClient {
        return OAuthClient(
            clientID: Self.clientID,
            redirectURIs: [Self.redirectURI],
            validScopes: [scope1, scope2],
            allowedGrantType: .authorization,
            authorizedOrigins: authorizedOrigins
        )
    }

    private func createImplicitClient(authorizedOrigins: [String]?) -> OAuthClient {
        return OAuthClient(
            clientID: Self.implicitClientID,
            redirectURIs: [Self.implicitRedirectURI],
            validScopes: [scope1, scope2],
            allowedGrantType: .implicit,
            authorizedOrigins: authorizedOrigins
        )
    }
}