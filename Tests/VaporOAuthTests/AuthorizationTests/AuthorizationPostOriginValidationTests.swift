import XCTVapor

@testable import VaporOAuth

final class AuthorizationPostOriginValidationTests: XCTestCase {

    // MARK: - Properties

    var app: Application!
    var fakeClientRetriever: FakeClientGetter!
    var capturingAuthoriseHandler: CapturingAuthoriseHandler!
    var fakeCodeManager: FakeCodeManager!

    static let clientID = "origin-test-client"
    static let redirectURI = "https://api.example.com/callback"

    let scope1 = "email"
    let scope2 = "address"
    let sessionID = "test-session-id"
    let csrfToken = "test-csrf-token"

    // MARK: - Overrides

    override func setUp() async throws {
        fakeClientRetriever = FakeClientGetter()
        capturingAuthoriseHandler = CapturingAuthoriseHandler()
        fakeCodeManager = FakeCodeManager()

        let fakeSessions = FakeSessions(
            sessions: [SessionID(string: sessionID): SessionData(initialData: ["CSRFToken": csrfToken])]
        )

        app = try TestDataBuilder.getOAuth2Application(
            codeManager: fakeCodeManager,
            clientRetriever: fakeClientRetriever,
            authorizeHandler: capturingAuthoriseHandler,
            sessions: fakeSessions,
            registeredUsers: [TestDataBuilder.anyOAuthUser()]
        )
    }

    override func tearDown() async throws {
        try await app.asyncShutdown()
        try await super.tearDown()
    }

    // MARK: - Origin Validation Tests

    func testPostAuthorizationWithValidOrigin_Succeeds() async throws {
        // Given
        let authorizedOrigins = ["https://example.com", "https://app.example.com"]
        let originClient = OAuthClient(
            clientID: Self.clientID,
            redirectURIs: [Self.redirectURI],
            allowedGrantType: .authorization,
            authorizedOrigins: authorizedOrigins
        )
        fakeClientRetriever.validClients[Self.clientID] = originClient
        fakeCodeManager.generatedCode = "test-code-123"

        // When
        let response = try await getPostAuthResponse(
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            origin: "https://example.com",
            approve: true
        )

        // Then
        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(
            response.headers.location?.value,
            "\(Self.redirectURI)?code=test-code-123"
        )
    }

    func testPostAuthorizationWithInvalidOrigin_ReturnsUnauthorizedClientError() async throws {
        // Given
        let authorizedOrigins = ["https://example.com"]
        let originClient = OAuthClient(
            clientID: Self.clientID,
            redirectURIs: [Self.redirectURI],
            allowedGrantType: .authorization,
            authorizedOrigins: authorizedOrigins
        )
        fakeClientRetriever.validClients[Self.clientID] = originClient

        // When
        let response = try await getPostAuthResponse(
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            origin: "https://malicious.com",
            approve: true
        )

        // Then
        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(
            response.headers.location?.value,
            "\(Self.redirectURI)?error=unauthorized_client&error_description=Origin+not+authorized+for+this+client"
        )
    }

    func testPostAuthorizationWithMissingOrigin_ReturnsInvalidRequestError() async throws {
        // Given
        let authorizedOrigins = ["https://example.com"]
        let originClient = OAuthClient(
            clientID: Self.clientID,
            redirectURIs: [Self.redirectURI],
            allowedGrantType: .authorization,
            authorizedOrigins: authorizedOrigins
        )
        fakeClientRetriever.validClients[Self.clientID] = originClient

        // When
        let response = try await getPostAuthResponse(
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            origin: nil,
            approve: true
        )

        // Then
        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(
            response.headers.location?.value,
            "\(Self.redirectURI)?error=invalid_request&error_description=Origin+header+required"
        )
    }

    func testPostAuthorizationWithWildcardOrigin_Succeeds() async throws {
        // Given
        let authorizedOrigins = ["*.example.com"]
        let wildcardClient = OAuthClient(
            clientID: Self.clientID,
            redirectURIs: [Self.redirectURI],
            allowedGrantType: .authorization,
            authorizedOrigins: authorizedOrigins
        )
        fakeClientRetriever.validClients[Self.clientID] = wildcardClient
        fakeCodeManager.generatedCode = "wildcard-code-456"

        // When
        let response = try await getPostAuthResponse(
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            origin: "https://app.example.com",
            approve: true
        )

        // Then
        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(
            response.headers.location?.value,
            "\(Self.redirectURI)?code=wildcard-code-456"
        )
    }

    func testPostAuthorizationWithMultipleAuthorizedOrigins_ValidatesCorrectly() async throws {
        // Given
        let authorizedOrigins = ["https://example.com", "https://app.example.com", "*.dev.example.com"]
        let multiOriginClient = OAuthClient(
            clientID: Self.clientID,
            redirectURIs: [Self.redirectURI],
            allowedGrantType: .authorization,
            authorizedOrigins: authorizedOrigins
        )
        fakeClientRetriever.validClients[Self.clientID] = multiOriginClient
        fakeCodeManager.generatedCode = "multi-origin-code"

        // Test first origin
        let response1 = try await getPostAuthResponse(
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            origin: "https://example.com",
            approve: true
        )
        XCTAssertEqual(response1.status, .seeOther)
        XCTAssertTrue(response1.headers.location?.value.contains("code=multi-origin-code") ?? false)

        // Test second origin
        let response2 = try await getPostAuthResponse(
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            origin: "https://app.example.com",
            approve: true
        )
        XCTAssertEqual(response2.status, .seeOther)
        XCTAssertTrue(response2.headers.location?.value.contains("code=multi-origin-code") ?? false)

        // Test wildcard origin
        let response3 = try await getPostAuthResponse(
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            origin: "https://staging.dev.example.com",
            approve: true
        )
        XCTAssertEqual(response3.status, .seeOther)
        XCTAssertTrue(response3.headers.location?.value.contains("code=multi-origin-code") ?? false)

        // Test invalid origin
        let response4 = try await getPostAuthResponse(
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            origin: "https://malicious.com",
            approve: true
        )
        XCTAssertEqual(response4.status, .seeOther)
        XCTAssertEqual(
            response4.headers.location?.value,
            "\(Self.redirectURI)?error=unauthorized_client&error_description=Origin+not+authorized+for+this+client"
        )
    }

    func testPostAuthorizationWithNoAuthorizedOrigins_SkipsValidation() async throws {
        // Given
        let noOriginClient = OAuthClient(
            clientID: Self.clientID,
            redirectURIs: [Self.redirectURI],
            allowedGrantType: .authorization,
            authorizedOrigins: nil
        )
        fakeClientRetriever.validClients[Self.clientID] = noOriginClient
        fakeCodeManager.generatedCode = "no-origin-code"

        // When - Should succeed even without Origin header (backward compatibility)
        let response = try await getPostAuthResponse(
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            origin: nil,
            approve: true
        )

        // Then
        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(
            response.headers.location?.value,
            "\(Self.redirectURI)?code=no-origin-code"
        )
    }

    func testPostAuthorizationWithEmptyAuthorizedOrigins_SkipsValidation() async throws {
        // Given
        let emptyOriginClient = OAuthClient(
            clientID: Self.clientID,
            redirectURIs: [Self.redirectURI],
            allowedGrantType: .authorization,
            authorizedOrigins: []
        )
        fakeClientRetriever.validClients[Self.clientID] = emptyOriginClient
        fakeCodeManager.generatedCode = "empty-origin-code"

        // When - Should succeed even without Origin header (backward compatibility)
        let response = try await getPostAuthResponse(
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            origin: nil,
            approve: true
        )

        // Then
        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(
            response.headers.location?.value,
            "\(Self.redirectURI)?code=empty-origin-code"
        )
    }

    // MARK: - State Parameter Tests

    func testPostAuthorizationOriginError_PreservesStateParameter() async throws {
        // Given
        let authorizedOrigins = ["https://example.com"]
        let originClient = OAuthClient(
            clientID: Self.clientID,
            redirectURIs: [Self.redirectURI],
            allowedGrantType: .authorization,
            authorizedOrigins: authorizedOrigins
        )
        fakeClientRetriever.validClients[Self.clientID] = originClient
        let state = "test-state-123"

        // When
        let response = try await getPostAuthResponse(
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            origin: "https://malicious.com",
            approve: true,
            state: state
        )

        // Then
        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(
            response.headers.location?.value,
            "\(Self.redirectURI)?error=unauthorized_client&error_description=Origin+not+authorized+for+this+client&state=\(state)"
        )
    }

    func testPostAuthorizationMissingOriginError_PreservesStateParameter() async throws {
        // Given
        let authorizedOrigins = ["https://example.com"]
        let originClient = OAuthClient(
            clientID: Self.clientID,
            redirectURIs: [Self.redirectURI],
            allowedGrantType: .authorization,
            authorizedOrigins: authorizedOrigins
        )
        fakeClientRetriever.validClients[Self.clientID] = originClient
        let state = "test-state-456"

        // When
        let response = try await getPostAuthResponse(
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            origin: nil,
            approve: true,
            state: state
        )

        // Then
        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(
            response.headers.location?.value,
            "\(Self.redirectURI)?error=invalid_request&error_description=Origin+header+required&state=\(state)"
        )
    }

    // MARK: - Implicit Grant Tests

    func testPostAuthorizationImplicitGrant_WithValidOrigin_Succeeds() async throws {
        // Given
        let authorizedOrigins = ["https://spa.example.com"]
        let implicitClient = OAuthClient(
            clientID: Self.clientID,
            redirectURIs: [Self.redirectURI],
            allowedGrantType: .implicit,
            authorizedOrigins: authorizedOrigins
        )
        fakeClientRetriever.validClients[Self.clientID] = implicitClient

        // When
        let response = try await getPostAuthResponse(
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            responseType: "token",
            origin: "https://spa.example.com",
            approve: true
        )

        // Then
        XCTAssertEqual(response.status, .seeOther)
        XCTAssertTrue(response.headers.location?.value.contains("#token_type=bearer&access_token=") ?? false)
    }

    func testPostAuthorizationImplicitGrant_WithInvalidOrigin_ReturnsError() async throws {
        // Given
        let authorizedOrigins = ["https://spa.example.com"]
        let implicitClient = OAuthClient(
            clientID: Self.clientID,
            redirectURIs: [Self.redirectURI],
            allowedGrantType: .implicit,
            authorizedOrigins: authorizedOrigins
        )
        fakeClientRetriever.validClients[Self.clientID] = implicitClient

        // When
        let response = try await getPostAuthResponse(
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            responseType: "token",
            origin: "https://malicious.com",
            approve: true
        )

        // Then
        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(
            response.headers.location?.value,
            "\(Self.redirectURI)?error=unauthorized_client&error_description=Origin+not+authorized+for+this+client"
        )
    }

    // MARK: - User Denial Tests

    func testPostAuthorizationUserDenial_WithOriginValidation_StillValidatesOrigin() async throws {
        // Given
        let authorizedOrigins = ["https://example.com"]
        let originClient = OAuthClient(
            clientID: Self.clientID,
            redirectURIs: [Self.redirectURI],
            allowedGrantType: .authorization,
            authorizedOrigins: authorizedOrigins
        )
        fakeClientRetriever.validClients[Self.clientID] = originClient

        // When - User denies but origin is invalid
        let response = try await getPostAuthResponse(
            clientID: Self.clientID,
            redirectURI: Self.redirectURI,
            origin: "https://malicious.com",
            approve: false
        )

        // Then - Origin validation should happen before user denial processing
        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(
            response.headers.location?.value,
            "\(Self.redirectURI)?error=unauthorized_client&error_description=Origin+not+authorized+for+this+client"
        )
    }

    // MARK: - Helper Methods

    private func getPostAuthResponse(
        clientID: String,
        redirectURI: String,
        responseType: String = "code",
        origin: String? = nil,
        approve: Bool,
        state: String? = nil,
        scope: String? = nil,
        user: OAuthUser? = nil,
        csrfToken: String? = nil,
        sessionID: String? = nil
    ) async throws -> XCTHTTPResponse {
        try await TestDataBuilder.getPostAuthResponseWithOrigin(
            with: app,
            clientID: clientID,
            redirectURI: redirectURI,
            responseType: responseType,
            origin: origin,
            approve: approve,
            state: state,
            scope: scope,
            user: user ?? TestDataBuilder.anyOAuthUser(),
            csrfToken: csrfToken ?? self.csrfToken,
            sessionID: sessionID ?? self.sessionID
        )
    }
}