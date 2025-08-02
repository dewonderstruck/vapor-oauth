import XCTVapor

@testable import VaporOAuth

class AuthorizationRequestTests: XCTestCase {

    // MARK: - Properties

    var app: Application!
    var fakeClientRetriever: FakeClientGetter!
    var capturingAuthoriseHandler: CapturingAuthoriseHandler!

    let clientID = "1234567890"
    let redirectURI = "https://api.brokenhands.io/callback"

    // MARK: - Overrides

    override func setUp() async throws {
        fakeClientRetriever = FakeClientGetter()
        capturingAuthoriseHandler = CapturingAuthoriseHandler()

        let oauthClient = OAuthClient(
            clientID: clientID,
            redirectURIs: [redirectURI],
            allowedGrantType: .authorization
        )
        fakeClientRetriever.validClients[clientID] = oauthClient

        app = try TestDataBuilder.getOAuth2Application(
            clientRetriever: fakeClientRetriever,
            authorizeHandler: capturingAuthoriseHandler
        )
    }

    override func tearDown() async throws {
        try await app.asyncShutdown()
        try await super.tearDown()
    }

    // MARK: - Tests

    func testThatAuthorizationCodeRequestCallsAuthoriseHandlerWithQueryParameters() async throws {
        let responseType = "code"

        _ = try await respondToOAuthRequest(responseType: responseType, clientID: clientID, redirectURI: redirectURI)

        XCTAssertEqual(capturingAuthoriseHandler.responseType, responseType)
        XCTAssertEqual(capturingAuthoriseHandler.clientID, clientID)
        XCTAssertEqual(capturingAuthoriseHandler.redirectURI, URI(string: redirectURI))
    }

    func testThatAuthorizationTokenRequestRedirectsToAuthoriseApplicationPage() async throws {
        let responseType = "token"
        let implicitClientID = "implicit"
        let implicitClient = OAuthClient(
            clientID: implicitClientID,
            redirectURIs: [redirectURI],
            allowedGrantType: .implicit
        )
        fakeClientRetriever.validClients[implicitClientID] = implicitClient

        _ = try await respondToOAuthRequest(
            responseType: responseType,
            clientID: implicitClientID,
            redirectURI: redirectURI
        )

        XCTAssertEqual(capturingAuthoriseHandler.responseType, responseType)
        XCTAssertEqual(capturingAuthoriseHandler.clientID, implicitClientID)
        XCTAssertEqual(capturingAuthoriseHandler.redirectURI, URI(string: redirectURI))
    }

    func testThatAuthorizeRequestResponseTypeRedirectsBackToClientWithErrorCode() async throws {
        let response = try await respondToOAuthRequest(
            responseType: nil,
            clientID: clientID,
            redirectURI: redirectURI
        )

        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(
            response.headers.first(name: "location"),
            "\(redirectURI)?error=invalid_request&error_description=Request+was+missing+the+response_type+parameter"
        )
    }

    func testThatBadRequestRedirectsBackToClientRedirectURI() async throws {
        let differentURI = "https://api.test.com/cb"
        let clientID = "123ABC"
        let client = OAuthClient(clientID: clientID, redirectURIs: [differentURI], allowedGrantType: .authorization)
        fakeClientRetriever.validClients[clientID] = client

        let response = try await respondToOAuthRequest(
            responseType: nil,
            clientID: clientID,
            redirectURI: differentURI
        )

        XCTAssertEqual(
            response.headers.first(name: "location"),
            "\(differentURI)?error=invalid_request&error_description=Request+was+missing+the+response_type+parameter"
        )
    }

    func testThatStateProvidedWhenRedirectingForMissingReponseType() async throws {
        let state = "xcoivjuywkdkhvusuye3kch"

        let response = try await respondToOAuthRequest(
            responseType: nil,
            clientID: clientID,
            redirectURI: redirectURI,
            state: state
        )

        XCTAssertTrue(response.headers.location?.value.contains("state=\(state)") ?? false)
    }

    func testThatAuthorizeRequestRedirectsBackToClientWithErrorCodeResponseTypeIsNotCodeOrToken() async throws {
        let response = try await respondToOAuthRequest(
            responseType: "invalid",
            clientID: clientID,
            redirectURI: redirectURI
        )

        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(
            response.headers.location?.value,
            "\(redirectURI)?error=invalid_request&error_description=invalid+response+type"
        )
    }

    func testThatStateProvidedWhenRedirectingForInvalidReponseType() async throws {
        let state = "xcoivjuywkdkhvusuye3kch"

        let response = try await respondToOAuthRequest(
            responseType: "invalid",
            clientID: clientID,
            redirectURI: redirectURI,
            state: state
        )

        XCTAssertTrue(response.headers.location?.value.contains("state=\(state)") ?? false)
    }

    func testThatAuthorizeRequestFailsWithoutClientIDQuery() async throws {
        _ = try await respondToOAuthRequest(clientID: nil, redirectURI: redirectURI)

        XCTAssertEqual(capturingAuthoriseHandler.authorizationError, .invalidClientID)
    }

    func testThatAuthorizeRequestFailsWithoutRedirectURI() async throws {
        _ = try await respondToOAuthRequest(clientID: clientID, redirectURI: nil)

        XCTAssertEqual(capturingAuthoriseHandler.authorizationError, .invalidRedirectURI)
    }

    func testThatSingleScopePassedThroughToAuthorizationHandler() async throws {
        let scope = "profile"

        _ = try await respondToOAuthRequest(clientID: clientID, redirectURI: redirectURI, scope: scope)

        XCTAssertEqual(capturingAuthoriseHandler.scope?.count, 1)
        XCTAssertTrue(capturingAuthoriseHandler.scope?.contains(scope) ?? false)
    }

    func testThatMultipleScopesPassedThroughToAuthorizationHandler() async throws {
        let scope1 = "profile"
        let scope2 = "create"
        let scope = "\(scope1)+\(scope2)"

        _ = try await respondToOAuthRequest(clientID: clientID, redirectURI: redirectURI, scope: scope)

        XCTAssertEqual(capturingAuthoriseHandler.scope?.count, 2)
        XCTAssertTrue(capturingAuthoriseHandler.scope?.contains(scope1) ?? false)
        XCTAssertTrue(capturingAuthoriseHandler.scope?.contains(scope2) ?? false)
    }

    func testStatePassedThroughToAuthorizationHandler() async throws {
        let state = "xcoivjuywkdkhvusuye3kch"

        _ = try await respondToOAuthRequest(clientID: clientID, redirectURI: redirectURI, state: state)

        XCTAssertEqual(capturingAuthoriseHandler.state, state)
    }

    func testAllPropertiesPassedThroughToAuthorizationHandler() async throws {
        let responseType = "code"
        let scope1 = "profile"
        let scope2 = "create"
        let state = "xcoivjuywkdkhvusuye3kch"
        let scope = "\(scope1)+\(scope2)"

        _ = try await respondToOAuthRequest(
            responseType: responseType,
            clientID: clientID,
            redirectURI: redirectURI,
            scope: scope,
            state: state
        )

        XCTAssertEqual(capturingAuthoriseHandler.responseType, responseType)
        XCTAssertEqual(capturingAuthoriseHandler.clientID, clientID)
        XCTAssertEqual(capturingAuthoriseHandler.redirectURI, URI(string: redirectURI))
        XCTAssertEqual(capturingAuthoriseHandler.scope?.count, 2)
        XCTAssertTrue(capturingAuthoriseHandler.scope?.contains(scope1) ?? false)
        XCTAssertTrue(capturingAuthoriseHandler.scope?.contains(scope2) ?? false)
        XCTAssertEqual(capturingAuthoriseHandler.state, state)
    }

    func testThatAnInvalidClientIDLoadsErrorPage() async throws {
        let clientID = "invalid"

        _ = try await respondToOAuthRequest(clientID: clientID, redirectURI: redirectURI)

        XCTAssertEqual(capturingAuthoriseHandler.authorizationError, .invalidClientID)
    }

    func testThatInvalidRedirectURICallsErrorHandlerWithCorrectError() async throws {
        _ = try await respondToOAuthRequest(clientID: clientID, redirectURI: "http://this.does.not/match")

        XCTAssertEqual(capturingAuthoriseHandler.authorizationError, .invalidRedirectURI)
    }

    func testThatUnknownScopeReturnsInvalidScopeError() async throws {
        try await app.asyncShutdown()
        app = try TestDataBuilder.getOAuth2Application(
            clientRetriever: fakeClientRetriever,
            authorizeHandler: capturingAuthoriseHandler,
            validScopes: ["email", "profile", "admin"]
        )
        let invalidScope = "create"

        let response = try await respondToOAuthRequest(
            clientID: clientID,
            redirectURI: redirectURI,
            scope: invalidScope
        )

        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(
            response.headers.location?.value,
            "\(redirectURI)?error=invalid_scope&error_description=scope+is+unknown"
        )
    }

    func testThatClientAccessingScopeItShouldNotReturnsInvalidScopeError() async throws {
        let clientID = "ABCDEFGH"
        let scopes = ["email", "profile", "admin"]
        let invalidScope = "create"
        let scopeClient = OAuthClient(
            clientID: clientID,
            redirectURIs: [redirectURI],
            validScopes: scopes,
            allowedGrantType: .authorization
        )
        fakeClientRetriever.validClients[clientID] = scopeClient

        let response = try await respondToOAuthRequest(
            clientID: clientID,
            redirectURI: redirectURI,
            scope: invalidScope
        )

        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(
            response.headers.location?.value,
            "\(redirectURI)?error=invalid_scope&error_description=scope+is+invalid"
        )
    }

    func testConfidentialClientMakingTokenRequestResultsInUnauthorizedClientError() async throws {
        let clientID = "ABCDEFGH"
        let responseType = "token"
        let confidentialClient = OAuthClient(
            clientID: clientID,
            redirectURIs: [redirectURI],
            confidential: true,
            allowedGrantType: .authorization
        )
        fakeClientRetriever.validClients[clientID] = confidentialClient

        let response = try await respondToOAuthRequest(
            responseType: responseType,
            clientID: clientID,
            redirectURI: redirectURI
        )

        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(
            response.headers.location?.value,
            "\(redirectURI)?error=unauthorized_client&error_description=token+grant+disabled+for+confidential+clients"
        )
    }

    func testNonHTTPSRedirectURICanNotBeUsedWhenInProduction() async throws {
        try await app.asyncShutdown()
        app = try TestDataBuilder.getOAuth2Application(
            clientRetriever: fakeClientRetriever,
            authorizeHandler: capturingAuthoriseHandler,
            environment: .production
        )

        let nonHTTPSRedirectURI = "http://api.brokenhands.io/callback/"
        let httpClient = OAuthClient(
            clientID: clientID,
            redirectURIs: [nonHTTPSRedirectURI],
            allowedGrantType: .authorization
        )
        fakeClientRetriever.validClients[clientID] = httpClient

        _ = try await respondToOAuthRequest(clientID: clientID, redirectURI: nonHTTPSRedirectURI)

        XCTAssertEqual(capturingAuthoriseHandler.authorizationError, .httpRedirectURI)
    }

    func testCSRFTokenProvidedToAuthorizeHandler() async throws {
        _ = try await respondToOAuthRequest(clientID: clientID, redirectURI: redirectURI)

        XCTAssertNotNil(capturingAuthoriseHandler.csrfToken)
    }

    func testCSRFTokenIsDifferentEachTime() async throws {
        _ = try await respondToOAuthRequest(clientID: clientID, redirectURI: redirectURI)

        let firstToken = capturingAuthoriseHandler.csrfToken

        _ = try await respondToOAuthRequest(clientID: clientID, redirectURI: redirectURI)

        XCTAssertNotEqual(firstToken, capturingAuthoriseHandler.csrfToken)
    }

    func testClientNotConfiguredWithAccessToAuthCodeFlowCantAccessItForGet() async throws {
        let unauthorizedID = "not-allowed"
        let unauthorizedClient = OAuthClient(
            clientID: unauthorizedID,
            redirectURIs: [redirectURI],
            clientSecret: nil,
            validScopes: nil,
            allowedGrantType: .implicit
        )
        fakeClientRetriever.validClients[unauthorizedID] = unauthorizedClient

        let response = try await respondToOAuthRequest(clientID: unauthorizedID, redirectURI: redirectURI)

        XCTAssertEqual(response.status, .forbidden)
    }

    func testClientConfiguredWithAccessToAuthCodeFlowCanAccessItForGet() async throws {
        let authorizedID = "not-allowed"
        let authorizedClient = OAuthClient(
            clientID: authorizedID,
            redirectURIs: [redirectURI],
            clientSecret: nil,
            validScopes: nil,
            allowedGrantType: .authorization
        )
        fakeClientRetriever.validClients[authorizedID] = authorizedClient

        let response = try await respondToOAuthRequest(
            clientID: authorizedID,
            redirectURI: redirectURI
        )

        XCTAssertEqual(response.status, .ok)
    }

    // MARK: - Origin Validation Integration Tests

    func testAuthorizationRequestWithValidOrigin_Succeeds() async throws {
        let clientID = "origin-client"
        let authorizedOrigins = ["https://example.com", "https://app.example.com"]
        let originClient = OAuthClient(
            clientID: clientID,
            redirectURIs: [redirectURI],
            allowedGrantType: .authorization,
            authorizedOrigins: authorizedOrigins
        )
        fakeClientRetriever.validClients[clientID] = originClient

        let response = try await respondToOAuthRequestWithOrigin(
            clientID: clientID,
            redirectURI: redirectURI,
            origin: "https://example.com"
        )

        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(capturingAuthoriseHandler.clientID, clientID)
    }

    func testAuthorizationRequestWithInvalidOrigin_ReturnsUnauthorizedClientError() async throws {
        let clientID = "origin-client"
        let authorizedOrigins = ["https://example.com"]
        let originClient = OAuthClient(
            clientID: clientID,
            redirectURIs: [redirectURI],
            allowedGrantType: .authorization,
            authorizedOrigins: authorizedOrigins
        )
        fakeClientRetriever.validClients[clientID] = originClient

        let response = try await respondToOAuthRequestWithOrigin(
            clientID: clientID,
            redirectURI: redirectURI,
            origin: "https://malicious.com"
        )

        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(
            response.headers.location?.value,
            "\(redirectURI)?error=unauthorized_client&error_description=Origin+not+authorized+for+this+client"
        )
    }

    func testAuthorizationRequestWithMissingOrigin_ReturnsInvalidRequestError() async throws {
        let clientID = "origin-client"
        let authorizedOrigins = ["https://example.com"]
        let originClient = OAuthClient(
            clientID: clientID,
            redirectURIs: [redirectURI],
            allowedGrantType: .authorization,
            authorizedOrigins: authorizedOrigins
        )
        fakeClientRetriever.validClients[clientID] = originClient

        let response = try await respondToOAuthRequest(
            clientID: clientID,
            redirectURI: redirectURI
        )

        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(
            response.headers.location?.value,
            "\(redirectURI)?error=invalid_request&error_description=Origin+header+required"
        )
    }

    func testAuthorizationRequestWithWildcardOrigin_Succeeds() async throws {
        let clientID = "wildcard-client"
        let authorizedOrigins = ["*.example.com"]
        let wildcardClient = OAuthClient(
            clientID: clientID,
            redirectURIs: [redirectURI],
            allowedGrantType: .authorization,
            authorizedOrigins: authorizedOrigins
        )
        fakeClientRetriever.validClients[clientID] = wildcardClient

        let response = try await respondToOAuthRequestWithOrigin(
            clientID: clientID,
            redirectURI: redirectURI,
            origin: "https://app.example.com"
        )

        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(capturingAuthoriseHandler.clientID, clientID)
    }

    func testAuthorizationRequestWithMultipleAuthorizedOrigins_ValidatesCorrectly() async throws {
        let clientID = "multi-origin-client"
        let authorizedOrigins = ["https://example.com", "https://app.example.com", "http://localhost:3000"]
        let multiOriginClient = OAuthClient(
            clientID: clientID,
            redirectURIs: [redirectURI],
            allowedGrantType: .authorization,
            authorizedOrigins: authorizedOrigins
        )
        fakeClientRetriever.validClients[clientID] = multiOriginClient

        // Test first origin
        let response1 = try await respondToOAuthRequestWithOrigin(
            clientID: clientID,
            redirectURI: redirectURI,
            origin: "https://example.com"
        )
        XCTAssertEqual(response1.status, .ok)

        // Test second origin
        let response2 = try await respondToOAuthRequestWithOrigin(
            clientID: clientID,
            redirectURI: redirectURI,
            origin: "https://app.example.com"
        )
        XCTAssertEqual(response2.status, .ok)

        // Test third origin
        let response3 = try await respondToOAuthRequestWithOrigin(
            clientID: clientID,
            redirectURI: redirectURI,
            origin: "http://localhost:3000"
        )
        XCTAssertEqual(response3.status, .ok)

        // Test invalid origin
        let response4 = try await respondToOAuthRequestWithOrigin(
            clientID: clientID,
            redirectURI: redirectURI,
            origin: "https://malicious.com"
        )
        XCTAssertEqual(response4.status, .seeOther)
        XCTAssertTrue(response4.headers.location?.value.contains("error=unauthorized_client") ?? false)
    }

    func testAuthorizationRequestWithNoAuthorizedOrigins_SkipsValidation() async throws {
        let clientID = "no-origin-client"
        let noOriginClient = OAuthClient(
            clientID: clientID,
            redirectURIs: [redirectURI],
            allowedGrantType: .authorization
            // No authorizedOrigins specified
        )
        fakeClientRetriever.validClients[clientID] = noOriginClient

        // Should succeed even without Origin header (backward compatibility)
        let response = try await respondToOAuthRequest(
            clientID: clientID,
            redirectURI: redirectURI
        )

        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(capturingAuthoriseHandler.clientID, clientID)
    }

    func testAuthorizationRequestWithEmptyAuthorizedOrigins_SkipsValidation() async throws {
        let clientID = "empty-origin-client"
        let emptyOriginClient = OAuthClient(
            clientID: clientID,
            redirectURIs: [redirectURI],
            allowedGrantType: .authorization,
            authorizedOrigins: [] // Empty array
        )
        fakeClientRetriever.validClients[clientID] = emptyOriginClient

        // Should succeed even without Origin header (backward compatibility)
        let response = try await respondToOAuthRequest(
            clientID: clientID,
            redirectURI: redirectURI
        )

        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(capturingAuthoriseHandler.clientID, clientID)
    }

    func testAuthorizationRequestWithStatePreservedInOriginError() async throws {
        let clientID = "origin-client"
        let state = "test-state-123"
        let authorizedOrigins = ["https://example.com"]
        let originClient = OAuthClient(
            clientID: clientID,
            redirectURIs: [redirectURI],
            allowedGrantType: .authorization,
            authorizedOrigins: authorizedOrigins
        )
        fakeClientRetriever.validClients[clientID] = originClient

        let response = try await respondToOAuthRequestWithOrigin(
            clientID: clientID,
            redirectURI: redirectURI,
            state: state,
            origin: "https://malicious.com"
        )

        XCTAssertEqual(response.status, .seeOther)
        XCTAssertTrue(response.headers.location?.value.contains("state=\(state)") ?? false)
        XCTAssertTrue(response.headers.location?.value.contains("error=unauthorized_client") ?? false)
    }

    //    // MARK: - Private

    private func respondToOAuthRequest(
        responseType: String? = "code",
        clientID: String?,
        redirectURI: String?,
        scope: String? = nil,
        state: String? = nil
    ) async throws -> XCTHTTPResponse {
        try await TestDataBuilder.getAuthRequestResponse(
            with: app,
            responseType: responseType,
            clientID: clientID,
            redirectURI: redirectURI,
            scope: scope,
            state: state
        )
    }

    private func respondToOAuthRequestWithOrigin(
        responseType: String? = "code",
        clientID: String?,
        redirectURI: String?,
        scope: String? = nil,
        state: String? = nil,
        origin: String
    ) async throws -> XCTHTTPResponse {
        try await TestDataBuilder.getAuthRequestResponseWithOrigin(
            with: app,
            responseType: responseType,
            clientID: clientID,
            redirectURI: redirectURI,
            scope: scope,
            state: state,
            origin: origin
        )
    }

}

extension URI: Equatable {
    public static func == (lhs: URI, rhs: URI) -> Bool {
        return lhs.description == rhs.description
    }
}
