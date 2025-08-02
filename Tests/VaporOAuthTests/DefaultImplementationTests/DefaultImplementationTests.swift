import XCTVapor

@testable import VaporOAuth

class DefaultImplementationTests: XCTestCase {
    // MARK: - Tests
    func testThatEmptyResourceServerRetrieverReturnsNilWhenGettingResourceServer() async throws {
        let emptyResourceServerRetriever = EmptyResourceServerRetriever()

        let server = try await emptyResourceServerRetriever.getServer("some username")
        XCTAssertNil(server)
    }

    func testThatEmptyUserManagerReturnsNilWhenAttemptingToAuthenticate() async throws {
        let emptyUserManager = EmptyUserManager()
        let token = try await emptyUserManager.authenticateUser(username: "username", password: "password")
        XCTAssertNil(token)
    }

    func testThatEmptyUserManagerReturnsNilWhenTryingToGetUser() async throws {
        let emptyUserManager = EmptyUserManager()
        let id = "some-id"
        let user = try await emptyUserManager.getUser(userID: id)
        XCTAssertNil(user)
    }

    func testThatEmptyAuthHandlerReturnsEmptyStringWhenHandlingAuthError() async throws {
        let emptyAuthHandler = EmptyAuthorizationHandler()

        let body = try await emptyAuthHandler.handleAuthorizationError(.invalidClientID).body

        XCTAssertEqual(body.string, "")
    }

    func testThatEmptyAuthHandlerReturnsEmptyStringWhenHandlingAuthRequest() async throws {
        let emptyAuthHandler = EmptyAuthorizationHandler()
        let app = try Application.testable()
        try await app.asyncShutdown()

        let request = Request(application: app, method: .POST, url: "/oauth/auth/", on: app.eventLoopGroup.next())
        let uri: URI = "https://api.brokenhands.io/callback"
        let authRequestObject = AuthorizationRequestObject(
            responseType: "token",
            clientID: "client-ID",
            redirectURI: uri,
            scope: ["email"],
            state: "abcdef",
            csrfToken: "01234",
            codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            codeChallengeMethod: "S256"
        )

        let body = try await emptyAuthHandler.handleAuthorizationRequest(
            request,
            authorizationRequestObject: authRequestObject
        ).body

        XCTAssertEqual(body.string, "")
    }

    func testThatEmptyCodeManagerReturnsNilWhenGettingCode() {
        let emptyCodeManager = EmptyCodeManager()
        XCTAssertNil(emptyCodeManager.getCode("code"))
    }

    func testThatEmptyCodeManagerGeneratesEmptyStringAsCode() throws {
        let emptyCodeManager = EmptyCodeManager()
        let id: String = "identifier"
        XCTAssertEqual(
            try emptyCodeManager.generateCode(
                userID: id,
                clientID: "client-id",
                redirectURI: "https://api.brokenhands.io/callback",
                scopes: nil,
                codeChallenge: nil,
                codeChallengeMethod: nil
            ),
            ""
        )
    }

    func testThatCodeUsedDoesNothingInEmptyCodeManager() {
        let emptyCodeManager = EmptyCodeManager()
        let id = "identifier"
        let code = OAuthCode(
            codeID: "id",
            clientID: "client-id",
            redirectURI: "https://api.brokenhands.io/callback",
            userID: id,
            expiryDate: Date(),
            scopes: nil,
            codeChallenge: nil,
            codeChallengeMethod: nil
        )
        emptyCodeManager.codeUsed(code)
    }

    // MARK: - StaticClientRetriever Tests

    func testStaticClientRetrieverReturnsCorrectClient() async throws {
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            clientSecret: "secret",
            validScopes: ["read"],
            confidential: true,
            firstParty: false,
            allowedGrantType: .authorization,
            authorizedOrigins: ["https://example.com"]
        )
        
        let retriever = StaticClientRetriever(clients: [client])
        
        let retrievedClient = try await retriever.getClient(clientID: "test-client")
        XCTAssertNotNil(retrievedClient)
        XCTAssertEqual(retrievedClient?.clientID, "test-client")
        XCTAssertEqual(retrievedClient?.authorizedOrigins, ["https://example.com"])
    }

    func testStaticClientRetrieverReturnsNilForUnknownClient() async throws {
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            clientSecret: "secret",
            validScopes: ["read"],
            confidential: true,
            firstParty: false,
            allowedGrantType: .authorization,
            authorizedOrigins: ["https://example.com"]
        )
        
        let retriever = StaticClientRetriever(clients: [client])
        
        let retrievedClient = try await retriever.getClient(clientID: "unknown-client")
        XCTAssertNil(retrievedClient)
    }

    func testStaticClientRetrieverWithExampleClients() async throws {
        let retriever = StaticClientRetriever.withExampleClients()
        
        // Test web app client
        let webAppClient = try await retriever.getClient(clientID: "web-app-client")
        XCTAssertNotNil(webAppClient)
        XCTAssertEqual(webAppClient?.clientID, "web-app-client")
        XCTAssertEqual(webAppClient?.authorizedOrigins, [
            "https://myapp.com",
            "https://staging.myapp.com",
            "http://localhost:3000"
        ])
        XCTAssertTrue(webAppClient?.confidentialClient == true)
        XCTAssertTrue(webAppClient?.firstParty == true)
        
        // Test SPA client with wildcard origins
        let spaClient = try await retriever.getClient(clientID: "spa-client")
        XCTAssertNotNil(spaClient)
        XCTAssertEqual(spaClient?.clientID, "spa-client")
        XCTAssertEqual(spaClient?.authorizedOrigins, [
            "*.example.com",
            "https://example.com"
        ])
        XCTAssertTrue(spaClient?.confidentialClient == false)
        
        // Test development client
        let devClient = try await retriever.getClient(clientID: "dev-client")
        XCTAssertNotNil(devClient)
        XCTAssertEqual(devClient?.clientID, "dev-client")
        XCTAssertEqual(devClient?.authorizedOrigins, [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://localhost:3000"
        ])
        
        // Test mobile app client (no origin validation)
        let mobileClient = try await retriever.getClient(clientID: "mobile-app-client")
        XCTAssertNotNil(mobileClient)
        XCTAssertEqual(mobileClient?.clientID, "mobile-app-client")
        XCTAssertNil(mobileClient?.authorizedOrigins)
        
        // Test legacy client (backward compatibility)
        let legacyClient = try await retriever.getClient(clientID: "legacy-client")
        XCTAssertNotNil(legacyClient)
        XCTAssertEqual(legacyClient?.clientID, "legacy-client")
        XCTAssertNil(legacyClient?.authorizedOrigins)
        
        // Test service client (server-to-server)
        let serviceClient = try await retriever.getClient(clientID: "service-client")
        XCTAssertNotNil(serviceClient)
        XCTAssertEqual(serviceClient?.clientID, "service-client")
        XCTAssertNil(serviceClient?.authorizedOrigins)
        XCTAssertEqual(serviceClient?.allowedGrantType, .clientCredentials)
    }

    func testStaticClientRetrieverForDevelopment() async throws {
        let retriever = StaticClientRetriever.forDevelopment()
        
        let devClient = try await retriever.getClient(clientID: "development-client")
        XCTAssertNotNil(devClient)
        XCTAssertEqual(devClient?.clientID, "development-client")
        XCTAssertEqual(devClient?.authorizedOrigins, [
            "http://localhost:3000",
            "http://localhost:8080",
            "https://dev.localhost",
            "*.dev.localhost"
        ])
        XCTAssertTrue(devClient?.confidentialClient == false)
        XCTAssertTrue(devClient?.firstParty == true)
        XCTAssertEqual(devClient?.allowedGrantType, .authorization)
        
        // Test that unknown client returns nil
        let unknownClient = try await retriever.getClient(clientID: "unknown-client")
        XCTAssertNil(unknownClient)
    }

    func testStaticClientRetrieverOriginValidationIntegration() async throws {
        let retriever = StaticClientRetriever.withExampleClients()
        
        // Test web app client origin validation
        let webAppClient = try await retriever.getClient(clientID: "web-app-client")
        XCTAssertNotNil(webAppClient)
        
        // Valid origins should pass
        XCTAssertTrue(webAppClient!.validateOrigin("https://myapp.com"))
        XCTAssertTrue(webAppClient!.validateOrigin("https://staging.myapp.com"))
        XCTAssertTrue(webAppClient!.validateOrigin("http://localhost:3000"))
        
        // Invalid origins should fail
        XCTAssertFalse(webAppClient!.validateOrigin("https://evil.com"))
        XCTAssertFalse(webAppClient!.validateOrigin("https://myapp.evil.com"))
        
        // Test SPA client with wildcard patterns
        let spaClient = try await retriever.getClient(clientID: "spa-client")
        XCTAssertNotNil(spaClient)
        
        // Wildcard should match subdomains
        XCTAssertTrue(spaClient!.validateOrigin("https://app.example.com"))
        XCTAssertTrue(spaClient!.validateOrigin("https://admin.example.com"))
        XCTAssertTrue(spaClient!.validateOrigin("https://dashboard.example.com"))
        
        // Root domain should also match (explicitly configured)
        XCTAssertTrue(spaClient!.validateOrigin("https://example.com"))
        
        // Invalid domains should fail
        XCTAssertFalse(spaClient!.validateOrigin("https://evil.com"))
        XCTAssertFalse(spaClient!.validateOrigin("https://example.evil.com"))
        
        // Test mobile client (no origin validation)
        let mobileClient = try await retriever.getClient(clientID: "mobile-app-client")
        XCTAssertNotNil(mobileClient)
        
        // Should allow any origin (backward compatibility)
        XCTAssertTrue(mobileClient!.validateOrigin("https://any-origin.com"))
        XCTAssertTrue(mobileClient!.validateOrigin("https://evil.com"))
        
        // Test legacy client (no origin validation)
        let legacyClient = try await retriever.getClient(clientID: "legacy-client")
        XCTAssertNotNil(legacyClient)
        
        // Should allow any origin (backward compatibility)
        XCTAssertTrue(legacyClient!.validateOrigin("https://any-origin.com"))
        XCTAssertTrue(legacyClient!.validateOrigin("https://evil.com"))
    }

    func testStaticClientRetrieverDevelopmentOriginValidation() async throws {
        let retriever = StaticClientRetriever.forDevelopment()
        let devClient = try await retriever.getClient(clientID: "development-client")
        XCTAssertNotNil(devClient)
        
        // Valid localhost origins should pass
        XCTAssertTrue(devClient!.validateOrigin("http://localhost:3000"))
        XCTAssertTrue(devClient!.validateOrigin("http://localhost:8080"))
        XCTAssertTrue(devClient!.validateOrigin("https://dev.localhost"))
        
        // Wildcard subdomain should work
        XCTAssertTrue(devClient!.validateOrigin("https://app.dev.localhost"))
        XCTAssertTrue(devClient!.validateOrigin("https://api.dev.localhost"))
        
        // Invalid origins should fail
        XCTAssertFalse(devClient!.validateOrigin("https://production.com"))
        XCTAssertFalse(devClient!.validateOrigin("http://localhost:9000"))
        XCTAssertFalse(devClient!.validateOrigin("https://evil.com"))
    }

    func testStaticClientRetrieverMultipleClientsWithSameID() async throws {
        // Test that later clients with same ID override earlier ones
        let client1 = OAuthClient(
            clientID: "duplicate-client",
            redirectURIs: ["https://first.com/callback"],
            clientSecret: "first-secret",
            validScopes: ["read"],
            confidential: true,
            firstParty: false,
            allowedGrantType: .authorization,
            authorizedOrigins: ["https://first.com"]
        )
        
        let client2 = OAuthClient(
            clientID: "duplicate-client",
            redirectURIs: ["https://second.com/callback"],
            clientSecret: "second-secret",
            validScopes: ["write"],
            confidential: false,
            firstParty: true,
            allowedGrantType: .implicit,
            authorizedOrigins: ["https://second.com"]
        )
        
        let retriever = StaticClientRetriever(clients: [client1, client2])
        
        let retrievedClient = try await retriever.getClient(clientID: "duplicate-client")
        XCTAssertNotNil(retrievedClient)
        
        // Should have the second client's properties
        XCTAssertEqual(retrievedClient?.clientSecret, "second-secret")
        XCTAssertEqual(retrievedClient?.validScopes, ["write"])
        XCTAssertEqual(retrievedClient?.confidentialClient, false)
        XCTAssertEqual(retrievedClient?.firstParty, true)
        XCTAssertEqual(retrievedClient?.allowedGrantType, .implicit)
        XCTAssertEqual(retrievedClient?.authorizedOrigins, ["https://second.com"])
    }

}
