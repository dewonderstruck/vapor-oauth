import XCTVapor

@testable import VaporOAuth

final class DeviceCodeFlowTests: XCTestCase {
    // MARK: - Properties
    var app: Application!
    var fakeClientGetter: FakeClientGetter!
    var fakeDeviceCodeManager: FakeDeviceCodeManager!
    var fakeTokenManager: FakeTokenManager!

    let testClientID = "device_client"
    let testClientRedirectURI = "https://api.brokenhands.io/callback"
    let testClientSecret = "device_secret"
    let testUserID = "test_user"
    let testScopes = ["profile", "email"]

    // MARK: - Overrides
    override func setUp() async throws {
        fakeClientGetter = FakeClientGetter()
        fakeDeviceCodeManager = FakeDeviceCodeManager()
        fakeTokenManager = FakeTokenManager()

        let oauthClient = OAuthClient(
            clientID: testClientID,
            redirectURIs: [testClientRedirectURI],
            clientSecret: testClientSecret,
            allowedGrantType: .deviceCode
        )
        fakeClientGetter.validClients[testClientID] = oauthClient

        let configuration = OAuthConfiguration(deviceVerificationURI: "/verify")
        app = try TestDataBuilder.getOAuth2Application(
            deviceCodeManager: fakeDeviceCodeManager,
            tokenManager: fakeTokenManager,
            clientRetriever: fakeClientGetter,
            configuration: configuration
        )
        app.oauth = configuration
    }

    override func tearDown() async throws {
        try await app.asyncShutdown()
        try await super.tearDown()
    }

    // MARK: - Tests
    func testDeviceAuthorizationSuccess() async throws {
        let response = try app.sendRequest(
            .POST, "oauth/device_authorization",
            beforeRequest: { req in
                try req.content.encode([
                    "client_id": "device_client",
                    "client_secret": "device_secret",
                    "scope": "profile",
                ])
            })

        XCTAssertEqual(response.status, .ok)

        let deviceResponse = try response.content.decode(DeviceAuthorizationHandler.DeviceResponse.self)
        XCTAssertFalse(deviceResponse.deviceCode.isEmpty)
        XCTAssertFalse(deviceResponse.userCode.isEmpty)
        XCTAssertFalse(deviceResponse.verificationURI.isEmpty)
        XCTAssertGreaterThan(deviceResponse.expiresIn, 0)
        XCTAssertGreaterThan(deviceResponse.interval, 0)

        // Verify headers
        XCTAssertEqual(response.headers[.cacheControl].first, "no-store")
        XCTAssertEqual(response.headers[.pragma].first, "no-cache")
    }

    func testDeviceAuthorizationMissingClientID() async throws {
        let response = try await getDeviceAuthorizationResponse(clientID: nil)
        XCTAssertEqual(response.status, .badRequest)

        let errorResponse = try response.content.decode(ErrorResponse.self)
        XCTAssertEqual(errorResponse.error, "invalid_request")
        XCTAssertEqual(errorResponse.errorDescription, "Request was missing the 'client_id' parameter")
    }

    func testDeviceAuthorizationInvalidClient() async throws {
        let response = try await getDeviceAuthorizationResponse(clientID: "invalid_client")
        XCTAssertEqual(response.status, .unauthorized)

        let errorResponse = try response.content.decode(ErrorResponse.self)
        XCTAssertEqual(errorResponse.error, "invalid_client")
    }

    // MARK: - Token Endpoint Tests

    func testDeviceCodeTokenSuccess() async throws {
        let deviceCode = setupAuthorizedDeviceCode()

        let response = try await getDeviceTokenResponse(deviceCode: deviceCode.deviceCode)
        XCTAssertEqual(response.status, .ok)

        let tokenResponse = try response.content.decode(TokenResponse.self)
        XCTAssertFalse(tokenResponse.accessToken?.isEmpty ?? true)
        XCTAssertFalse(tokenResponse.refreshToken?.isEmpty ?? true)
        XCTAssertEqual(tokenResponse.tokenType, "bearer")
        XCTAssertEqual(tokenResponse.expiresIn, 3600)
        XCTAssertEqual(tokenResponse.scope, "profile")
    }

    func testDeviceCodeTokenPending() async throws {
        let deviceCode = setupPendingDeviceCode()

        let response = try await getDeviceTokenResponse(deviceCode: deviceCode.deviceCode)
        XCTAssertEqual(response.status, .badRequest)  // Changed from .ok to .badRequest

        let errorResponse = try response.content.decode(ErrorResponse.self)
        XCTAssertEqual(errorResponse.error, "authorization_pending")
        XCTAssertEqual(errorResponse.errorDescription, "The authorization request is still pending")
    }

    func testDeviceCodeTokenExpired() async throws {
        let deviceCode = setupExpiredDeviceCode()

        let response = try await getDeviceTokenResponse(deviceCode: deviceCode.deviceCode)
        XCTAssertEqual(response.status, .badRequest)

        let errorResponse = try response.content.decode(ErrorResponse.self)
        XCTAssertEqual(errorResponse.error, "expired_token")
        XCTAssertEqual(errorResponse.errorDescription, "The device code has expired")

        // Verify required headers are present
        XCTAssertEqual(response.headers[.cacheControl].first, "no-store")
        XCTAssertEqual(response.headers[.pragma].first, "no-cache")
    }

    // MARK: - Device Authorization Endpoint Additional Tests
    func testDeviceAuthorizationInvalidScope() async throws {
        // Setup client with specific valid scopes
        let oauthClient = OAuthClient(
            clientID: testClientID,
            redirectURIs: [testClientRedirectURI],
            clientSecret: testClientSecret,
            validScopes: ["profile", "email"],
            allowedGrantType: .deviceCode
        )
        fakeClientGetter.validClients[testClientID] = oauthClient

        let response = try await getDeviceAuthorizationResponse(scope: "invalid_scope")
        XCTAssertEqual(response.status, .badRequest)

        let errorResponse = try response.content.decode(ErrorResponse.self)
        XCTAssertEqual(errorResponse.error, "invalid_scope")
        XCTAssertEqual(errorResponse.errorDescription, "The requested scope is invalid, unknown, or malformed")
    }

    func testDeviceAuthorizationRequiredHeaders() async throws {
        let response = try await getDeviceAuthorizationResponse()

        // RFC requires these headers
        XCTAssertEqual(response.headers[.contentType].first, "application/json; charset=utf-8")
        XCTAssertEqual(response.headers[.cacheControl].first, "no-store")
        XCTAssertEqual(response.headers[.pragma].first, "no-cache")
    }

    // MARK: - Token Endpoint Additional Tests
    func testDeviceCodeTokenSlowDown() async throws {
        let deviceCode = setupPendingDeviceCode()

        // First request
        let response1 = try await getDeviceTokenResponse(deviceCode: deviceCode.deviceCode)
        XCTAssertEqual(response1.status, .badRequest)

        // Immediate second request (too fast)
        let response2 = try await getDeviceTokenResponse(deviceCode: deviceCode.deviceCode)
        XCTAssertEqual(response2.status, .badRequest)

        let errorResponse = try response2.content.decode(ErrorResponse.self)
        XCTAssertEqual(errorResponse.error, "slow_down")
        XCTAssertEqual(errorResponse.errorDescription, "Polling too frequently")
    }

    func testDeviceCodeTokenAccessDenied() async throws {
        let deviceCode = setupDeniedDeviceCode()

        let response = try await getDeviceTokenResponse(deviceCode: deviceCode.deviceCode)
        XCTAssertEqual(response.status, .badRequest)

        let errorResponse = try response.content.decode(ErrorResponse.self)
        XCTAssertEqual(errorResponse.error, "access_denied")
        XCTAssertEqual(errorResponse.errorDescription, "The end-user denied the authorization request")
    }

    func testDeviceCodeTokenInvalidClient() async throws {
        let deviceCode = setupAuthorizedDeviceCode()

        let response = try await getDeviceTokenResponse(
            deviceCode: deviceCode.deviceCode,
            clientID: "invalid_client",
            clientSecret: "invalid_secret"
        )

        XCTAssertEqual(response.status, .unauthorized)
        let errorResponse = try response.content.decode(ErrorResponse.self)
        XCTAssertEqual(errorResponse.error, "invalid_client")
    }

    func testDeviceCodeTokenMissingDeviceCode() async throws {
        let response = try await getDeviceTokenResponse(deviceCode: "")
        XCTAssertEqual(response.status, .badRequest)

        let errorResponse = try response.content.decode(ErrorResponse.self)
        XCTAssertEqual(errorResponse.error, "expired_token")
        XCTAssertEqual(errorResponse.errorDescription, "The device code is invalid, expired, or already used")
    }

    func testDeviceCodeCannotBeReusedAfterSuccess() async throws {
        let deviceCode = setupAuthorizedDeviceCode(deviceCode: "replay_code")
        // First use: should succeed
        let firstResponse = try await getDeviceTokenResponse(deviceCode: deviceCode.deviceCode)
        XCTAssertEqual(firstResponse.status, .ok)
        // Second use: should fail (replay protection)
        let secondResponse = try await getDeviceTokenResponse(deviceCode: deviceCode.deviceCode)
        XCTAssertEqual(secondResponse.status, .badRequest)
        let errorResponse = try secondResponse.content.decode(ErrorResponse.self)
        XCTAssertEqual(errorResponse.error, "expired_token")
    }

    func testDeviceCodeIsRemovedAfterUseOrExpiry() async throws {
        let deviceCode = setupAuthorizedDeviceCode(deviceCode: "remove_code")
        _ = try await getDeviceTokenResponse(deviceCode: deviceCode.deviceCode)
        // Should be removed from manager
        XCTAssertNil(fakeDeviceCodeManager.deviceCodes[deviceCode.deviceCode])
        // Expired code
        let expiredCode = setupExpiredDeviceCode(deviceCode: "expired_remove_code")
        _ = try await getDeviceTokenResponse(deviceCode: expiredCode.deviceCode)
        XCTAssertNil(fakeDeviceCodeManager.deviceCodes[expiredCode.deviceCode])
    }

    func testPollingIntervalIncreasesAfterRepeatedSlowDown() async throws {
        let deviceCode = setupPendingDeviceCode(deviceCode: "slowdown_code")
        // First poll (pending)
        _ = try await getDeviceTokenResponse(deviceCode: deviceCode.deviceCode)
        // Second poll (too soon, triggers slow_down)
        _ = try await getDeviceTokenResponse(deviceCode: deviceCode.deviceCode)
        // Check that interval was increased in fake manager
        XCTAssertTrue(fakeDeviceCodeManager.increaseIntervalCalls.contains { $0.deviceCode == deviceCode.deviceCode })
    }

    // MARK: - Origin Validation Tests

    func testDeviceAuthorizationWithValidOrigin() async throws {
        // Setup client with authorized origins
        let oauthClient = OAuthClient(
            clientID: testClientID,
            redirectURIs: [testClientRedirectURI],
            clientSecret: testClientSecret,
            allowedGrantType: .deviceCode,
            authorizedOrigins: ["https://example.com", "https://app.example.com"]
        )
        fakeClientGetter.validClients[testClientID] = oauthClient

        let response = try await getDeviceAuthorizationResponseWithOrigin(
            origin: "https://example.com"
        )
        XCTAssertEqual(response.status, .ok)

        let deviceResponse = try response.content.decode(DeviceAuthorizationHandler.DeviceResponse.self)
        XCTAssertFalse(deviceResponse.deviceCode.isEmpty)
        XCTAssertFalse(deviceResponse.userCode.isEmpty)
    }

    func testDeviceAuthorizationWithInvalidOrigin() async throws {
        // Setup client with authorized origins
        let oauthClient = OAuthClient(
            clientID: testClientID,
            redirectURIs: [testClientRedirectURI],
            clientSecret: testClientSecret,
            allowedGrantType: .deviceCode,
            authorizedOrigins: ["https://example.com"]
        )
        fakeClientGetter.validClients[testClientID] = oauthClient

        let response = try await getDeviceAuthorizationResponseWithOrigin(
            origin: "https://malicious.com"
        )
        XCTAssertEqual(response.status, .badRequest)

        let errorResponse = try response.content.decode(ErrorResponse.self)
        XCTAssertEqual(errorResponse.error, "unauthorized_client")
        XCTAssertEqual(errorResponse.errorDescription, "Origin not authorized for this client")
    }

    func testDeviceAuthorizationWithMissingOriginFromBrowser() async throws {
        // Setup client with authorized origins
        let oauthClient = OAuthClient(
            clientID: testClientID,
            redirectURIs: [testClientRedirectURI],
            clientSecret: testClientSecret,
            allowedGrantType: .deviceCode,
            authorizedOrigins: ["https://example.com"]
        )
        fakeClientGetter.validClients[testClientID] = oauthClient

        // Make request with browser user agent but no origin header
        let response = try await getDeviceAuthorizationResponseWithHeaders(
            headers: [
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
            ]
        )
        XCTAssertEqual(response.status, .badRequest)

        let errorResponse = try response.content.decode(ErrorResponse.self)
        XCTAssertEqual(errorResponse.error, "invalid_request")
        XCTAssertEqual(errorResponse.errorDescription, "Origin header required for device authorization")
    }

    func testDeviceAuthorizationWithoutOriginFromNonBrowser() async throws {
        // Setup client with authorized origins
        let oauthClient = OAuthClient(
            clientID: testClientID,
            redirectURIs: [testClientRedirectURI],
            clientSecret: testClientSecret,
            allowedGrantType: .deviceCode,
            authorizedOrigins: ["https://example.com"]
        )
        fakeClientGetter.validClients[testClientID] = oauthClient

        // Make request without browser headers (e.g., from a CLI tool)
        let response = try await getDeviceAuthorizationResponseWithHeaders(
            headers: [
                "User-Agent": "MyApp/1.0"
            ]
        )
        XCTAssertEqual(response.status, .ok)

        // Should succeed because it's not detected as a browser request
        let deviceResponse = try response.content.decode(DeviceAuthorizationHandler.DeviceResponse.self)
        XCTAssertFalse(deviceResponse.deviceCode.isEmpty)
    }

    func testDeviceAuthorizationWithWildcardOrigin() async throws {
        // Setup client with wildcard authorized origins
        let oauthClient = OAuthClient(
            clientID: testClientID,
            redirectURIs: [testClientRedirectURI],
            clientSecret: testClientSecret,
            allowedGrantType: .deviceCode,
            authorizedOrigins: ["*.example.com"]
        )
        fakeClientGetter.validClients[testClientID] = oauthClient

        let response = try await getDeviceAuthorizationResponseWithOrigin(
            origin: "https://app.example.com"
        )
        XCTAssertEqual(response.status, .ok)

        let deviceResponse = try response.content.decode(DeviceAuthorizationHandler.DeviceResponse.self)
        XCTAssertFalse(deviceResponse.deviceCode.isEmpty)
    }

    func testDeviceAuthorizationBackwardCompatibilityNoOrigins() async throws {
        // Setup client without authorized origins (backward compatibility)
        let oauthClient = OAuthClient(
            clientID: testClientID,
            redirectURIs: [testClientRedirectURI],
            clientSecret: testClientSecret,
            allowedGrantType: .deviceCode
            // No authorizedOrigins specified
        )
        fakeClientGetter.validClients[testClientID] = oauthClient

        let response = try await getDeviceAuthorizationResponseWithOrigin(
            origin: "https://any-origin.com"
        )
        XCTAssertEqual(response.status, .ok)

        // Should succeed because no origins are configured (backward compatibility)
        let deviceResponse = try response.content.decode(DeviceAuthorizationHandler.DeviceResponse.self)
        XCTAssertFalse(deviceResponse.deviceCode.isEmpty)
    }

    // MARK: - Helper Methods

    private func getDeviceAuthorizationResponse(
        clientID: String? = "device_client",
        clientSecret: String? = "device_secret",
        scope: String? = "profile"
    ) async throws -> XCTHTTPResponse {
        return try await TestDataBuilder.getDeviceAuthorizationResponse(
            with: app,
            clientID: clientID,
            clientSecret: clientSecret,
            scope: scope
        )
    }

    private func getDeviceTokenResponse(
        deviceCode: String,
        clientID: String = "device_client",
        clientSecret: String = "device_secret"
    ) async throws -> XCTHTTPResponse {
        return try await TestDataBuilder.getDeviceTokenResponse(
            with: app,
            deviceCode: deviceCode,
            clientID: clientID,
            clientSecret: clientSecret
        )
    }

    private func getDeviceAuthorizationResponseWithOrigin(
        origin: String,
        clientID: String = "device_client",
        clientSecret: String = "device_secret",
        scope: String? = "profile"
    ) async throws -> XCTHTTPResponse {
        return try await getDeviceAuthorizationResponseWithHeaders(
            headers: [
                "Origin": origin,
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
            ],
            clientID: clientID,
            clientSecret: clientSecret,
            scope: scope
        )
    }

    private func getDeviceAuthorizationResponseWithHeaders(
        headers: [String: String],
        clientID: String = "device_client",
        clientSecret: String = "device_secret",
        scope: String? = "profile"
    ) async throws -> XCTHTTPResponse {
        return try app.sendRequest(
            .POST, "oauth/device_authorization",
            beforeRequest: { req in
                // Add headers
                for (name, value) in headers {
                    req.headers.add(name: HTTPHeaders.Name(name), value: value)
                }
                
                // Add content
                var content: [String: String] = [:]
                content["client_id"] = clientID
                content["client_secret"] = clientSecret
                if let scope = scope {
                    content["scope"] = scope
                }
                try req.content.encode(content)
            })
    }

    // MARK: - Test Setup Helpers

    private func setupAuthorizedDeviceCode(
        deviceCode: String = "valid_device_code",
        userCode: String = "ABCD-1234",
        scopes: [String] = ["profile"]
    ) -> OAuthDeviceCode {
        let code = OAuthDeviceCode(
            deviceCode: deviceCode,
            userCode: userCode,
            clientID: testClientID,
            verificationURI: "/verify",
            verificationURIComplete: nil,
            expiryDate: Date().addingTimeInterval(300),
            interval: 5,
            scopes: scopes,
            status: .authorized,
            userID: "test_user"
        )
        fakeDeviceCodeManager.deviceCodes[deviceCode] = code
        return code
    }

    private func setupPendingDeviceCode(
        deviceCode: String = "pending_code",
        userCode: String = "WXYZ-5678",
        scopes: [String] = ["profile"]
    ) -> OAuthDeviceCode {
        let code = OAuthDeviceCode(
            deviceCode: deviceCode,
            userCode: userCode,
            clientID: testClientID,
            verificationURI: "/verify",
            verificationURIComplete: nil,
            expiryDate: Date().addingTimeInterval(300),
            interval: 5,
            scopes: scopes,
            status: .unauthorized
        )
        fakeDeviceCodeManager.deviceCodes[deviceCode] = code
        return code
    }

    private func setupExpiredDeviceCode(
        deviceCode: String = "expired_code",
        userCode: String = "WXYZ-5678",
        scopes: [String]? = ["profile"]
    ) -> OAuthDeviceCode {
        let code = OAuthDeviceCode(
            deviceCode: deviceCode,
            userCode: userCode,
            clientID: testClientID,
            verificationURI: "/verify",
            verificationURIComplete: nil,
            expiryDate: Date().addingTimeInterval(-300),  // Set to expired (5 minutes ago)
            interval: 5,
            scopes: scopes,
            status: .pending,  // Using new status enum
            userID: nil,
            lastPolled: nil
        )
        fakeDeviceCodeManager.deviceCodes[deviceCode] = code
        return code
    }

    private func setupDeniedDeviceCode(
        deviceCode: String = "denied_code",
        userCode: String = "WXYZ-5678",
        scopes: [String] = ["profile"]
    ) -> OAuthDeviceCode {
        let code = OAuthDeviceCode(
            deviceCode: deviceCode,
            userCode: userCode,
            clientID: testClientID,
            verificationURI: "/verify",
            verificationURIComplete: nil,
            expiryDate: Date().addingTimeInterval(300),
            interval: 5,
            scopes: scopes,
            status: .declined
        )
        fakeDeviceCodeManager.deviceCodes[deviceCode] = code
        return code
    }
}

// MARK: - Response Models
extension DeviceCodeFlowTests {
    struct ErrorResponse: Decodable {
        var error: String
        var errorDescription: String

        enum CodingKeys: String, CodingKey {
            case error
            case errorDescription = "error_description"
        }
    }

    struct DeviceResponse: Decodable {
        var deviceCode: String
        var userCode: String
        var verificationURI: String
        var verificationURIComplete: String?
        var expiresIn: Int
        var interval: Int

        enum CodingKeys: String, CodingKey {
            case deviceCode = "device_code"
            case userCode = "user_code"
            case verificationURI = "verification_uri"
            case verificationURIComplete = "verification_uri_complete"
            case expiresIn = "expires_in"
            case interval
        }
    }

    struct TokenResponse: Decodable {
        var tokenType: String?
        var expiresIn: Int?
        var accessToken: String?
        var refreshToken: String?
        var scope: String?

        enum CodingKeys: String, CodingKey {
            case tokenType = "token_type"
            case expiresIn = "expires_in"
            case accessToken = "access_token"
            case refreshToken = "refresh_token"
            case scope
        }
    }
}
