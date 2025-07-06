import XCTVapor

@testable import VaporOAuth

class TokenRevocationTests: XCTestCase {
    // MARK: - Properties
    var app: Application!
    var fakeTokenManager: FakeTokenManager!
    var fakeClientRetriever: FakeClientGetter!

    let testClientID = "ABCDEF"
    let testClientSecret = "01234567890"
    let accessToken = "ABDEFGHIJKLMNO01234567890"
    let refreshToken = "REFRESH-TOKEN-12345"
    let scope1 = "email"
    let scope2 = "create"

    // MARK: - Overrides
    override func setUp() async throws {
        fakeTokenManager = FakeTokenManager()
        fakeClientRetriever = FakeClientGetter()

        app = try await TestDataBuilder.getOAuth2Application(
            tokenManager: fakeTokenManager,
            clientRetriever: fakeClientRetriever,
            validScopes: [scope1, scope2]
        )

        let client = OAuthClient(
            clientID: testClientID,
            redirectURIs: ["https://new.brokenhands.io/callback"],
            clientSecret: testClientSecret,
            validScopes: [scope1, scope2],
            allowedGrantType: .authorization
        )
        fakeClientRetriever.validClients[testClientID] = client

        let validAccessToken = FakeAccessToken(
            tokenString: accessToken,
            clientID: testClientID,
            userID: nil,
            scopes: [scope1],
            expiryTime: Date().addingTimeInterval(60)
        )
        fakeTokenManager.accessTokens[accessToken] = validAccessToken

        let validRefreshToken = FakeRefreshToken(
            tokenString: refreshToken,
            clientID: testClientID,
            userID: nil,
            scopes: [scope1]
        )
        fakeTokenManager.refreshTokens[refreshToken] = validRefreshToken
    }

    override func tearDown() async throws {
        try await app.asyncShutdown()
        try await super.tearDown()
    }

    // MARK: - Tests
    func testCorrectErrorWhenTokenParameterNotSuppliedInRequest() async throws {
        let response = try await getRevocationResponse(token: nil)
        let responseJSON = try response.content.decode(TokenRevocationHandler.ErrorResponse.self)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_request")
        XCTAssertEqual(responseJSON.errorDescription, "Request was missing the 'token' parameter")
    }

    func testCorrectErrorWhenClientIDNotSuppliedInRequest() async throws {
        let response = try await getRevocationResponse(clientID: nil)
        let responseJSON = try response.content.decode(TokenRevocationHandler.ErrorResponse.self)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_request")
        XCTAssertEqual(responseJSON.errorDescription, "Request was missing the 'client_id' parameter")
    }

    func testCorrectErrorWhenInvalidClientCredentialsSupplied() async throws {
        let response = try await getRevocationResponse(clientSecret: "wrong-secret")
        let responseJSON = try response.content.decode(TokenRevocationHandler.ErrorResponse.self)

        XCTAssertEqual(response.status, .unauthorized)
        XCTAssertEqual(responseJSON.error, "invalid_client")
        XCTAssertEqual(responseJSON.errorDescription, "Request had invalid client credentials")
    }

    func testSuccessfulAccessTokenRevocation() async throws {
        let response = try await getRevocationResponse(
            token: accessToken,
            tokenTypeHint: "access_token"
        )

        XCTAssertEqual(response.status, .ok)
        let token = fakeTokenManager.getAccessToken(accessToken)
        XCTAssertNil(token)
    }

    func testSuccessfulRefreshTokenRevocation() async throws {
        let response = try await getRevocationResponse(
            token: refreshToken,
            tokenTypeHint: "refresh_token"
        )

        XCTAssertEqual(response.status, .ok)
        let token = fakeTokenManager.getRefreshToken(refreshToken)
        XCTAssertNil(token)
    }

    func testSuccessfulRevocationWithoutTypeHint() async throws {
        let response = try await getRevocationResponse(token: accessToken)

        XCTAssertEqual(response.status, .ok)
        let token = fakeTokenManager.getAccessToken(accessToken)
        XCTAssertNil(token)
    }

    func testNonExistentTokenReturnsSuccess() async throws {
        let response = try await getRevocationResponse(token: "non-existent-token")

        XCTAssertEqual(response.status, .ok)
    }

    func testWrongClientIDForTokenReturnsSuccess() async throws {
        let response = try await getRevocationResponse(
            token: accessToken,
            clientID: "wrong-client-id",
            clientSecret: "wrong-secret"
        )

        XCTAssertEqual(response.status, .unauthorized)
    }

    func testResponseContainsCorrectCacheHeaders() async throws {
        let response = try await getRevocationResponse(token: accessToken)

        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testInvalidContentTypeReturnsError() async throws {
        try await app.test(
            .POST,
            "/oauth/revoke",
            beforeRequest: { request in
                request.headers.contentType = .json

                var components = URLComponents()
                components.queryItems = [
                    URLQueryItem(name: "token", value: accessToken),
                    URLQueryItem(name: "client_id", value: testClientID),
                    URLQueryItem(name: "client_secret", value: testClientSecret),
                ]
                let formData = components.percentEncodedQuery ?? ""

                request.body = ByteBuffer(string: formData)
            },
            afterResponse: { response in
                XCTAssertEqual(response.status, .badRequest)
                let errorResponse = try response.content.decode(TokenRevocationHandler.ErrorResponse.self)
                XCTAssertEqual(errorResponse.error, "invalid_request")
                XCTAssertEqual(errorResponse.errorDescription, "Content-Type must be application/x-www-form-urlencoded")
            }
        )
    }

    // MARK: - Helper method
    func getRevocationResponse(
        token: String? = "ABDEFGHIJKLMNO01234567890",
        tokenTypeHint: String? = nil,
        clientID: String? = "ABCDEF",
        clientSecret: String? = "01234567890"
    ) async throws -> XCTHTTPResponse {
        return try await withCheckedThrowingContinuation { continuation in
            do {
                try app.test(
                    .POST,
                    "/oauth/revoke",
                    beforeRequest: { request in
                        request.headers.contentType = .urlEncodedForm

                        var components = URLComponents()
                        var queryItems: [URLQueryItem] = []

                        if let token = token {
                            queryItems.append(URLQueryItem(name: "token", value: token))
                        }
                        if let tokenTypeHint = tokenTypeHint {
                            queryItems.append(URLQueryItem(name: "token_type_hint", value: tokenTypeHint))
                        }
                        if let clientId = clientID {
                            queryItems.append(URLQueryItem(name: "client_id", value: clientId))
                        }
                        if let clientSecret = clientSecret {
                            queryItems.append(URLQueryItem(name: "client_secret", value: clientSecret))
                        }

                        components.queryItems = queryItems
                        let formData = components.percentEncodedQuery ?? ""

                        request.body = ByteBuffer(string: formData)
                    },
                    afterResponse: { response in
                        continuation.resume(returning: response)
                    }
                )
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }
}
