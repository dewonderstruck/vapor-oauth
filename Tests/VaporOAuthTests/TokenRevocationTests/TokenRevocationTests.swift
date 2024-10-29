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
    override func setUp() {
        fakeTokenManager = FakeTokenManager()
        fakeClientRetriever = FakeClientGetter()
        
        app = try! TestDataBuilder.getOAuth2Application(
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
    
    // MARK: - Helper method
    func getRevocationResponse(
        token: String? = "ABDEFGHIJKLMNO01234567890",
        tokenTypeHint: String? = nil,
        clientID: String? = "ABCDEF",
        clientSecret: String? = "01234567890"
    ) async throws -> XCTHTTPResponse {
        struct RevocationData: Content {
            var token: String?
            var token_type_hint: String?
            var client_id: String?
            var client_secret: String?
        }
        
        return try await withCheckedThrowingContinuation { continuation in
            do {
                try app.test(
                    .POST,
                    "/oauth/revoke",
                    beforeRequest: { request in
                        let revocationData = RevocationData(
                            token: token,
                            token_type_hint: tokenTypeHint,
                            client_id: clientID,
                            client_secret: clientSecret
                        )
                        try request.content.encode(revocationData)
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
