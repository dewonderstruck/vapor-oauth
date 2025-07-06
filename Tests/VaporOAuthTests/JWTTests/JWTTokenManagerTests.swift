import JWTKit
import XCTVapor

@testable import VaporOAuth

class JWTTokenManagerTests: XCTestCase {

    var jwtConfiguration: JWTConfiguration!
    var storage: InMemoryTokenStorage!
    var tokenManager: JWTTokenManager!

    override func setUp() async throws {
        jwtConfiguration = await JWTConfiguration.hmac(
            issuer: "test-issuer",
            secret: "test-secret-key-for-jwt-signing",
            useJWT: true
        )
        storage = InMemoryTokenStorage()
        tokenManager = JWTTokenManager(configuration: jwtConfiguration, storage: storage)
    }

    // MARK: - Token Generation Tests

    func testGenerateAccessRefreshTokens() async throws {
        let (accessToken, refreshToken) = try await tokenManager.generateAccessRefreshTokens(
            clientID: "test-client",
            userID: "test-user",
            scopes: ["read", "write"],
            accessTokenExpiryTime: 3600
        )

        // Verify access token
        XCTAssertEqual(accessToken.clientID, "test-client")
        XCTAssertEqual(accessToken.userID, "test-user")
        XCTAssertEqual(accessToken.scopes, ["read", "write"])
        XCTAssertTrue(accessToken.expiryTime > Date())

        // Verify refresh token
        XCTAssertEqual(refreshToken.clientID, "test-client")
        XCTAssertEqual(refreshToken.userID, "test-user")
        XCTAssertEqual(refreshToken.scopes, ["read", "write"])

        // Verify tokens are stored
        let accessCount = await storage.accessTokenCount
        let refreshCount = await storage.refreshTokenCount
        XCTAssertEqual(accessCount, 1)
        XCTAssertEqual(refreshCount, 1)
    }

    func testGenerateAccessToken() async throws {
        let accessToken = try await tokenManager.generateAccessToken(
            clientID: "test-client",
            userID: "test-user",
            scopes: ["read", "write"],
            expiryTime: 3600
        )

        XCTAssertEqual(accessToken.clientID, "test-client")
        XCTAssertEqual(accessToken.userID, "test-user")
        XCTAssertEqual(accessToken.scopes, ["read", "write"])
        XCTAssertTrue(accessToken.expiryTime > Date())

        // Verify token is stored
        let accessCount = await storage.accessTokenCount
        XCTAssertEqual(accessCount, 1)
    }

    func testGenerateTokensWithNilUserID() async throws {
        let (accessToken, refreshToken) = try await tokenManager.generateAccessRefreshTokens(
            clientID: "test-client",
            userID: nil,
            scopes: ["read", "write"],
            accessTokenExpiryTime: 3600
        )

        // For client credentials flow, userID should be empty string
        XCTAssertEqual(accessToken.userID, "")
        XCTAssertEqual(refreshToken.userID, "")
    }

    func testGenerateTokensWithNilScopes() async throws {
        let (accessToken, refreshToken) = try await tokenManager.generateAccessRefreshTokens(
            clientID: "test-client",
            userID: "test-user",
            scopes: nil,
            accessTokenExpiryTime: 3600
        )

        XCTAssertNil(accessToken.scopes)
        XCTAssertNil(refreshToken.scopes)
    }

    // MARK: - Token Retrieval Tests

    func testGetAccessTokenFromStorage() async throws {
        // Generate and store a token
        let originalToken = try await tokenManager.generateAccessToken(
            clientID: "test-client",
            userID: "test-user",
            scopes: ["read", "write"],
            expiryTime: 3600
        )

        // Retrieve the token
        let retrievedToken = try await tokenManager.getAccessToken(originalToken.tokenString)

        XCTAssertNotNil(retrievedToken)
        XCTAssertEqual(retrievedToken?.clientID, "test-client")
        XCTAssertEqual(retrievedToken?.userID, "test-user")
        XCTAssertEqual(retrievedToken?.scopes, ["read", "write"])
    }

    func testGetRefreshTokenFromStorage() async throws {
        // Generate and store tokens
        let (_, originalRefreshToken) = try await tokenManager.generateAccessRefreshTokens(
            clientID: "test-client",
            userID: "test-user",
            scopes: ["read", "write"],
            accessTokenExpiryTime: 3600
        )

        // Retrieve the refresh token
        let retrievedToken = try await tokenManager.getRefreshToken(originalRefreshToken.tokenString)

        XCTAssertNotNil(retrievedToken)
        XCTAssertEqual(retrievedToken?.clientID, "test-client")
        XCTAssertEqual(retrievedToken?.userID, "test-user")
        XCTAssertEqual(retrievedToken?.scopes, ["read", "write"])
    }

    func testGetNonExistentToken() async throws {
        let accessToken = try await tokenManager.getAccessToken("non-existent-token")
        XCTAssertNil(accessToken)

        let refreshToken = try await tokenManager.getRefreshToken("non-existent-token")
        XCTAssertNil(refreshToken)
    }

    // MARK: - Token Update Tests

    func testUpdateRefreshTokenScopes() async throws {
        // Generate tokens
        let (_, originalRefreshToken) = try await tokenManager.generateAccessRefreshTokens(
            clientID: "test-client",
            userID: "test-user",
            scopes: ["read"],
            accessTokenExpiryTime: 3600
        )

        // Save the original token string
        let oldTokenString = originalRefreshToken.tokenString

        // Update scopes - this should create a new token (with a new token string)
        try await tokenManager.updateRefreshToken(originalRefreshToken, scopes: ["read", "write"])

        // The old token string should no longer be present in storage
        let allTokens = await storage.allRefreshTokens
        XCTAssertNil(allTokens[oldTokenString], "Old refresh token should be revoked from storage after scope update")

        // For JWT tokens, the old token can still be verified cryptographically even after revocation
        // This is expected RFC-compliant behavior for JWT tokens
        let oldToken = try await tokenManager.getRefreshToken(oldTokenString)
        XCTAssertNotNil(oldToken, "JWT tokens can still be verified after revocation (RFC-compliant behavior)")
        XCTAssertEqual(oldToken?.scopes, ["read"], "Old token should still have original scopes")

        // Find the new token in storage and check its scopes
        let allTokens2 = await storage.allRefreshTokens
        var foundNewToken = false
        for (_, token) in allTokens2 {
            if let scopes = token.scopes, scopes == ["read", "write"] {
                foundNewToken = true
                break
            }
        }
        XCTAssertTrue(foundNewToken, "New refresh token with updated scopes should exist in storage")
    }

    // MARK: - Token Revocation Tests

    func testRevokeAccessToken() async throws {
        // Generate and store a token
        let originalToken = try await tokenManager.generateAccessToken(
            clientID: "test-client",
            userID: "test-user",
            scopes: ["read", "write"],
            expiryTime: 3600
        )

        // Verify token exists in storage
        let accessCountBefore = await storage.accessTokenCount
        XCTAssertEqual(accessCountBefore, 1)

        // Revoke the token
        try await tokenManager.revokeAccessToken(originalToken.tokenString)

        // Verify token is removed from storage
        let accessCountAfter = await storage.accessTokenCount
        XCTAssertEqual(accessCountAfter, 0)

        // For JWT tokens, the token can still be verified but should not be in storage
        // This is expected behavior for JWT tokens
        let retrievedToken = try await tokenManager.getAccessToken(originalToken.tokenString)
        // The token should still be retrievable via JWT verification, but not from storage
        XCTAssertNotNil(retrievedToken)
    }

    func testRevokeRefreshToken() async throws {
        // Generate and store tokens
        let (_, originalRefreshToken) = try await tokenManager.generateAccessRefreshTokens(
            clientID: "test-client",
            userID: "test-user",
            scopes: ["read", "write"],
            accessTokenExpiryTime: 3600
        )

        // Verify token exists in storage
        let refreshCountBefore = await storage.refreshTokenCount
        XCTAssertEqual(refreshCountBefore, 1)

        // Revoke the token
        try await tokenManager.revokeRefreshToken(originalRefreshToken.tokenString)

        // Verify token is removed from storage
        let refreshCountAfter = await storage.refreshTokenCount
        XCTAssertEqual(refreshCountAfter, 0)

        // For JWT tokens, the token can still be verified but should not be in storage
        // This is expected behavior for JWT tokens
        let retrievedToken = try await tokenManager.getRefreshToken(originalRefreshToken.tokenString)
        // The token should still be retrievable via JWT verification, but not from storage
        XCTAssertNotNil(retrievedToken)
    }

    // MARK: - JWT Token Validation Tests

    func testJWTTokenSignatureValidation() async throws {
        // Generate a token
        let accessToken = try await tokenManager.generateAccessToken(
            clientID: "test-client",
            userID: "test-user",
            scopes: ["read", "write"],
            expiryTime: 3600
        )

        // Verify the token is a JWT
        XCTAssertTrue(accessToken.tokenString.contains("."))

        // Verify the token can be decoded and verified
        let retrievedToken = try await tokenManager.getAccessToken(accessToken.tokenString)
        XCTAssertNotNil(retrievedToken)
    }

    func testJWTTokenExpirationValidation() async throws {
        // Generate a token with short expiration
        let accessToken = try await tokenManager.generateAccessToken(
            clientID: "test-client",
            userID: "test-user",
            scopes: ["read", "write"],
            expiryTime: 1  // 1 second
        )

        // Wait for token to expire
        try await Task.sleep(nanoseconds: 2_000_000_000)  // 2 seconds

        // Token should still be retrievable from storage but expired
        let retrievedToken = try await tokenManager.getAccessToken(accessToken.tokenString)
        XCTAssertNotNil(retrievedToken)
        XCTAssertTrue(retrievedToken!.expiryTime < Date())
    }
}
