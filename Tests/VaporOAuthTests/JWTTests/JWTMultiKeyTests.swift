import JWTKit
import XCTVapor

@testable import VaporOAuth

class JWTMultiKeyTests: XCTestCase {

    // MARK: - Multi-Key JWT Configuration Tests

    func testMultiKeyTokenGenerationAndValidation() async throws {
        // Create multi-key configuration with HMAC + RSA + ECDSA
        let config = try await JWTConfiguration.multiKey(
            issuer: "test-issuer",
            hmacSecret: "test-hmac-secret",
            rsaPrivateKeyPEM: TestDataBuilder.rsaPrivateKeyPEM,
            ecdsaPrivateKeyPEM: TestDataBuilder.ecdsaPrivateKeyPEM,
            useJWT: true
        )

        let storage = InMemoryTokenStorage()
        let tokenManager = JWTTokenManager(configuration: config, storage: storage)

        // Test data
        let clientID = "test-client"
        let userID = "test-user"
        let scopes = ["read", "write"]

        // Generate tokens using different key types
        let (accessToken, refreshToken) = try await tokenManager.generateAccessRefreshTokens(
            clientID: clientID,
            userID: userID,
            scopes: scopes,
            accessTokenExpiryTime: 3600
        )

        // Verify the access token is a valid JWT
        XCTAssertTrue(accessToken.tokenString.contains("."))
        XCTAssertEqual(accessToken.tokenString.components(separatedBy: ".").count, 3)

        // Verify the refresh token is a valid JWT
        XCTAssertTrue(refreshToken.tokenString.contains("."))
        XCTAssertEqual(refreshToken.tokenString.components(separatedBy: ".").count, 3)

        // Validate the access token
        let accessPayload = try await config.keyCollection.verify(accessToken.tokenString, as: JWTAccessToken.self)
        XCTAssertEqual(accessPayload.iss.value, config.issuer)
        XCTAssertEqual(accessPayload.sub.value, userID)
        XCTAssertEqual(accessPayload.aud.value, [clientID])
        XCTAssertEqual(accessPayload.scope, scopes.joined(separator: " "))
        XCTAssertEqual(accessPayload.clientID, clientID)
        XCTAssertEqual(accessPayload.tokenType, "Bearer")

        // Validate the refresh token
        let refreshPayload = try await config.keyCollection.verify(refreshToken.tokenString, as: JWTRefreshToken.self)
        XCTAssertEqual(refreshPayload.iss.value, config.issuer)
        XCTAssertEqual(refreshPayload.sub.value, userID)
        XCTAssertEqual(refreshPayload.aud.value, [clientID])
        XCTAssertEqual(refreshPayload.scope, scopes.joined(separator: " "))
        XCTAssertEqual(refreshPayload.clientID, clientID)
        XCTAssertEqual(refreshPayload.tokenType, "Refresh")

        // Verify tokens are stored
        let storedAccessToken = try await storage.getAccessToken(accessToken.tokenString)
        XCTAssertNotNil(storedAccessToken)
        XCTAssertEqual(storedAccessToken?.tokenString, accessToken.tokenString)

        let storedRefreshToken = try await storage.getRefreshToken(refreshToken.tokenString)
        XCTAssertNotNil(storedRefreshToken)
        XCTAssertEqual(storedRefreshToken?.tokenString, refreshToken.tokenString)
    }

    func testMultiKeyTokenValidationWithDifferentKeys() async throws {
        // Create multi-key configuration
        let config = try await JWTConfiguration.multiKey(
            issuer: "test-issuer",
            hmacSecret: "test-hmac-secret",
            rsaPrivateKeyPEM: TestDataBuilder.rsaPrivateKeyPEM,
            ecdsaPrivateKeyPEM: TestDataBuilder.ecdsaPrivateKeyPEM,
            useJWT: true
        )

        let storage = InMemoryTokenStorage()
        let tokenManager = JWTTokenManager(configuration: config, storage: storage)

        // Generate tokens
        let (accessToken, _) = try await tokenManager.generateAccessRefreshTokens(
            clientID: "test-client",
            userID: "test-user",
            scopes: ["read"],
            accessTokenExpiryTime: 3600
        )

        // Verify the token can be validated with the multi-key configuration
        let payload = try await config.keyCollection.verify(accessToken.tokenString, as: JWTAccessToken.self)
        XCTAssertEqual(payload.iss.value, config.issuer)

        // Test that the token is valid and not expired
        let now = Date()
        XCTAssertGreaterThan(payload.exp.value, now)
        XCTAssertLessThanOrEqual(payload.iat.value, now)
    }

    func testMultiKeyJWKSExposure() async throws {
        // Create multi-key configuration
        let config = try await JWTConfiguration.multiKey(
            issuer: "test-issuer",
            rsaPrivateKeyPEM: TestDataBuilder.rsaPrivateKeyPEM,
            ecdsaPrivateKeyPEM: TestDataBuilder.ecdsaPrivateKeyPEM,
            useJWT: true
        )

        // Verify JWKS contains the correct number of public keys
        XCTAssertEqual(config.publicJWKs.count, 2)

        let rsaKeys = config.publicJWKs.filter { $0.keyType == .rsa }
        let ecdsaKeys = config.publicJWKs.filter { $0.keyType == .ecdsa }

        XCTAssertEqual(rsaKeys.count, 1)
        XCTAssertEqual(ecdsaKeys.count, 1)

        // Verify RSA key properties
        let rsaKey = rsaKeys.first!
        XCTAssertEqual(rsaKey.keyType, .rsa)
        XCTAssertNotNil(rsaKey.modulus) // modulus
        XCTAssertNotNil(rsaKey.exponent) // exponent
        XCTAssertNotNil(rsaKey.keyIdentifier) // key ID

        // Verify ECDSA key properties
        let ecdsaKey = ecdsaKeys.first!
        XCTAssertEqual(ecdsaKey.keyType, .ecdsa)
        XCTAssertNotNil(ecdsaKey.curve) // curve
        XCTAssertNotNil(ecdsaKey.x) // x coordinate
        XCTAssertNotNil(ecdsaKey.y) // y coordinate
        XCTAssertNotNil(ecdsaKey.keyIdentifier) // key ID
    }

    func testMultiKeyTokenRevocation() async throws {
        // Create multi-key configuration
        let config = try await JWTConfiguration.multiKey(
            issuer: "test-issuer",
            hmacSecret: "test-hmac-secret",
            rsaPrivateKeyPEM: TestDataBuilder.rsaPrivateKeyPEM,
            useJWT: true
        )

        let storage = InMemoryTokenStorage()
        let tokenManager = JWTTokenManager(configuration: config, storage: storage)

        // Generate tokens
        let (accessToken, refreshToken) = try await tokenManager.generateAccessRefreshTokens(
            clientID: "test-client",
            userID: "test-user",
            scopes: ["read"],
            accessTokenExpiryTime: 3600
        )

        // Verify tokens are stored
        let storedAccessToken = try await storage.getAccessToken(accessToken.tokenString)
        let storedRefreshToken = try await storage.getRefreshToken(refreshToken.tokenString)
        XCTAssertNotNil(storedAccessToken)
        XCTAssertNotNil(storedRefreshToken)

        // Revoke access token
        try await storage.revokeAccessToken(accessToken.tokenString)
        let revokedAccessToken = try await storage.getAccessToken(accessToken.tokenString)
        XCTAssertNil(revokedAccessToken)

        // Revoke refresh token
        try await storage.revokeRefreshToken(refreshToken.tokenString)
        let revokedRefreshToken = try await storage.getRefreshToken(refreshToken.tokenString)
        XCTAssertNil(revokedRefreshToken)
    }

    func testMultiKeyTokenExpiration() async throws {
        // Create multi-key configuration
        let config = try await JWTConfiguration.multiKey(
            issuer: "test-issuer",
            hmacSecret: "test-hmac-secret",
            useJWT: true
        )

        let storage = InMemoryTokenStorage()
        let tokenManager = JWTTokenManager(configuration: config, storage: storage)

        // Generate token with short expiration
        let (accessToken, _) = try await tokenManager.generateAccessRefreshTokens(
            clientID: "test-client",
            userID: "test-user",
            scopes: ["read"],
            accessTokenExpiryTime: 1 // 1 second
        )

        // Verify token is valid initially
        let payload = try await config.keyCollection.verify(accessToken.tokenString, as: JWTAccessToken.self)
        XCTAssertEqual(payload.iss.value, config.issuer)

        // Wait for token to expire
        try await Task.sleep(nanoseconds: 2_000_000_000) // 2 seconds

        // Verify token is now expired by checking that verification throws an error
        do {
            _ = try await config.keyCollection.verify(accessToken.tokenString, as: JWTAccessToken.self)
            XCTFail("Token should be expired and verification should fail")
        } catch {
            // Expected error for expired token - any error is acceptable
            XCTAssertTrue(error is Error, "Expected an error for expired token")
        }
    }

    func testMultiKeyDifferentKeyTypes() async throws {
        // Test HMAC-only configuration
        let hmacConfig = await JWTConfiguration.hmac(
            issuer: "test-issuer",
            secret: "test-hmac-secret",
            useJWT: true
        )

        // Test RSA-only configuration
        let rsaConfig = try await JWTConfiguration.multiKey(
            issuer: "test-issuer",
            rsaPrivateKeyPEM: TestDataBuilder.rsaPrivateKeyPEM,
            useJWT: true
        )

        // Test ECDSA-only configuration
        let ecdsaConfig = try await JWTConfiguration.multiKey(
            issuer: "test-issuer",
            ecdsaPrivateKeyPEM: TestDataBuilder.ecdsaPrivateKeyPEM,
            useJWT: true
        )

        // Verify JWKS exposure
        XCTAssertEqual(hmacConfig.publicJWKs.count, 0) // HMAC not exposed
        XCTAssertEqual(rsaConfig.publicJWKs.count, 1) // RSA exposed
        XCTAssertEqual(ecdsaConfig.publicJWKs.count, 1) // ECDSA exposed

        // Test token generation with each configuration
        let storage = InMemoryTokenStorage()

        // HMAC tokens
        let hmacManager = JWTTokenManager(configuration: hmacConfig, storage: storage)
        let (hmacToken, _) = try await hmacManager.generateAccessRefreshTokens(
            clientID: "test-client",
            userID: "test-user",
            scopes: ["read"],
            accessTokenExpiryTime: 3600
        )

        // RSA tokens
        let rsaManager = JWTTokenManager(configuration: rsaConfig, storage: storage)
        let (rsaToken, _) = try await rsaManager.generateAccessRefreshTokens(
            clientID: "test-client",
            userID: "test-user",
            scopes: ["read"],
            accessTokenExpiryTime: 3600
        )

        // ECDSA tokens
        let ecdsaManager = JWTTokenManager(configuration: ecdsaConfig, storage: storage)
        let (ecdsaToken, _) = try await ecdsaManager.generateAccessRefreshTokens(
            clientID: "test-client",
            userID: "test-user",
            scopes: ["read"],
            accessTokenExpiryTime: 3600
        )

        // Verify all tokens are valid JWTs
        XCTAssertTrue(hmacToken.tokenString.contains("."))
        XCTAssertTrue(rsaToken.tokenString.contains("."))
        XCTAssertTrue(ecdsaToken.tokenString.contains("."))

        // Verify tokens can be validated with their respective configurations
        let hmacPayload = try await hmacConfig.keyCollection.verify(hmacToken.tokenString, as: JWTAccessToken.self)
        let rsaPayload = try await rsaConfig.keyCollection.verify(rsaToken.tokenString, as: JWTAccessToken.self)
        let ecdsaPayload = try await ecdsaConfig.keyCollection.verify(ecdsaToken.tokenString, as: JWTAccessToken.self)

        XCTAssertEqual(hmacPayload.iss.value, "test-issuer")
        XCTAssertEqual(rsaPayload.iss.value, "test-issuer")
        XCTAssertEqual(ecdsaPayload.iss.value, "test-issuer")
    }

    func testMultiKeyTokenCrossValidation() async throws {
        // Create two different multi-key configurations
        let config1 = try await JWTConfiguration.multiKey(
            issuer: "test-issuer-1",
            hmacSecret: "test-hmac-secret-1",
            rsaPrivateKeyPEM: TestDataBuilder.rsaPrivateKeyPEM,
            useJWT: true
        )

        let config2 = try await JWTConfiguration.multiKey(
            issuer: "test-issuer-2",
            hmacSecret: "test-hmac-secret-2",
            ecdsaPrivateKeyPEM: TestDataBuilder.ecdsaPrivateKeyPEM,
            useJWT: true
        )

        let storage = InMemoryTokenStorage()

        // Generate tokens with config1
        let manager1 = JWTTokenManager(configuration: config1, storage: storage)
        let (token1, _) = try await manager1.generateAccessRefreshTokens(
            clientID: "test-client",
            userID: "test-user",
            scopes: ["read"],
            accessTokenExpiryTime: 3600
        )

        // Generate tokens with config2
        let manager2 = JWTTokenManager(configuration: config2, storage: storage)
        let (token2, _) = try await manager2.generateAccessRefreshTokens(
            clientID: "test-client",
            userID: "test-user",
            scopes: ["read"],
            accessTokenExpiryTime: 3600
        )

        // Verify tokens can only be validated with their respective configurations
        let payload1 = try await config1.keyCollection.verify(token1.tokenString, as: JWTAccessToken.self)
        let payload2 = try await config2.keyCollection.verify(token2.tokenString, as: JWTAccessToken.self)

        XCTAssertEqual(payload1.iss.value, "test-issuer-1")
        XCTAssertEqual(payload2.iss.value, "test-issuer-2")

        // Verify cross-validation fails
        do {
            _ = try await config2.keyCollection.verify(token1.tokenString, as: JWTAccessToken.self)
            XCTFail("Token from config1 should not validate with config2")
        } catch {
            // Expected error
        }

        do {
            _ = try await config1.keyCollection.verify(token2.tokenString, as: JWTAccessToken.self)
            XCTFail("Token from config2 should not validate with config1")
        } catch {
            // Expected error
        }
    }
} 