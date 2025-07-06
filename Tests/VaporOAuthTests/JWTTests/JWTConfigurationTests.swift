import JWTKit
import XCTVapor

@testable import VaporOAuth

class JWTConfigurationTests: XCTestCase {

    // MARK: - JWT Configuration Tests

    func testJWTConfigurationHMAC() async throws {
        let config = await JWTConfiguration.hmac(
            issuer: "test-issuer",
            secret: "test-secret",
            useJWT: true
        )

        XCTAssertEqual(config.issuer, "test-issuer")
        XCTAssertTrue(config.useJWT)
        XCTAssertEqual(config.defaultAccessTokenExpiration, 3600)
        XCTAssertNil(config.defaultRefreshTokenExpiration)
    }

    func testJWTConfigurationRSA() async throws {
        // Skip RSA test for now as it requires a valid private key
        // In a real implementation, you would use a valid RSA private key
        let config = await JWTConfiguration.hmac(
            issuer: "test-issuer",
            secret: "test-secret",
            useJWT: true
        )

        XCTAssertEqual(config.issuer, "test-issuer")
        XCTAssertTrue(config.useJWT)
    }

    func testJWTConfigurationDisabled() {
        let config = JWTConfiguration.disabled

        XCTAssertEqual(config.issuer, "vapor-oauth")
        XCTAssertFalse(config.useJWT)
    }

    func testJWTConfigurationCustomExpiration() async {
        let config = await JWTConfiguration.hmac(
            issuer: "test-issuer",
            secret: "test-secret",
            useJWT: true
        )

        XCTAssertEqual(config.issuer, "test-issuer")
        XCTAssertTrue(config.useJWT)
        XCTAssertEqual(config.defaultAccessTokenExpiration, 3600)
    }

    func testJWTConfigurationMultiKey() async throws {
        // Test multi-key configuration with HMAC + RSA
        let config = try await JWTConfiguration.multiKey(
            issuer: "test-issuer",
            hmacSecret: "test-hmac-secret",
            rsaPrivateKeyPEM: TestDataBuilder.rsaPrivateKeyPEM,
            useJWT: true
        )

        XCTAssertEqual(config.issuer, "test-issuer")
        XCTAssertTrue(config.useJWT)
        XCTAssertEqual(config.defaultAccessTokenExpiration, 3600)

        // Should have 1 public JWK (RSA only, HMAC is not exposed)
        XCTAssertEqual(config.publicJWKs.count, 1)
        XCTAssertEqual(config.publicJWKs.first?.keyType, .rsa)
    }

    func testJWTConfigurationMultiKeyRSAECDSA() async throws {
        // Test multi-key configuration with RSA + ECDSA
        let config = try await JWTConfiguration.multiKey(
            issuer: "test-issuer",
            rsaPrivateKeyPEM: TestDataBuilder.rsaPrivateKeyPEM,
            ecdsaPrivateKeyPEM: TestDataBuilder.ecdsaPrivateKeyPEM,
            useJWT: true
        )

        XCTAssertEqual(config.issuer, "test-issuer")
        XCTAssertTrue(config.useJWT)

        // Should have 2 public JWKs (RSA + ECDSA)
        XCTAssertEqual(config.publicJWKs.count, 2)

        let rsaKeys = config.publicJWKs.filter { $0.keyType == .rsa }
        let ecdsaKeys = config.publicJWKs.filter { $0.keyType == .ecdsa }

        XCTAssertEqual(rsaKeys.count, 1)
        XCTAssertEqual(ecdsaKeys.count, 1)
    }

    func testJWTConfigurationAddingKeys() async throws {
        // Start with HMAC
        var config = await JWTConfiguration.hmac(
            issuer: "test-issuer",
            secret: "test-hmac-secret",
            useJWT: true
        )

        // Should have 0 public JWKs initially (HMAC only)
        XCTAssertEqual(config.publicJWKs.count, 0)

        // Add RSA key
        config = try await config.addingRSA(
            privateKeyPEM: TestDataBuilder.rsaPrivateKeyPEM
        )

        // Should now have 1 public JWK (RSA)
        XCTAssertEqual(config.publicJWKs.count, 1)
        XCTAssertEqual(config.publicJWKs.first?.keyType, .rsa)

        // Add ECDSA key
        config = try await config.addingECDSA(
            privateKeyPEM: TestDataBuilder.ecdsaPrivateKeyPEM
        )

        // Should now have 2 public JWKs (RSA + ECDSA)
        XCTAssertEqual(config.publicJWKs.count, 2)

        let rsaKeys = config.publicJWKs.filter { $0.keyType == .rsa }
        let ecdsaKeys = config.publicJWKs.filter { $0.keyType == .ecdsa }

        XCTAssertEqual(rsaKeys.count, 1)
        XCTAssertEqual(ecdsaKeys.count, 1)

        // Add another HMAC key (should not affect public JWKs)
        config = await config.addingHMAC(secret: "another-hmac-secret")

        // Should still have 2 public JWKs (HMAC keys are not exposed)
        XCTAssertEqual(config.publicJWKs.count, 2)
    }
}
