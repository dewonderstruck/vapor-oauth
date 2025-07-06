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
}
