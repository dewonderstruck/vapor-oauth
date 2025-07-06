import JWTKit
import XCTVapor

@testable import VaporOAuth

class JWTAccessTokenTests: XCTestCase {

    // MARK: - JWT Access Token Creation Tests

    func testJWTAccessTokenCreation() async throws {
        let issuer = "test-issuer"
        let subject = "test-user"
        let audience = "test-client"
        let expiryTime = Date().addingTimeInterval(3600)
        let scope = "read write"
        let clientID = "test-client"

        let accessToken = JWTAccessToken(
            issuer: issuer,
            subject: subject,
            audience: audience,
            expirationTime: expiryTime,
            scope: scope,
            clientID: clientID
        )

        XCTAssertEqual(accessToken.iss.value, "test-issuer")
        XCTAssertEqual(accessToken.sub.value, "test-user")
        XCTAssertEqual(accessToken.aud.value, [audience])
        XCTAssertEqual(accessToken.exp.value, expiryTime)
        XCTAssertEqual(accessToken.scope, "read write")
        XCTAssertEqual(accessToken.clientID, "test-client")
        XCTAssertEqual(accessToken.tokenType, "Bearer")
    }

    func testJWTAccessTokenSigningAndVerification() async throws {
        let issuer = "test-issuer"
        let subject = "test-user"
        let audience = "test-client"
        let expiryTime = Date().addingTimeInterval(3600)
        let scope = "read write"
        let clientID = "test-client"

        let jwtToken = JWTAccessToken(
            issuer: issuer,
            subject: subject,
            audience: audience,
            expirationTime: expiryTime,
            scope: scope,
            clientID: clientID
        )

        XCTAssertEqual(jwtToken.iss.value, "test-issuer")
        XCTAssertEqual(jwtToken.sub.value, "test-user")
        XCTAssertEqual(jwtToken.aud.value, [audience])
        XCTAssertEqual(jwtToken.scope, "read write")
        XCTAssertEqual(jwtToken.clientID, "test-client")

        // Test signing and verification with HMAC
        let keyCollection = JWTKeyCollection()
        let keyID = JWKIdentifier(string: UUID().uuidString)
        await keyCollection.add(hmac: HMACKey(from: "test-secret"), digestAlgorithm: .sha256, kid: keyID)

        let signedToken = try await keyCollection.sign(jwtToken)
        XCTAssertNotNil(signedToken)

        // Test verification
        let verifiedToken = try await keyCollection.verify(signedToken, as: JWTAccessToken.self)
        XCTAssertEqual(verifiedToken.iss.value, issuer)
        XCTAssertEqual(verifiedToken.sub.value, subject)
        XCTAssertEqual(verifiedToken.aud.value, [audience])
        XCTAssertEqual(verifiedToken.scope, scope)
        XCTAssertEqual(verifiedToken.clientID, clientID)
    }

    func testJWTAccessTokenExpiration() async throws {
        let issuer = "test-issuer"
        let subject = "test-user"
        let audience = "test-client"
        let expiryTime = Date().addingTimeInterval(-3600)  // Expired 1 hour ago
        let scope = "read write"
        let clientID = "test-client"

        let accessToken = JWTAccessToken(
            issuer: issuer,
            subject: subject,
            audience: audience,
            expirationTime: expiryTime,
            scope: scope,
            clientID: clientID
        )

        // Test verification with expired token
        let keyCollection = JWTKeyCollection()
        let keyID = JWKIdentifier(string: UUID().uuidString)
        await keyCollection.add(hmac: HMACKey(from: "test-secret"), digestAlgorithm: .sha256, kid: keyID)

        let signedToken = try await keyCollection.sign(accessToken)

        do {
            _ = try await keyCollection.verify(signedToken, as: JWTAccessToken.self)
            XCTFail("Should have thrown an error for expired token")
        } catch {
            // Expected error for expired token
            XCTAssertTrue(error is JWTError)
        }
    }

    func testJWTAccessTokenFutureIssuedAt() async throws {
        let issuer = "test-issuer"
        let subject = "test-user"
        let audience = "test-client"
        let expiryTime = Date().addingTimeInterval(3600)
        let issuedAtTime = Date().addingTimeInterval(3600)  // Future issued at time
        let scope = "read write"
        let clientID = "test-client"

        let accessToken = JWTAccessToken(
            issuer: issuer,
            subject: subject,
            audience: audience,
            expirationTime: expiryTime,
            issuedAt: issuedAtTime,
            scope: scope,
            clientID: clientID
        )

        // Test verification with future issued at time
        let keyCollection = JWTKeyCollection()
        let keyID = JWKIdentifier(string: UUID().uuidString)
        await keyCollection.add(hmac: HMACKey(from: "test-secret"), digestAlgorithm: .sha256, kid: keyID)

        let signedToken = try await keyCollection.sign(accessToken)

        do {
            _ = try await keyCollection.verify(signedToken, as: JWTAccessToken.self)
            XCTFail("Should have thrown an error for future issued at time")
        } catch {
            // Expected error for future issued at time
            XCTAssertTrue(error is JWTError)
        }
    }

    // MARK: - RFC 9068 Compliance Tests

    func testRFC9068RequiredClaims() {
        let expiryTime = Date().addingTimeInterval(3600)
        let accessToken = JWTAccessToken(
            issuer: "test-issuer",
            subject: "test-user",
            audience: "test-client",
            expirationTime: expiryTime,
            scope: "read write",
            clientID: "test-client"
        )

        // RFC 9068 requires: iss, sub, aud, exp, iat
        XCTAssertNotNil(accessToken.iss)
        XCTAssertNotNil(accessToken.sub)
        XCTAssertNotNil(accessToken.aud)
        XCTAssertNotNil(accessToken.exp)
        XCTAssertNotNil(accessToken.iat)
        XCTAssertNotNil(accessToken.jti)
    }

    func testRFC9068OptionalClaims() {
        let expiryTime = Date().addingTimeInterval(3600)
        let accessToken = JWTAccessToken(
            issuer: "test-issuer",
            subject: "test-user",
            audience: "test-client",
            expirationTime: expiryTime,
            scope: "read write",
            clientID: "test-client",
            tokenType: "Bearer"
        )

        // RFC 9068 optional claims: scope, client_id, token_type
        XCTAssertEqual(accessToken.scope, "read write")
        XCTAssertEqual(accessToken.clientID, "test-client")
        XCTAssertEqual(accessToken.tokenType, "Bearer")
    }

    func testJWTAccessTokenWithNilUserID() {
        let expiryTime = Date().addingTimeInterval(3600)
        let accessToken = JWTAccessToken(
            issuer: "test-issuer",
            subject: "",  // Empty subject for client credentials flow
            audience: "test-client",
            expirationTime: expiryTime,
            scope: "read write",
            clientID: "test-client"
        )

        XCTAssertEqual(accessToken.userID, "")
        XCTAssertEqual(accessToken.sub.value, "")
    }
}
