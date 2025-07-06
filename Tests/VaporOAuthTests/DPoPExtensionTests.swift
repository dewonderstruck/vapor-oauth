import XCTVapor
import JWTKit
@testable import VaporOAuth

final class DPoPExtensionTests: XCTestCase {
    
    func testDPoPExtensionRegistration() throws {
        let app = Application(.testing)
        defer { app.shutdown() }
        
        // Create the DPoP extension
        let dpopExtension = DemonstratingProofOfPossessionExtension()
        
        // Create extension manager and register DPoP extension
        let extensionManager = OAuthExtensionManager()
        extensionManager.register(dpopExtension)
        
        // Verify extension is registered by checking metadata
        let metadata = extensionManager.getAllExtensionMetadata()
        let dpopMetadata = metadata.first { ($0["extension_id"] as? String) == "dpop" }
        
        XCTAssertNotNil(dpopMetadata)
        XCTAssertEqual(dpopMetadata?["extension_name"] as? String, "Demonstrating Proof of Possession")
    }
    
    func testDPoPExtensionMetadata() throws {
        let dpopExtension = DemonstratingProofOfPossessionExtension()
        
        let metadata = dpopExtension.getMetadata()
        
        XCTAssertEqual(metadata["extension_id"] as? String, "dpop")
        XCTAssertEqual(metadata["extension_name"] as? String, "Demonstrating Proof of Possession")
        XCTAssertEqual(metadata["specification_version"] as? String, "RFC 9449")
        XCTAssertEqual(metadata["modifies_authorization_request"] as? Bool, false)
        XCTAssertEqual(metadata["modifies_token_request"] as? Bool, true)
        XCTAssertEqual(metadata["adds_endpoints"] as? Bool, true)
        XCTAssertEqual(metadata["requires_configuration"] as? Bool, false)
        XCTAssertEqual(metadata["dpop_nonce_endpoint"] as? String, "/oauth/dpop_nonce")
    }
    
    func testDPoPExtensionProperties() throws {
        let dpopExtension = DemonstratingProofOfPossessionExtension()
        
        XCTAssertEqual(dpopExtension.extensionID, "dpop")
        XCTAssertEqual(dpopExtension.extensionName, "Demonstrating Proof of Possession")
        XCTAssertEqual(dpopExtension.specificationVersion, "RFC 9449")
        XCTAssertFalse(dpopExtension.modifiesAuthorizationRequest)
        XCTAssertTrue(dpopExtension.modifiesTokenRequest)
        XCTAssertTrue(dpopExtension.addsEndpoints)
        XCTAssertFalse(dpopExtension.requiresConfiguration)
    }
    
    func testDPoPClaimsStructure() throws {
        let jti = "test-jti"
        let iat = IssuedAtClaim(value: Date())
        let exp = ExpirationClaim(value: Date().addingTimeInterval(300))
        let htm = HTTPMethodClaim("POST")
        let htu = HTTPURIClaim("https://example.com/oauth/token")
        let jwk = JWK.rsa(.rs256, identifier: nil, modulus: "test", exponent: "test")
        let cnf = ConfirmationClaim(jwk: jwk)
        
        let claims = DPoPClaims(
            jti: jti,
            iat: iat,
            exp: exp,
            htm: htm,
            htu: htu,
            cnf: cnf
        )
        
        XCTAssertEqual(claims.jti, jti)
        XCTAssertEqual(claims.iat.value, iat.value)
        XCTAssertEqual(claims.exp.value, exp.value)
        XCTAssertEqual(claims.htm.value, "POST")
        XCTAssertEqual(claims.htu.value, "https://example.com/oauth/token")
        XCTAssertEqual(claims.cnf.jwk.keyType, jwk.keyType)
        XCTAssertNil(claims.ath)
        XCTAssertNil(claims.nonce)
    }
    
    func testDPoPNonceResponse() throws {
        let nonce = "test-nonce-123"
        let expiresIn = 300
        
        let response = DPoPNonceResponse(nonce: nonce, expiresIn: expiresIn)
        
        XCTAssertEqual(response.nonce, nonce)
        XCTAssertEqual(response.expiresIn, expiresIn)
    }
    
    func testDPoPValidationResponse() throws {
        let validResponse = DPoPValidationResponse(valid: true)
        XCTAssertTrue(validResponse.valid)
        XCTAssertNil(validResponse.claims)
        XCTAssertNil(validResponse.error)
        
        let invalidResponse = DPoPValidationResponse(valid: false, error: "Invalid token")
        XCTAssertFalse(invalidResponse.valid)
        XCTAssertNil(invalidResponse.claims)
        XCTAssertEqual(invalidResponse.error, "Invalid token")
    }
    
    func testOAuthErrorResponse() throws {
        let errorResponse = OAuthErrorResponse(
            error: "invalid_request",
            errorDescription: "Missing required parameter",
            errorUri: "https://example.com/errors/invalid_request"
        )
        
        XCTAssertEqual(errorResponse.error, "invalid_request")
        XCTAssertEqual(errorResponse.errorDescription, "Missing required parameter")
        XCTAssertEqual(errorResponse.errorUri, "https://example.com/errors/invalid_request")
    }
    
    func testDPoPTokenResponseModification() throws {
        let app = Application(.testing)
        defer { app.shutdown() }
        
        // Create the DPoP extension
        let dpopExtension = DemonstratingProofOfPossessionExtension()
        
        // Create extension manager and register DPoP extension
        let extensionManager = OAuthExtensionManager()
        extensionManager.register(dpopExtension)
        
        // Verify that the extension modifies token responses
        XCTAssertTrue(dpopExtension.modifiesTokenResponse)
        
        // Verify this is reflected in metadata
        let metadata = dpopExtension.getMetadata()
        XCTAssertEqual(metadata["modifies_token_response"] as? Bool, true)
    }
} 