import XCTest
@testable import VaporOAuth

final class OAuthClientTests: XCTestCase {
    
    // MARK: - Origin Validation Tests
    
    func testValidateOrigin_WithNoAuthorizedOrigins_ReturnsTrue() {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            allowedGrantType: .authorization,
            authorizedOrigins: nil
        )
        
        // When & Then
        XCTAssertTrue(client.validateOrigin("https://malicious.com"))
        XCTAssertTrue(client.validateOrigin("http://localhost:3000"))
        XCTAssertTrue(client.validateOrigin("https://example.com"))
    }
    
    func testValidateOrigin_WithEmptyAuthorizedOrigins_ReturnsTrue() {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            allowedGrantType: .authorization,
            authorizedOrigins: []
        )
        
        // When & Then
        XCTAssertTrue(client.validateOrigin("https://malicious.com"))
        XCTAssertTrue(client.validateOrigin("http://localhost:3000"))
    }
    
    func testValidateOrigin_WithExactMatch_ReturnsTrue() {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            allowedGrantType: .authorization,
            authorizedOrigins: ["https://example.com", "http://localhost:3000"]
        )
        
        // When & Then
        XCTAssertTrue(client.validateOrigin("https://example.com"))
        XCTAssertTrue(client.validateOrigin("http://localhost:3000"))
    }
    
    func testValidateOrigin_WithNoMatch_ReturnsFalse() {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            allowedGrantType: .authorization,
            authorizedOrigins: ["https://example.com", "http://localhost:3000"]
        )
        
        // When & Then
        XCTAssertFalse(client.validateOrigin("https://malicious.com"))
        XCTAssertFalse(client.validateOrigin("http://evil.com"))
        XCTAssertFalse(client.validateOrigin("https://example.org"))
    }
    
    func testValidateOrigin_WithWildcardPattern_ReturnsTrue() {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            allowedGrantType: .authorization,
            authorizedOrigins: ["*.example.com"]
        )
        
        // When & Then
        XCTAssertTrue(client.validateOrigin("https://app.example.com"))
        XCTAssertTrue(client.validateOrigin("http://api.example.com"))
        XCTAssertTrue(client.validateOrigin("https://subdomain.example.com:8080"))
    }
    
    func testValidateOrigin_WithWildcardPattern_MatchesRootDomain() {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            allowedGrantType: .authorization,
            authorizedOrigins: ["*.example.com"]
        )
        
        // When & Then
        XCTAssertTrue(client.validateOrigin("https://example.com"))
        XCTAssertTrue(client.validateOrigin("http://example.com"))
    }
    
    func testValidateOrigin_WithWildcardPattern_DoesNotMatchOtherDomains() {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            allowedGrantType: .authorization,
            authorizedOrigins: ["*.example.com"]
        )
        
        // When & Then
        XCTAssertFalse(client.validateOrigin("https://example.org"))
        XCTAssertFalse(client.validateOrigin("https://malicious-example.com"))
        XCTAssertFalse(client.validateOrigin("https://notexample.com"))
    }
    
    func testValidateOrigin_WithMultipleOrigins_ValidatesCorrectly() {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            allowedGrantType: .authorization,
            authorizedOrigins: [
                "https://example.com",
                "*.staging.example.com",
                "http://localhost:3000"
            ]
        )
        
        // When & Then
        // Exact matches
        XCTAssertTrue(client.validateOrigin("https://example.com"))
        XCTAssertTrue(client.validateOrigin("http://localhost:3000"))
        
        // Wildcard matches
        XCTAssertTrue(client.validateOrigin("https://app.staging.example.com"))
        XCTAssertTrue(client.validateOrigin("http://api.staging.example.com"))
        
        // Non-matches
        XCTAssertFalse(client.validateOrigin("https://malicious.com"))
        XCTAssertFalse(client.validateOrigin("https://app.production.example.com"))
    }
    
    func testValidateOrigin_CaseInsensitiveDomains() {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            allowedGrantType: .authorization,
            authorizedOrigins: ["https://Example.COM", "*.STAGING.example.com"]
        )
        
        // When & Then
        XCTAssertTrue(client.validateOrigin("https://example.com"))
        XCTAssertTrue(client.validateOrigin("https://EXAMPLE.COM"))
        XCTAssertTrue(client.validateOrigin("https://app.staging.EXAMPLE.COM"))
        XCTAssertTrue(client.validateOrigin("https://APP.STAGING.example.com"))
    }
    
    func testValidateOrigin_WithPortNumbers() {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            allowedGrantType: .authorization,
            authorizedOrigins: ["https://example.com:8080", "*.example.com"]
        )
        
        // When & Then
        XCTAssertTrue(client.validateOrigin("https://example.com:8080"))
        XCTAssertTrue(client.validateOrigin("https://app.example.com:3000"))
        XCTAssertFalse(client.validateOrigin("https://example.com:9000"))
    }
    
    // MARK: - Backward Compatibility Tests
    
    func testInitializer_WithoutAuthorizedOrigins_DefaultsToNil() {
        // Given & When
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            allowedGrantType: .authorization
        )
        
        // Then
        XCTAssertNil(client.authorizedOrigins)
        XCTAssertTrue(client.validateOrigin("https://any-origin.com"))
    }
    
    func testInitializer_WithAuthorizedOrigins_StoresCorrectly() {
        // Given
        let origins = ["https://example.com", "*.staging.example.com"]
        
        // When
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            allowedGrantType: .authorization,
            authorizedOrigins: origins
        )
        
        // Then
        XCTAssertEqual(client.authorizedOrigins, origins)
    }
    
    // MARK: - Edge Cases
    
    func testValidateOrigin_WithEmptyOrigin_ReturnsFalse() {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            allowedGrantType: .authorization,
            authorizedOrigins: ["https://example.com"]
        )
        
        // When & Then
        XCTAssertFalse(client.validateOrigin(""))
    }
    
    func testValidateOrigin_WithMalformedOrigin_HandlesSafely() {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            allowedGrantType: .authorization,
            authorizedOrigins: ["https://example.com"]
        )
        
        // When & Then
        XCTAssertFalse(client.validateOrigin("not-a-url"))
        XCTAssertFalse(client.validateOrigin("://malformed"))
    }
    
    func testValidateOrigin_WithNonWildcardPattern_DoesNotMatch() {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            allowedGrantType: .authorization,
            authorizedOrigins: ["example.com"] // No wildcard
        )
        
        // When & Then
        XCTAssertTrue(client.validateOrigin("example.com"))
        XCTAssertFalse(client.validateOrigin("https://app.example.com"))
    }
    
    // MARK: - Origin Configuration Validation Tests
    
    func testCreateWithValidatedOrigins_WithValidOrigins_CreatesClient() throws {
        // Given
        let validOrigins = [
            "https://example.com",
            "*.staging.example.com",
            "http://localhost:3000"
        ]
        
        // When
        let client = try OAuthClient.createWithValidatedOrigins(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            allowedGrantType: .authorization,
            authorizedOrigins: validOrigins
        )
        
        // Then
        XCTAssertEqual(client.clientID, "test-client")
        XCTAssertEqual(client.authorizedOrigins, validOrigins)
    }
    
    func testCreateWithValidatedOrigins_WithNilOrigins_CreatesClient() throws {
        // Given & When
        let client = try OAuthClient.createWithValidatedOrigins(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            allowedGrantType: .authorization,
            authorizedOrigins: nil
        )
        
        // Then
        XCTAssertEqual(client.clientID, "test-client")
        XCTAssertNil(client.authorizedOrigins)
    }
    
    func testCreateWithValidatedOrigins_WithEmptyOrigins_CreatesClient() throws {
        // Given & When
        let client = try OAuthClient.createWithValidatedOrigins(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            allowedGrantType: .authorization,
            authorizedOrigins: []
        )
        
        // Then
        XCTAssertEqual(client.clientID, "test-client")
        XCTAssertEqual(client.authorizedOrigins, [])
    }
    
    func testCreateWithValidatedOrigins_WithOverlyBroadPattern_ThrowsError() {
        // Given
        let overlyBroadOrigins = ["*.com", "https://example.com"]
        
        // When & Then
        XCTAssertThrowsError(
            try OAuthClient.createWithValidatedOrigins(
                clientID: "test-client",
                redirectURIs: ["https://example.com/callback"],
                allowedGrantType: .authorization,
                authorizedOrigins: overlyBroadOrigins
            )
        ) { error in
            XCTAssertTrue(error is OriginValidationError)
            if case OriginValidationError.overlyBroadPattern = error {
                // Expected error type
            } else {
                XCTFail("Expected overlyBroadPattern error")
            }
        }
    }
    
    func testCreateWithValidatedOrigins_WithMalformedOrigin_ThrowsError() {
        // Given
        let malformedOrigins = ["https://example.com", "not-a-valid-origin"]
        
        // When & Then
        XCTAssertThrowsError(
            try OAuthClient.createWithValidatedOrigins(
                clientID: "test-client",
                redirectURIs: ["https://example.com/callback"],
                allowedGrantType: .authorization,
                authorizedOrigins: malformedOrigins
            )
        ) { error in
            XCTAssertTrue(error is OriginValidationError)
            if case OriginValidationError.invalidOriginFormat = error {
                // Expected error type
            } else {
                XCTFail("Expected invalidOriginFormat error")
            }
        }
    }
    
    func testCreateWithValidatedOrigins_WithHTTPSRequired_ValidatesCorrectly() throws {
        // Given
        let httpsOrigins = ["https://example.com", "*.example.com", "http://localhost:3000"]
        let httpOrigins = ["http://example.com", "https://secure.com"]
        
        // When & Then - HTTPS origins should work
        XCTAssertNoThrow(
            try OAuthClient.createWithValidatedOrigins(
                clientID: "test-client",
                redirectURIs: ["https://example.com/callback"],
                allowedGrantType: .authorization,
                authorizedOrigins: httpsOrigins,
                requireHTTPS: true
            )
        )
        
        // HTTP origins should fail when HTTPS is required
        XCTAssertThrowsError(
            try OAuthClient.createWithValidatedOrigins(
                clientID: "test-client",
                redirectURIs: ["https://example.com/callback"],
                allowedGrantType: .authorization,
                authorizedOrigins: httpOrigins,
                requireHTTPS: true
            )
        ) { error in
            XCTAssertTrue(error is OriginValidationError)
            if case OriginValidationError.insecureOrigin = error {
                // Expected error type
            } else {
                XCTFail("Expected insecureOrigin error")
            }
        }
    }
    
    func testCreateWithValidatedOrigins_WithAllParameters_CreatesClientCorrectly() throws {
        // Given
        let origins = ["https://example.com", "*.staging.example.com"]
        
        // When
        let client = try OAuthClient.createWithValidatedOrigins(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            clientSecret: "secret",
            validScopes: ["read", "write"],
            confidential: true,
            firstParty: true,
            allowedGrantType: .authorization,
            authorizedOrigins: origins,
            requireHTTPS: false
        )
        
        // Then
        XCTAssertEqual(client.clientID, "test-client")
        XCTAssertEqual(client.redirectURIs, ["https://example.com/callback"])
        XCTAssertEqual(client.clientSecret, "secret")
        XCTAssertEqual(client.validScopes, ["read", "write"])
        XCTAssertEqual(client.confidentialClient, true)
        XCTAssertEqual(client.firstParty, true)
        XCTAssertEqual(client.allowedGrantType, .authorization)
        XCTAssertEqual(client.authorizedOrigins, origins)
    }
    
    func testCreateWithValidatedOrigins_WithDangerousPatterns_ThrowsError() {
        // Given
        let dangerousPatterns = [
            "*.localhost",
            "*.127.0.0.1", 
            "*.0.0.0.0"
        ]
        
        // When & Then
        for pattern in dangerousPatterns {
            XCTAssertThrowsError(
                try OAuthClient.createWithValidatedOrigins(
                    clientID: "test-client",
                    redirectURIs: ["https://example.com/callback"],
                    allowedGrantType: .authorization,
                    authorizedOrigins: [pattern]
                )
            ) { error in
                XCTAssertTrue(error is OriginValidationError)
                if case OriginValidationError.overlyBroadPattern = error {
                    // Expected error type
                } else {
                    XCTFail("Expected overlyBroadPattern error for dangerous pattern: \(pattern)")
                }
            }
        }
    }
    
    func testCreateWithValidatedOrigins_WithSuspiciousCharacters_ThrowsError() {
        // Given - origins that remain invalid after trimming whitespace
        let suspiciousOrigins = [
            "https://example.com<script>",
            "https://example.com\"",
            "https://example.com'",
            "https://example.com`",
            "https://example.com\\",
            "https://example.com\u{0001}" // Control character that won't be trimmed
        ]
        
        // When & Then
        for origin in suspiciousOrigins {
            XCTAssertThrowsError(
                try OAuthClient.createWithValidatedOrigins(
                    clientID: "test-client",
                    redirectURIs: ["https://example.com/callback"],
                    allowedGrantType: .authorization,
                    authorizedOrigins: [origin]
                )
            ) { error in
                XCTAssertTrue(error is OriginValidationError)
                if case OriginValidationError.invalidOriginFormat = error {
                    // Expected error type
                } else {
                    XCTFail("Expected invalidOriginFormat error for suspicious origin: \(origin)")
                }
            }
        }
    }
}