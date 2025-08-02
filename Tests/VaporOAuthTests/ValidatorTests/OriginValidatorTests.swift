import XCTest
import Vapor
@testable import VaporOAuth

final class OriginValidatorTests: XCTestCase {
    
    var validator: OriginValidator!
    
    override func setUp() {
        super.setUp()
        validator = OriginValidator()
    }
    
    override func tearDown() {
        validator = nil
        super.tearDown()
    }
    
    // MARK: - validateOrigin(_:against:) Tests
    
    func testValidateOrigin_WithEmptyAuthorizedOrigins_ReturnsTrue() {
        // Given
        let origin = "https://malicious.com"
        let authorizedOrigins: [String] = []
        
        // When
        let result = validator.validateOrigin(origin, against: authorizedOrigins)
        
        // Then
        XCTAssertTrue(result, "Empty authorized origins should allow any origin for backward compatibility")
    }
    
    func testValidateOrigin_WithExactMatch_ReturnsTrue() {
        // Given
        let origin = "https://example.com"
        let authorizedOrigins = ["https://example.com", "http://localhost:3000"]
        
        // When
        let result = validator.validateOrigin(origin, against: authorizedOrigins)
        
        // Then
        XCTAssertTrue(result, "Exact match should be allowed")
    }
    
    func testValidateOrigin_WithExactMatchCaseInsensitive_ReturnsTrue() {
        // Given
        let origin = "https://EXAMPLE.COM"
        let authorizedOrigins = ["https://example.com"]
        
        // When
        let result = validator.validateOrigin(origin, against: authorizedOrigins)
        
        // Then
        XCTAssertTrue(result, "Case insensitive domain matching should work")
    }
    
    func testValidateOrigin_WithExactMatchDifferentPort_ReturnsFalse() {
        // Given
        let origin = "https://example.com:8080"
        let authorizedOrigins = ["https://example.com:3000"]
        
        // When
        let result = validator.validateOrigin(origin, against: authorizedOrigins)
        
        // Then
        XCTAssertFalse(result, "Different ports should not match")
    }
    
    func testValidateOrigin_WithNoMatch_ReturnsFalse() {
        // Given
        let origin = "https://malicious.com"
        let authorizedOrigins = ["https://example.com", "http://localhost:3000"]
        
        // When
        let result = validator.validateOrigin(origin, against: authorizedOrigins)
        
        // Then
        XCTAssertFalse(result, "Non-matching origin should be rejected")
    }
    
    func testValidateOrigin_WithWildcardPattern_ReturnsTrue() {
        // Given
        let origin = "https://app.example.com"
        let authorizedOrigins = ["*.example.com"]
        
        // When
        let result = validator.validateOrigin(origin, against: authorizedOrigins)
        
        // Then
        XCTAssertTrue(result, "Wildcard pattern should match subdomain")
    }
    
    func testValidateOrigin_WithWildcardPatternRootDomain_ReturnsTrue() {
        // Given
        let origin = "https://example.com"
        let authorizedOrigins = ["*.example.com"]
        
        // When
        let result = validator.validateOrigin(origin, against: authorizedOrigins)
        
        // Then
        XCTAssertTrue(result, "Wildcard pattern should match root domain")
    }
    
    func testValidateOrigin_WithWildcardPatternDifferentDomain_ReturnsFalse() {
        // Given
        let origin = "https://app.different.com"
        let authorizedOrigins = ["*.example.com"]
        
        // When
        let result = validator.validateOrigin(origin, against: authorizedOrigins)
        
        // Then
        XCTAssertFalse(result, "Wildcard pattern should not match different domain")
    }
    
    func testValidateOrigin_WithOverlyBroadPattern_ContinuesValidation() {
        // Given
        let origin = "https://example.com"
        let authorizedOrigins = ["*.com", "https://example.com"] // *.com is overly broad but exact match should work
        
        // When
        let result = validator.validateOrigin(origin, against: authorizedOrigins)
        
        // Then
        XCTAssertTrue(result, "Should continue validation even with overly broad patterns")
    }
    
    func testValidateOrigin_WithMultiplePatterns_ValidatesCorrectly() {
        // Given
        let authorizedOrigins = [
            "https://example.com",
            "*.staging.example.com",
            "http://localhost:3000"
        ]
        
        // When & Then
        XCTAssertTrue(validator.validateOrigin("https://example.com", against: authorizedOrigins))
        XCTAssertTrue(validator.validateOrigin("https://app.staging.example.com", against: authorizedOrigins))
        XCTAssertTrue(validator.validateOrigin("http://localhost:3000", against: authorizedOrigins))
        XCTAssertFalse(validator.validateOrigin("https://malicious.com", against: authorizedOrigins))
    }
    
    // MARK: - matchesPattern(_:pattern:) Tests
    
    func testMatchesPattern_WithExactMatch_ReturnsTrue() {
        // Given
        let origin = "https://example.com"
        let pattern = "https://example.com"
        
        // When
        let result = validator.matchesPattern(origin, pattern: pattern)
        
        // Then
        XCTAssertTrue(result, "Exact match should return true")
    }
    
    func testMatchesPattern_WithWildcardSubdomain_ReturnsTrue() {
        // Given
        let origin = "https://app.example.com"
        let pattern = "*.example.com"
        
        // When
        let result = validator.matchesPattern(origin, pattern: pattern)
        
        // Then
        XCTAssertTrue(result, "Wildcard should match subdomain")
    }
    
    func testMatchesPattern_WithWildcardRootDomain_ReturnsTrue() {
        // Given
        let origin = "https://example.com"
        let pattern = "*.example.com"
        
        // When
        let result = validator.matchesPattern(origin, pattern: pattern)
        
        // Then
        XCTAssertTrue(result, "Wildcard should match root domain")
    }
    
    func testMatchesPattern_WithInvalidWildcardPosition_ReturnsFalse() {
        // Given
        let origin = "https://example.com"
        let pattern = "example.*.com"
        
        // When
        let result = validator.matchesPattern(origin, pattern: pattern)
        
        // Then
        XCTAssertFalse(result, "Wildcard in middle should not be supported")
    }
    
    func testMatchesPattern_WithOverlyBroadPattern_ReturnsFalse() {
        // Given
        let origin = "https://example.com"
        let pattern = "*.com"
        
        // When
        let result = validator.matchesPattern(origin, pattern: pattern)
        
        // Then
        XCTAssertFalse(result, "Overly broad pattern should be rejected")
    }
    
    func testMatchesPattern_WithCaseInsensitive_ReturnsTrue() {
        // Given
        let origin = "https://APP.EXAMPLE.COM"
        let pattern = "*.example.com"
        
        // When
        let result = validator.matchesPattern(origin, pattern: pattern)
        
        // Then
        XCTAssertTrue(result, "Pattern matching should be case insensitive")
    }
    
    func testMatchesPattern_WithDifferentProtocols_ReturnsTrue() {
        // Given
        let httpOrigin = "http://app.example.com"
        let httpsOrigin = "https://app.example.com"
        let pattern = "*.example.com"
        
        // When & Then
        XCTAssertTrue(validator.matchesPattern(httpOrigin, pattern: pattern))
        XCTAssertTrue(validator.matchesPattern(httpsOrigin, pattern: pattern))
    }
    
    func testMatchesPattern_WithPorts_ReturnsTrue() {
        // Given
        let origin = "https://app.example.com:8080"
        let pattern = "*.example.com"
        
        // When
        let result = validator.matchesPattern(origin, pattern: pattern)
        
        // Then
        XCTAssertTrue(result, "Wildcard should match regardless of port")
    }
    
    // MARK: - extractOrigin(from:) Tests
    
    func testExtractOrigin_WithValidOriginHeader_ReturnsOrigin() throws {
        // Given
        let app = Application(.testing)
        defer { app.shutdown() }
        
        let request = Request(application: app, method: .GET, url: "/test", on: app.eventLoopGroup.next())
        request.headers.add(name: .origin, value: "https://example.com")
        
        // When
        let result = validator.extractOrigin(from: request)
        
        // Then
        XCTAssertEqual(result, "https://example.com")
    }
    
    func testExtractOrigin_WithMissingOriginHeader_ReturnsNil() throws {
        // Given
        let app = Application(.testing)
        defer { app.shutdown() }
        
        let request = Request(application: app, method: .GET, url: "/test", on: app.eventLoopGroup.next())
        
        // When
        let result = validator.extractOrigin(from: request)
        
        // Then
        XCTAssertNil(result, "Missing origin header should return nil")
    }
    
    func testExtractOrigin_WithEmptyOriginHeader_ReturnsNil() throws {
        // Given
        let app = Application(.testing)
        defer { app.shutdown() }
        
        let request = Request(application: app, method: .GET, url: "/test", on: app.eventLoopGroup.next())
        request.headers.add(name: .origin, value: "")
        
        // When
        let result = validator.extractOrigin(from: request)
        
        // Then
        XCTAssertNil(result, "Empty origin header should return nil")
    }
    
    func testExtractOrigin_WithWhitespaceOnlyOriginHeader_ReturnsNil() throws {
        // Given
        let app = Application(.testing)
        defer { app.shutdown() }
        
        let request = Request(application: app, method: .GET, url: "/test", on: app.eventLoopGroup.next())
        request.headers.add(name: .origin, value: "   \t\n  ")
        
        // When
        let result = validator.extractOrigin(from: request)
        
        // Then
        XCTAssertNil(result, "Whitespace-only origin header should return nil")
    }
    
    func testExtractOrigin_WithValidOriginWithWhitespace_ReturnsTrimmedOrigin() throws {
        // Given
        let app = Application(.testing)
        defer { app.shutdown() }
        
        let request = Request(application: app, method: .GET, url: "/test", on: app.eventLoopGroup.next())
        request.headers.add(name: .origin, value: "  https://example.com  ")
        
        // When
        let result = validator.extractOrigin(from: request)
        
        // Then
        XCTAssertEqual(result, "https://example.com")
    }
    
    func testExtractOrigin_WithInvalidOriginFormat_ReturnsNil() throws {
        // Given
        let app = Application(.testing)
        defer { app.shutdown() }
        
        let request = Request(application: app, method: .GET, url: "/test", on: app.eventLoopGroup.next())
        request.headers.add(name: .origin, value: "not-a-valid-origin")
        
        // When
        let result = validator.extractOrigin(from: request)
        
        // Then
        XCTAssertNil(result, "Invalid origin format should return nil")
    }
    
    func testExtractOrigin_WithValidDomainOnly_ReturnsOrigin() throws {
        // Given
        let app = Application(.testing)
        defer { app.shutdown() }
        
        let request = Request(application: app, method: .GET, url: "/test", on: app.eventLoopGroup.next())
        request.headers.add(name: .origin, value: "example.com")
        
        // When
        let result = validator.extractOrigin(from: request)
        
        // Then
        XCTAssertEqual(result, "example.com")
    }
    
    func testExtractOrigin_WithLocalhost_ReturnsOrigin() throws {
        // Given
        let app = Application(.testing)
        defer { app.shutdown() }
        
        let request = Request(application: app, method: .GET, url: "/test", on: app.eventLoopGroup.next())
        request.headers.add(name: .origin, value: "localhost")
        
        // When
        let result = validator.extractOrigin(from: request)
        
        // Then
        XCTAssertEqual(result, "localhost")
    }
    
    // MARK: - Edge Cases and Security Tests
    
    func testValidateOrigin_WithMaliciousPatterns_HandlesSecurely() {
        // Given
        let maliciousOrigins = [
            "*.com",
            "*.org",
            "*.net",
            "*.",
            "*",
            "*.co"
        ]
        
        // When & Then
        for pattern in maliciousOrigins {
            let result = validator.validateOrigin("https://example.com", against: [pattern])
            XCTAssertFalse(result, "Malicious pattern \(pattern) should be rejected")
        }
    }
    
    func testValidateOrigin_WithValidWildcardPatterns_Works() {
        // Given
        let validPatterns = [
            "*.example.com",
            "*.staging.example.com",
            "*.api.example.com"
        ]
        
        // When & Then
        for pattern in validPatterns {
            let result = validator.validateOrigin("https://app.example.com", against: [pattern])
            // Only the first pattern should match
            if pattern == "*.example.com" {
                XCTAssertTrue(result, "Valid pattern \(pattern) should work")
            }
        }
    }
    
    func testValidateOrigin_WithComplexScenarios_ValidatesCorrectly() {
        // Given
        let authorizedOrigins = [
            "https://example.com",
            "*.staging.example.com",
            "http://localhost:3000",
            "https://app.production.com:8080"
        ]
        
        let testCases: [(String, Bool)] = [
            ("https://example.com", true),
            ("https://EXAMPLE.COM", true),
            ("https://app.staging.example.com", true),
            ("http://api.staging.example.com", true),
            ("https://staging.example.com", true),
            ("http://localhost:3000", true),
            ("https://app.production.com:8080", true),
            ("https://malicious.com", false),
            ("https://app.production.com:9000", false),
            ("https://app.example.com", false), // Not in staging subdomain
            ("http://localhost:8080", false), // Wrong port
            ("https://example.org", false)
        ]
        
        // When & Then
        for (origin, expected) in testCases {
            let result = validator.validateOrigin(origin, against: authorizedOrigins)
            XCTAssertEqual(result, expected, "Origin \(origin) should return \(expected)")
        }
    }
    
    func testMatchesPattern_WithEdgeCases_HandlesCorrectly() {
        let testCases: [(String, String, Bool)] = [
            ("https://example.com", "*.example.com", true),
            ("https://app.example.com", "*.example.com", true),
            ("https://deep.sub.example.com", "*.example.com", true),
            ("https://example.com.evil.com", "*.example.com", false),
            ("https://notexample.com", "*.example.com", false),
            ("https://example.com", "example.com", true), // Domain-only pattern should match with protocol
            ("https://app.example.com", "example.com", false),
            ("", "*.example.com", false),
            ("https://example.com", "", false)
        ]
        
        for (origin, pattern, expected) in testCases {
            let result = validator.matchesPattern(origin, pattern: pattern)
            XCTAssertEqual(result, expected, "Pattern \(pattern) with origin \(origin) should return \(expected)")
        }
    }
    
    // MARK: - Origin Configuration Validation Tests
    
    func testValidateOriginConfiguration_WithNilOrigins_DoesNotThrow() {
        // Given
        let origins: [String]? = nil
        
        // When & Then
        XCTAssertNoThrow(try validator.validateOriginConfiguration(origins))
    }
    
    func testValidateOriginConfiguration_WithEmptyOrigins_DoesNotThrow() {
        // Given
        let origins: [String] = []
        
        // When & Then
        XCTAssertNoThrow(try validator.validateOriginConfiguration(origins))
    }
    
    func testValidateOriginConfiguration_WithValidOrigins_DoesNotThrow() {
        // Given
        let origins = [
            "https://example.com",
            "*.staging.example.com",
            "http://localhost:3000"
        ]
        
        // When & Then
        XCTAssertNoThrow(try validator.validateOriginConfiguration(origins))
    }
    
    func testValidateOriginConfiguration_WithOverlyBroadWildcard_ThrowsError() {
        // Given
        let overlyBroadPatterns = [
            "*.com",
            "*.org", 
            "*.net",
            "*.co",
            "*.localhost"
        ]
        
        // When & Then
        for pattern in overlyBroadPatterns {
            XCTAssertThrowsError(try validator.validateOriginConfiguration([pattern])) { error in
                XCTAssertTrue(error is OriginValidationError)
                if case OriginValidationError.overlyBroadPattern = error {
                    // Expected error type
                } else {
                    XCTFail("Expected overlyBroadPattern error for pattern: \(pattern)")
                }
            }
        }
    }
    
    func testValidateOriginConfiguration_WithMalformedOrigins_ThrowsError() {
        // Given
        let malformedOrigins = [
            "",
            "   ",
            "https://",
            "://example.com",
            "https://example..com",
            "ftp://example.com",
            "javascript://example.com"
        ]
        
        // When & Then
        for origin in malformedOrigins {
            XCTAssertThrowsError(try validator.validateOriginConfiguration([origin])) { error in
                XCTAssertTrue(error is OriginValidationError)
                if case OriginValidationError.invalidOriginFormat = error {
                    // Expected error type
                } else {
                    XCTFail("Expected invalidOriginFormat error for origin: \(origin)")
                }
            }
        }
    }
    
    func testValidateOriginConfiguration_WithSuspiciousCharacters_ThrowsError() {
        // Given - origins that remain invalid after trimming whitespace
        let suspiciousOrigins = [
            "https://example.com<script>",
            "https://example.com\"",
            "https://example.com'",
            "https://example.com`",
            "https://example.com\\",
            "https://example.com\u{0001}", // Control character that won't be trimmed
            "https://example.com\u{0002}"  // Another control character
        ]
        
        // When & Then
        for origin in suspiciousOrigins {
            XCTAssertThrowsError(try validator.validateOriginConfiguration([origin])) { error in
                XCTAssertTrue(error is OriginValidationError)
                if case OriginValidationError.invalidOriginFormat = error {
                    // Expected error type
                } else {
                    XCTFail("Expected invalidOriginFormat error for suspicious origin: \(origin)")
                }
            }
        }
    }
    
    func testValidateOriginConfiguration_WithHTTPSRequired_ValidatesCorrectly() {
        // Given
        let validHTTPSOrigins = [
            "https://example.com",
            "*.example.com", // No protocol, assumed HTTPS capable
            "http://localhost:3000", // Localhost exception
            "http://127.0.0.1:8080" // Localhost exception
        ]
        
        let invalidHTTPOrigins = [
            "http://example.com",
            "http://production.example.com"
        ]
        
        // When & Then - Valid HTTPS origins should not throw
        XCTAssertNoThrow(try validator.validateOriginConfiguration(validHTTPSOrigins, requireHTTPS: true))
        
        // Invalid HTTP origins should throw
        for origin in invalidHTTPOrigins {
            XCTAssertThrowsError(try validator.validateOriginConfiguration([origin], requireHTTPS: true)) { error in
                XCTAssertTrue(error is OriginValidationError)
                if case OriginValidationError.insecureOrigin = error {
                    // Expected error type
                } else {
                    XCTFail("Expected insecureOrigin error for origin: \(origin)")
                }
            }
        }
    }
    
    func testValidateOriginConfiguration_WithMultipleWildcards_ThrowsError() {
        // Given
        let multipleWildcardPatterns = [
            "*.*.example.com",
            "*.*",
            "*.example.*.com"
        ]
        
        // When & Then
        for pattern in multipleWildcardPatterns {
            XCTAssertThrowsError(try validator.validateOriginConfiguration([pattern])) { error in
                XCTAssertTrue(error is OriginValidationError)
                if case OriginValidationError.overlyBroadPattern = error {
                    // Expected error type
                } else {
                    XCTFail("Expected overlyBroadPattern error for pattern: \(pattern)")
                }
            }
        }
    }
    
    func testValidateOriginConfiguration_WithDangerousPatterns_ThrowsError() {
        // Given
        let dangerousPatterns = [
            "*.localhost",
            "*.127.0.0.1",
            "*.0.0.0.0",
            "*.::1"
        ]
        
        // When & Then
        for pattern in dangerousPatterns {
            XCTAssertThrowsError(try validator.validateOriginConfiguration([pattern])) { error in
                XCTAssertTrue(error is OriginValidationError)
                if case OriginValidationError.overlyBroadPattern = error {
                    // Expected error type
                } else {
                    XCTFail("Expected overlyBroadPattern error for dangerous pattern: \(pattern)")
                }
            }
        }
    }
    
    func testValidateOriginConfiguration_WithExtremelyLongOrigin_ThrowsError() {
        // Given
        let longOrigin = "https://" + String(repeating: "a", count: 2050) + ".com"
        
        // When & Then
        XCTAssertThrowsError(try validator.validateOriginConfiguration([longOrigin])) { error in
            XCTAssertTrue(error is OriginValidationError)
            if case OriginValidationError.invalidOriginFormat = error {
                // Expected error type
            } else {
                XCTFail("Expected invalidOriginFormat error for extremely long origin")
            }
        }
    }
    
    func testValidateOriginConfiguration_WithMultipleProtocols_ThrowsError() {
        // Given
        let multipleProtocolOrigins = [
            "https://http://example.com",
            "http://https://example.com"
        ]
        
        // When & Then
        for origin in multipleProtocolOrigins {
            XCTAssertThrowsError(try validator.validateOriginConfiguration([origin])) { error in
                XCTAssertTrue(error is OriginValidationError)
                if case OriginValidationError.invalidOriginFormat = error {
                    // Expected error type
                } else {
                    XCTFail("Expected invalidOriginFormat error for multiple protocol origin: \(origin)")
                }
            }
        }
    }
    
    func testValidateOriginConfiguration_WithValidComplexScenarios_DoesNotThrow() {
        // Given
        let complexValidOrigins = [
            "https://app.example.com",
            "https://api.example.com:8080",
            "*.staging.example.com",
            "*.dev.example.com",
            "http://localhost:3000",
            "https://127.0.0.1:8080",
            "example.com", // Domain only
            "subdomain.example.org"
        ]
        
        // When & Then
        XCTAssertNoThrow(try validator.validateOriginConfiguration(complexValidOrigins))
        XCTAssertNoThrow(try validator.validateOriginConfiguration(complexValidOrigins, requireHTTPS: false))
    }
    
    func testValidateOriginConfiguration_WithEmptyWildcardComponents_ThrowsError() {
        // Given
        let emptyComponentPatterns = [
            "*.example..com",
            "*..example.com",
            "*.example.com.",
            "*."
        ]
        
        // When & Then
        for pattern in emptyComponentPatterns {
            XCTAssertThrowsError(try validator.validateOriginConfiguration([pattern])) { error in
                XCTAssertTrue(error is OriginValidationError)
                // Should throw either overlyBroadPattern or invalidOriginFormat
                XCTAssertTrue(
                    error is OriginValidationError,
                    "Expected OriginValidationError for pattern with empty components: \(pattern)"
                )
            }
        }
    }
}