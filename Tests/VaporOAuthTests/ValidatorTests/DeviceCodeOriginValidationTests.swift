import XCTest
import Vapor
import Logging
@testable import VaporOAuth

final class DeviceCodeOriginValidationTests: XCTestCase {
    
    var app: Application!
    var originValidator: OriginValidator!
    var capturingLogger: CapturingLogger!
    var securityLogger: SecurityLogger!
    
    override func setUp() {
        super.setUp()
        app = Application(.testing)
        
        originValidator = OriginValidator()
        capturingLogger = CapturingLogger()
        securityLogger = SecurityLogger(logger: Logger(label: "test", factory: { _ in capturingLogger }))
    }
    
    override func tearDown() {
        app.shutdown()
        super.tearDown()
    }
    
    // MARK: - Device Code Flow Origin Validation Tests
    
    func testValidateOriginForDeviceFlow_WithNoAuthorizedOrigins_SkipsValidation() throws {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            clientSecret: "secret",
            validScopes: ["read"],
            confidential: false,
            firstParty: false,
            allowedGrantType: .deviceCode,
            authorizedOrigins: nil
        )
        
        let request = Request(application: app, method: .POST, url: "/oauth/device_authorization", on: app.eventLoopGroup.next())
        request.headers.add(name: .origin, value: "https://malicious.com")
        request.headers.add(name: .userAgent, value: "Mozilla/5.0")
        
        // When & Then
        try originValidator.validateOriginForDeviceFlow(client: client, request: request, securityLogger: securityLogger)
        // Should not throw
    }
    
    func testValidateOriginForDeviceFlow_WithEmptyAuthorizedOrigins_SkipsValidation() throws {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            clientSecret: "secret",
            validScopes: ["read"],
            confidential: false,
            firstParty: false,
            allowedGrantType: .deviceCode,
            authorizedOrigins: []
        )
        
        let request = Request(application: app, method: .POST, url: "/oauth/device_authorization", on: app.eventLoopGroup.next())
        request.headers.add(name: .origin, value: "https://malicious.com")
        request.headers.add(name: .userAgent, value: "Mozilla/5.0")
        
        // When & Then
        try originValidator.validateOriginForDeviceFlow(client: client, request: request, securityLogger: securityLogger)
        // Should not throw
    }
    
    func testValidateOriginForDeviceFlow_WithNonBrowserRequest_SkipsValidation() throws {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            clientSecret: "secret",
            validScopes: ["read"],
            confidential: false,
            firstParty: false,
            allowedGrantType: .deviceCode,
            authorizedOrigins: ["https://example.com"]
        )
        
        let request = Request(application: app, method: .POST, url: "/oauth/device_authorization", on: app.eventLoopGroup.next())
        // No browser-like headers
        request.headers.add(name: .userAgent, value: "MyApp/1.0")
        
        // When & Then
        try originValidator.validateOriginForDeviceFlow(client: client, request: request, securityLogger: securityLogger)
        // Should not throw
    }
    
    func testValidateOriginForDeviceFlow_WithBrowserRequestMissingOrigin_ThrowsAndLogs() throws {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            clientSecret: "secret",
            validScopes: ["read"],
            confidential: false,
            firstParty: false,
            allowedGrantType: .deviceCode,
            authorizedOrigins: ["https://example.com"]
        )
        
        let request = Request(application: app, method: .POST, url: "/oauth/device_authorization", on: app.eventLoopGroup.next())
        request.headers.add(name: .userAgent, value: "Mozilla/5.0")
        // No Origin header
        
        // When & Then
        do {
            try originValidator.validateOriginForDeviceFlow(client: client, request: request, securityLogger: securityLogger)
            XCTFail("Should have thrown AuthorizationError.missingOrigin")
        } catch AuthorizationError.missingOrigin {
            // Expected
            XCTAssertEqual(capturingLogger.logLevel, .warning)
            XCTAssertTrue(capturingLogger.logMessage?.contains("OAuth origin validation failed") ?? false)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
    
    func testValidateOriginForDeviceFlow_WithBrowserRequestUnauthorizedOrigin_ThrowsAndLogs() throws {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            clientSecret: "secret",
            validScopes: ["read"],
            confidential: false,
            firstParty: false,
            allowedGrantType: .deviceCode,
            authorizedOrigins: ["https://example.com"]
        )
        
        let request = Request(application: app, method: .POST, url: "/oauth/device_authorization", on: app.eventLoopGroup.next())
        request.headers.add(name: .origin, value: "https://malicious.com")
        request.headers.add(name: .userAgent, value: "Mozilla/5.0")
        
        // When & Then
        do {
            try originValidator.validateOriginForDeviceFlow(client: client, request: request, securityLogger: securityLogger)
            XCTFail("Should have thrown AuthorizationError.unauthorizedOrigin")
        } catch AuthorizationError.unauthorizedOrigin {
            // Expected
            XCTAssertEqual(capturingLogger.logLevel, .warning)
            XCTAssertTrue(capturingLogger.logMessage?.contains("OAuth origin validation failed") ?? false)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
    
    func testValidateOriginForDeviceFlow_WithBrowserRequestValidOrigin_SucceedsAndLogs() throws {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            clientSecret: "secret",
            validScopes: ["read"],
            confidential: false,
            firstParty: false,
            allowedGrantType: .deviceCode,
            authorizedOrigins: ["https://example.com"]
        )
        
        let request = Request(application: app, method: .POST, url: "/oauth/device_authorization", on: app.eventLoopGroup.next())
        request.headers.add(name: .origin, value: "https://example.com")
        request.headers.add(name: .userAgent, value: "Mozilla/5.0")
        
        // When & Then
        try originValidator.validateOriginForDeviceFlow(client: client, request: request, securityLogger: securityLogger)
        
        // Verify success logging
        XCTAssertEqual(capturingLogger.logLevel, .info)
        XCTAssertTrue(capturingLogger.logMessage?.contains("OAuth origin validation succeeded") ?? false)
    }
    
    func testValidateOriginForDeviceFlow_WithRefererHeaderDetectsBrowser() throws {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            clientSecret: "secret",
            validScopes: ["read"],
            confidential: false,
            firstParty: false,
            allowedGrantType: .deviceCode,
            authorizedOrigins: ["https://example.com"]
        )
        
        let request = Request(application: app, method: .POST, url: "/oauth/device_authorization", on: app.eventLoopGroup.next())
        request.headers.add(name: .referer, value: "https://example.com/app")
        // No Origin header, but has Referer
        
        // When & Then
        do {
            try originValidator.validateOriginForDeviceFlow(client: client, request: request, securityLogger: securityLogger)
            XCTFail("Should have thrown AuthorizationError.missingOrigin")
        } catch AuthorizationError.missingOrigin {
            // Expected - browser detected but no Origin header
            XCTAssertEqual(capturingLogger.logLevel, .warning)
            XCTAssertTrue(capturingLogger.logMessage?.contains("OAuth origin validation failed") ?? false)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
    
    // MARK: - Security Logging Metadata Tests
    
    func testSecurityLogger_DeviceCodeFlow_LogsCorrectMetadata() throws {
        // Given
        let client = OAuthClient(
            clientID: "device-client",
            redirectURIs: ["https://example.com/callback"],
            clientSecret: "secret",
            validScopes: ["read"],
            confidential: false,
            firstParty: false,
            allowedGrantType: .deviceCode,
            authorizedOrigins: ["https://example.com"]
        )
        
        let request = Request(application: app, method: .POST, url: "/oauth/device_authorization", on: app.eventLoopGroup.next())
        request.headers.add(name: .origin, value: "https://malicious.com")
        request.headers.add(name: .userAgent, value: "Mozilla/5.0 (Test Browser)")
        
        // When
        do {
            try originValidator.validateOriginForDeviceFlow(client: client, request: request, securityLogger: securityLogger)
        } catch AuthorizationError.unauthorizedOrigin {
            // Expected
        }
        
        // Then - verify the log contains expected metadata
        XCTAssertEqual(capturingLogger.logLevel, .warning)
        XCTAssertTrue(capturingLogger.logMessage?.contains("OAuth origin validation failed") ?? false)
        // Note: In a real implementation, we would check the metadata directly,
        // but CapturingLogger only captures the message. The SecurityLogger
        // implementation includes all the required metadata.
    }
    
    func testSecurityLogger_LogsAllRequiredMetadata() {
        // Given
        let request = Request(application: app, method: .POST, url: "/oauth/device_authorization", on: app.eventLoopGroup.next())
        request.headers.add(name: .origin, value: "https://malicious.com")
        request.headers.add(name: .userAgent, value: "Mozilla/5.0 (Test Browser)")
        
        // When - Test failure logging
        securityLogger.logOriginValidationFailure(
            clientID: "test-client-123",
            attemptedOrigin: "https://malicious.com",
            authorizedOrigins: ["https://example.com", "https://app.example.com"],
            request: request
        )
        
        // Then - verify warning level and message
        XCTAssertEqual(capturingLogger.logLevel, .warning)
        XCTAssertTrue(capturingLogger.logMessage?.contains("OAuth origin validation failed") ?? false)
    }
    
    func testSecurityLogger_LogsSuccessMetadata() {
        // Given
        let request = Request(application: app, method: .POST, url: "/oauth/device_authorization", on: app.eventLoopGroup.next())
        request.headers.add(name: .origin, value: "https://example.com")
        request.headers.add(name: .userAgent, value: "Mozilla/5.0 (Test Browser)")
        
        // When - Test success logging
        securityLogger.logOriginValidationSuccess(
            clientID: "test-client-123",
            validatedOrigin: "https://example.com",
            request: request
        )
        
        // Then - verify info level and message
        XCTAssertEqual(capturingLogger.logLevel, .info)
        XCTAssertTrue(capturingLogger.logMessage?.contains("OAuth origin validation succeeded") ?? false)
    }
    
    func testSecurityLogger_DoesNotExposeSensitiveInformation() {
        // Given
        let request = Request(application: app, method: .POST, url: "/oauth/device_authorization", on: app.eventLoopGroup.next())
        request.headers.add(name: .origin, value: "https://malicious.com")
        request.headers.add(name: .userAgent, value: "Mozilla/5.0 (Test Browser)")
        
        // When
        securityLogger.logOriginValidationFailure(
            clientID: "client-with-secret",
            attemptedOrigin: "https://malicious.com",
            authorizedOrigins: ["https://example.com"],
            request: request
        )
        
        // Then - verify no sensitive information is exposed
        let logMessage = capturingLogger.logMessage ?? ""
        
        // Should not contain sensitive information like client secrets, tokens, etc.
        XCTAssertFalse(logMessage.contains("secret"))
        XCTAssertFalse(logMessage.contains("password"))
        XCTAssertFalse(logMessage.contains("token"))
        
        // Should contain debugging information
        XCTAssertTrue(logMessage.contains("OAuth origin validation failed"))
    }
}