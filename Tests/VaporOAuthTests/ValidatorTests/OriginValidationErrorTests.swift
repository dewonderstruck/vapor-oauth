import XCTest
import Vapor
import Logging
@testable import VaporOAuth

final class OriginValidationErrorTests: XCTestCase {
    
    var app: Application!
    var clientValidator: ClientValidator!
    var fakeClientRetriever: FakeClientGetter!
    var scopeValidator: ScopeValidator!
    var originValidator: OriginValidator!
    var capturingLogger: CapturingLogger!
    var securityLogger: SecurityLogger!
    
    override func setUp() {
        super.setUp()
        app = Application(.testing)
        
        fakeClientRetriever = FakeClientGetter()
        scopeValidator = ScopeValidator(validScopes: ["read", "write"], clientRetriever: fakeClientRetriever)
        originValidator = OriginValidator()
        capturingLogger = CapturingLogger()
        securityLogger = SecurityLogger(logger: Logger(label: "test", factory: { _ in capturingLogger }))
        
        clientValidator = ClientValidator(
            clientRetriever: fakeClientRetriever,
            scopeValidator: scopeValidator,
            environment: .testing,
            originValidator: originValidator,
            securityLogger: securityLogger
        )
    }
    
    override func tearDown() {
        app.shutdown()
        super.tearDown()
    }
    
    // MARK: - AuthorizationError Extension Tests
    
    func testAuthorizationError_HasUnauthorizedOriginCase() {
        // Given
        let error = AuthorizationError.unauthorizedOrigin
        
        // Then
        XCTAssertNotNil(error, "AuthorizationError should have unauthorizedOrigin case")
    }
    
    func testAuthorizationError_HasMissingOriginCase() {
        // Given
        let error = AuthorizationError.missingOrigin
        
        // Then
        XCTAssertNotNil(error, "AuthorizationError should have missingOrigin case")
    }
    
    // MARK: - ClientValidator Origin Validation Tests
    
    func testValidateClient_WithNoAuthorizedOrigins_SkipsOriginValidation() async throws {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            clientSecret: "secret",
            validScopes: ["read"],
            confidential: false,
            firstParty: false,
            allowedGrantType: .authorization,
            authorizedOrigins: nil
        )
        fakeClientRetriever.validClients[client.clientID] = client
        
        let request = Request(application: app, method: .GET, url: "/test", on: app.eventLoopGroup.next())
        // No Origin header
        
        // When & Then
        try await clientValidator.validateClient(
            clientID: client.clientID,
            responseType: "code",
            redirectURI: "https://example.com/callback",
            scopes: ["read"],
            request: request
        )
        // Should not throw
    }
    
    func testValidateClient_WithEmptyAuthorizedOrigins_SkipsOriginValidation() async throws {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            clientSecret: "secret",
            validScopes: ["read"],
            confidential: false,
            firstParty: false,
            allowedGrantType: .authorization,
            authorizedOrigins: []
        )
        fakeClientRetriever.validClients[client.clientID] = client
        
        let request = Request(application: app, method: .GET, url: "/test", on: app.eventLoopGroup.next())
        // No Origin header
        
        // When & Then
        try await clientValidator.validateClient(
            clientID: client.clientID,
            responseType: "code",
            redirectURI: "https://example.com/callback",
            scopes: ["read"],
            request: request
        )
        // Should not throw
    }
    
    func testValidateClient_WithMissingOriginHeader_ThrowsMissingOriginError() async throws {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            clientSecret: "secret",
            validScopes: ["read"],
            confidential: false,
            firstParty: false,
            allowedGrantType: .authorization,
            authorizedOrigins: ["https://example.com"]
        )
        fakeClientRetriever.validClients[client.clientID] = client
        
        let request = Request(application: app, method: .GET, url: "/test", on: app.eventLoopGroup.next())
        // No Origin header
        
        // When & Then
        do {
            try await clientValidator.validateClient(
                clientID: client.clientID,
                responseType: "code",
                redirectURI: "https://example.com/callback",
                scopes: ["read"],
                request: request
            )
            XCTFail("Should have thrown AuthorizationError.missingOrigin")
        } catch AuthorizationError.missingOrigin {
            // Expected
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
    
    func testValidateClient_WithUnauthorizedOrigin_ThrowsUnauthorizedOriginError() async throws {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            clientSecret: "secret",
            validScopes: ["read"],
            confidential: false,
            firstParty: false,
            allowedGrantType: .authorization,
            authorizedOrigins: ["https://example.com"]
        )
        fakeClientRetriever.validClients[client.clientID] = client
        
        let request = Request(application: app, method: .GET, url: "/test", on: app.eventLoopGroup.next())
        request.headers.add(name: .origin, value: "https://malicious.com")
        
        // When & Then
        do {
            try await clientValidator.validateClient(
                clientID: client.clientID,
                responseType: "code",
                redirectURI: "https://example.com/callback",
                scopes: ["read"],
                request: request
            )
            XCTFail("Should have thrown AuthorizationError.unauthorizedOrigin")
        } catch AuthorizationError.unauthorizedOrigin {
            // Expected
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
    
    func testValidateClient_WithValidOrigin_Succeeds() async throws {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            clientSecret: "secret",
            validScopes: ["read"],
            confidential: false,
            firstParty: false,
            allowedGrantType: .authorization,
            authorizedOrigins: ["https://example.com"]
        )
        fakeClientRetriever.validClients[client.clientID] = client
        
        let request = Request(application: app, method: .GET, url: "/test", on: app.eventLoopGroup.next())
        request.headers.add(name: .origin, value: "https://example.com")
        
        // When & Then
        try await clientValidator.validateClient(
            clientID: client.clientID,
            responseType: "code",
            redirectURI: "https://example.com/callback",
            scopes: ["read"],
            request: request
        )
        // Should not throw
    }
    
    // MARK: - Security Logging Tests
    
    func testValidateClient_WithMissingOrigin_LogsSecurityEvent() async throws {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            clientSecret: "secret",
            validScopes: ["read"],
            confidential: false,
            firstParty: false,
            allowedGrantType: .authorization,
            authorizedOrigins: ["https://example.com"]
        )
        fakeClientRetriever.validClients[client.clientID] = client
        
        let request = Request(application: app, method: .GET, url: "/test", on: app.eventLoopGroup.next())
        request.headers.add(name: .userAgent, value: "TestAgent/1.0")
        
        // When
        do {
            try await clientValidator.validateClient(
                clientID: client.clientID,
                responseType: "code",
                redirectURI: "https://example.com/callback",
                scopes: ["read"],
                request: request
            )
        } catch AuthorizationError.missingOrigin {
            // Expected
        }
        
        // Then
        XCTAssertEqual(capturingLogger.logLevel, .warning)
        XCTAssertTrue(capturingLogger.logMessage?.contains("OAuth origin validation failed") ?? false)
    }
    
    func testValidateClient_WithUnauthorizedOrigin_LogsSecurityEvent() async throws {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            clientSecret: "secret",
            validScopes: ["read"],
            confidential: false,
            firstParty: false,
            allowedGrantType: .authorization,
            authorizedOrigins: ["https://example.com"]
        )
        fakeClientRetriever.validClients[client.clientID] = client
        
        let request = Request(application: app, method: .GET, url: "/test", on: app.eventLoopGroup.next())
        request.headers.add(name: .origin, value: "https://malicious.com")
        request.headers.add(name: .userAgent, value: "TestAgent/1.0")
        
        // When
        do {
            try await clientValidator.validateClient(
                clientID: client.clientID,
                responseType: "code",
                redirectURI: "https://example.com/callback",
                scopes: ["read"],
                request: request
            )
        } catch AuthorizationError.unauthorizedOrigin {
            // Expected
        }
        
        // Then
        XCTAssertEqual(capturingLogger.logLevel, .warning)
        XCTAssertTrue(capturingLogger.logMessage?.contains("OAuth origin validation failed") ?? false)
    }
    
    func testValidateClient_WithValidOrigin_LogsSuccessEvent() async throws {
        // Given
        let client = OAuthClient(
            clientID: "test-client",
            redirectURIs: ["https://example.com/callback"],
            clientSecret: "secret",
            validScopes: ["read"],
            confidential: false,
            firstParty: false,
            allowedGrantType: .authorization,
            authorizedOrigins: ["https://example.com"]
        )
        fakeClientRetriever.validClients[client.clientID] = client
        
        let request = Request(application: app, method: .GET, url: "/test", on: app.eventLoopGroup.next())
        request.headers.add(name: .origin, value: "https://example.com")
        
        // When
        try await clientValidator.validateClient(
            clientID: client.clientID,
            responseType: "code",
            redirectURI: "https://example.com/callback",
            scopes: ["read"],
            request: request
        )
        
        // Then
        XCTAssertEqual(capturingLogger.logLevel, .info)
        XCTAssertTrue(capturingLogger.logMessage?.contains("OAuth origin validation succeeded") ?? false)
    }
    
    // MARK: - Error Response Format Tests
    
    func testSecurityLogger_LogsOriginValidationFailure_WithCorrectMetadata() {
        // Given
        let request = Request(application: app, method: .GET, url: "/test", on: app.eventLoopGroup.next())
        request.headers.add(name: .userAgent, value: "TestAgent/1.0")
        
        // When
        securityLogger.logOriginValidationFailure(
            clientID: "test-client",
            attemptedOrigin: "https://malicious.com",
            authorizedOrigins: ["https://example.com"],
            request: request
        )
        
        // Then
        XCTAssertEqual(capturingLogger.logLevel, .warning)
        XCTAssertTrue(capturingLogger.logMessage?.contains("OAuth origin validation failed") ?? false)
    }
    
    func testSecurityLogger_LogsOriginValidationFailure_WithMissingOrigin() {
        // Given
        let request = Request(application: app, method: .GET, url: "/test", on: app.eventLoopGroup.next())
        
        // When
        securityLogger.logOriginValidationFailure(
            clientID: "test-client",
            attemptedOrigin: nil,
            authorizedOrigins: ["https://example.com"],
            request: request
        )
        
        // Then
        XCTAssertEqual(capturingLogger.logLevel, .warning)
        XCTAssertTrue(capturingLogger.logMessage?.contains("OAuth origin validation failed") ?? false)
    }
    
    func testSecurityLogger_LogsOriginValidationSuccess_WithCorrectMetadata() {
        // Given
        let request = Request(application: app, method: .GET, url: "/test", on: app.eventLoopGroup.next())
        
        // When
        securityLogger.logOriginValidationSuccess(
            clientID: "test-client",
            validatedOrigin: "https://example.com",
            request: request
        )
        
        // Then
        XCTAssertEqual(capturingLogger.logLevel, .info)
        XCTAssertTrue(capturingLogger.logMessage?.contains("OAuth origin validation succeeded") ?? false)
    }
}