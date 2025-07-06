import Vapor
import XCTVapor
import XCTest

@testable import VaporOAuth

final class PARExtensionTests: XCTestCase {

    func testPARExtensionRegistration() async throws {
        // Given
        let app = try await Application.make(.testing)

        let extensionManager = OAuthExtensionManager()
        extensionManager.register(PushedAuthorizationRequestsExtension())

        // When
        let extensions = extensionManager.getAllExtensions()

        // Then
        XCTAssertEqual(extensions.count, 1)

        let parExtension = extensions.first
        XCTAssertNotNil(parExtension)
        XCTAssertEqual(parExtension?.extensionID, "par")
        XCTAssertEqual(parExtension?.extensionName, "Pushed Authorization Requests")
        XCTAssertEqual(parExtension?.specificationVersion, "RFC 9126")
        XCTAssertTrue(parExtension?.modifiesAuthorizationRequest == true)
        XCTAssertTrue(parExtension?.modifiesTokenRequest == false)
        XCTAssertTrue(parExtension?.addsEndpoints == true)
        XCTAssertTrue(parExtension?.requiresConfiguration == false)

        // Cleanup
        try await app.asyncShutdown()
    }

    func testPARExtensionMetadata() async throws {
        // Given
        let app = try await Application.make(.testing)

        let extensionManager = OAuthExtensionManager()
        extensionManager.register(PushedAuthorizationRequestsExtension())

        // Add extension routes
        try await extensionManager.addExtensionRoutes(to: app)

        // When
        let response = try await app.sendRequest(.GET, "/oauth/extensions/metadata")

        // Then
        XCTAssertEqual(response.status, .ok)

        let metadata = try response.content.decode(ExtensionsMetadataResponse.self)
        XCTAssertEqual(metadata.totalExtensions, 1)
        XCTAssertEqual(metadata.extensions.count, 1)

        let parExtension = metadata.extensions.first
        XCTAssertNotNil(parExtension)
        XCTAssertEqual(parExtension?.id, "par")
        XCTAssertEqual(parExtension?.name, "Pushed Authorization Requests")
        XCTAssertEqual(parExtension?.specificationVersion, "RFC 9126")
        XCTAssertTrue(parExtension?.modifiesAuthorizationRequest == true)
        XCTAssertTrue(parExtension?.modifiesTokenRequest == false)
        XCTAssertTrue(parExtension?.addsEndpoints == true)
        XCTAssertTrue(parExtension?.requiresConfiguration == false)

        // Cleanup
        try await app.asyncShutdown()
    }

    func testPAREndpointExists() async throws {
        // Given
        let app = try await Application.make(.testing)

        let extensionManager = OAuthExtensionManager()
        extensionManager.register(PushedAuthorizationRequestsExtension())

        // Add extension routes
        try await extensionManager.addExtensionRoutes(to: app)

        // When
        let response = try await app.sendRequest(.POST, "/oauth/par")

        // Then
        // Should return an error (missing authentication) but endpoint should exist
        XCTAssertNotEqual(response.status, .notFound)

        // Cleanup
        try await app.asyncShutdown()
    }

    func testPARRequestURIValidation() async throws {
        // Given
        let app = try await Application.make(.testing)

        let extensionManager = OAuthExtensionManager()
        extensionManager.register(PushedAuthorizationRequestsExtension())

        // Add extension routes
        try await extensionManager.addExtensionRoutes(to: app)

        // When - Valid request URI
        let validRequestData = ["request_uri": "urn:ietf:params:oauth:request_uri:abc123"]
        let validRequestBody = ["requestData": validRequestData]

        let validResponse = try app.sendRequest(
            .POST, "/oauth/extensions/validate",
            beforeRequest: { req in
                try req.content.encode(validRequestBody)
            })

        // Then - Valid request should pass
        XCTAssertEqual(validResponse.status, .ok)
        let validResult = try validResponse.content.decode(ExtensionsValidationResponse.self)
        XCTAssertTrue(validResult.valid)
        XCTAssertTrue(validResult.errors.isEmpty)
        XCTAssertEqual(validResult.validatedExtensions, ["par"])

        // When - Invalid request URI
        let invalidRequestData = ["request_uri": "invalid-uri"]
        let invalidRequestBody = ["requestData": invalidRequestData]

        let invalidResponse = try await app.sendRequest(
            .POST, "/oauth/extensions/validate",
            beforeRequest: { req in
                try req.content.encode(invalidRequestBody)
            })

        // Then - Invalid request should fail
        XCTAssertEqual(invalidResponse.status, .ok)
        let invalidResult = try invalidResponse.content.decode(ExtensionsValidationResponse.self)
        XCTAssertFalse(invalidResult.valid)
        XCTAssertFalse(invalidResult.errors.isEmpty)
        XCTAssertEqual(invalidResult.validatedExtensions, ["par"])

        let error = invalidResult.errors.first
        XCTAssertNotNil(error)
        XCTAssertEqual(error?.extensionID, "par")
        XCTAssertTrue(error?.error.contains("Request URI must be in the format") == true)

        // Cleanup
        try await app.asyncShutdown()
    }

    func testPARModelValidation() async throws {
        // Given
        let parameters = AuthorizationRequestParameters(
            responseType: "code",
            clientID: "test-client",
            redirectURI: "https://example.com/callback",
            scope: "read write",
            state: "abc123",
            codeChallenge: "test-challenge",
            codeChallengeMethod: "S256",
            authorizationDetails: "[{\"type\":\"payment_initiation\",\"actions\":[\"initiate\"]}]",
            additionalParameters: ["custom_param": "custom_value"]
        )

        // When
        let dictionary = parameters.toDictionary()

        // Then
        XCTAssertEqual(dictionary[OAuthRequestParameters.responseType], "code")
        XCTAssertEqual(dictionary[OAuthRequestParameters.clientID], "test-client")
        XCTAssertEqual(dictionary[OAuthRequestParameters.redirectURI], "https://example.com/callback")
        XCTAssertEqual(dictionary[OAuthRequestParameters.scope], "read write")
        XCTAssertEqual(dictionary[OAuthRequestParameters.state], "abc123")
        XCTAssertEqual(dictionary[OAuthRequestParameters.codeChallenge], "test-challenge")
        XCTAssertEqual(dictionary[OAuthRequestParameters.codeChallengeMethod], "S256")
        XCTAssertEqual(
            dictionary[OAuthRequestParameters.authorizationDetails], "[{\"type\":\"payment_initiation\",\"actions\":[\"initiate\"]}]")
        XCTAssertEqual(dictionary["custom_param"], "custom_value")
    }

    func testPushedAuthorizationRequestValidation() async throws {
        // Given
        let parameters = AuthorizationRequestParameters(
            responseType: "code",
            clientID: "test-client",
            redirectURI: "https://example.com/callback",
            scope: "read write"
        )

        let request = PushedAuthorizationRequest(
            id: "test-id",
            clientID: "test-client",
            requestURI: "urn:ietf:params:oauth:request_uri:abc123",
            expiresAt: Date().addingTimeInterval(60),
            parameters: parameters
        )

        // When & Then
        XCTAssertFalse(request.isExpired)
        XCTAssertTrue(request.isValid)

        // Test expired request
        let expiredRequest = PushedAuthorizationRequest(
            id: "test-id",
            clientID: "test-client",
            requestURI: "urn:ietf:params:oauth:request_uri:abc123",
            expiresAt: Date().addingTimeInterval(-60),  // Expired
            parameters: parameters
        )

        XCTAssertTrue(expiredRequest.isExpired)
        XCTAssertFalse(expiredRequest.isValid)

        // Test used request
        let usedRequest = PushedAuthorizationRequest(
            id: "test-id",
            clientID: "test-client",
            requestURI: "urn:ietf:params:oauth:request_uri:abc123",
            expiresAt: Date().addingTimeInterval(60),
            parameters: parameters,
            isUsed: true
        )

        XCTAssertFalse(usedRequest.isExpired)
        XCTAssertFalse(usedRequest.isValid)
    }

    func testEmptyPARManager() async throws {
        // Given
        let manager = EmptyPushedAuthorizationRequestManager()

        // When
        let requestURI = try await manager.generateRequestURI()

        // Then
        XCTAssertTrue(requestURI.hasPrefix("urn:ietf:params:oauth:request_uri:"))
        XCTAssertEqual(manager.requestExpirationTime, 60)

        // Test that other methods don't throw
        let parameters = AuthorizationRequestParameters(
            responseType: "code",
            clientID: "test-client"
        )

        let request = PushedAuthorizationRequest(
            id: "test-id",
            clientID: "test-client",
            requestURI: requestURI,
            expiresAt: Date().addingTimeInterval(60),
            parameters: parameters
        )

        try await manager.storeRequest(request)
        let retrieved = try await manager.getRequest(requestURI: requestURI, clientID: "test-client")
        XCTAssertNil(retrieved)  // Empty implementation returns nil

        try await manager.markRequestAsUsed(requestURI: requestURI)
        try await manager.deleteRequest(requestURI: requestURI)
        try await manager.cleanupExpiredRequests()
    }

    func testPARResponseEncoding() async throws {
        // Given
        let app = try await Application.make(.testing)
        let response = PushedAuthorizationResponse(
            requestURI: "urn:ietf:params:oauth:request_uri:abc123",
            expiresIn: 60
        )

        // When
        let testRequest = Request(application: app, on: app.eventLoopGroup.next())
        let encodedResponse = try await response.encodeResponse(for: testRequest)

        // Then
        XCTAssertEqual(encodedResponse.status, HTTPStatus.ok)
        XCTAssertEqual(encodedResponse.headers.first(name: .contentType), "application/json")

        let responseData = encodedResponse.body.data ?? Data()
        let decodedResponse = try JSONDecoder().decode(PushedAuthorizationResponse.self, from: responseData)

        XCTAssertEqual(decodedResponse.requestURI, "urn:ietf:params:oauth:request_uri:abc123")
        XCTAssertEqual(decodedResponse.expiresIn, 60)

        // Cleanup
        try await app.asyncShutdown()
    }

    func testPARErrorResponseEncoding() async throws {
        // Given
        let app = try await Application.make(.testing)
        let errorResponse = PARErrorResponse(
            error: "invalid_request",
            errorDescription: "Missing required parameter",
            errorURI: "https://example.com/errors/invalid_request"
        )

        // When
        let testRequest = Request(application: app, on: app.eventLoopGroup.next())
        let encodedResponse = try await errorResponse.encodeResponse(for: testRequest)

        // Then
        XCTAssertEqual(encodedResponse.status, HTTPStatus.badRequest)
        XCTAssertEqual(encodedResponse.headers.first(name: .contentType), "application/json")

        let responseData = encodedResponse.body.data ?? Data()
        let decodedResponse = try JSONDecoder().decode(PARErrorResponse.self, from: responseData)

        XCTAssertEqual(decodedResponse.error, "invalid_request")
        XCTAssertEqual(decodedResponse.errorDescription, "Missing required parameter")
        XCTAssertEqual(decodedResponse.errorURI, "https://example.com/errors/invalid_request")

        // Cleanup
        try await app.asyncShutdown()
    }

    func testPARIntegrationWithOAuth2() async throws {
        // Given
        let app = try await TestDataBuilder.getOAuth2Application(
            enablePARExtension: true
        )

        // When - Check if PAR endpoint is available
        let response = try await app.sendRequest(.POST, "/oauth/par")

        // Then
        // Should return an error (missing authentication) but endpoint should exist
        XCTAssertNotEqual(response.status, .notFound)

        // When - Check server metadata
        let metadataResponse = try await app.sendRequest(.GET, "/.well-known/oauth-authorization-server")

        // Then
        XCTAssertEqual(metadataResponse.status, .ok)

        let metadata = try metadataResponse.content.decode(OAuthServerMetadata.self)
        XCTAssertNotNil(metadata.pushedAuthorizationRequestEndpoint)
        XCTAssertTrue(metadata.pushedAuthorizationRequestEndpoint?.hasSuffix("/oauth/par") == true)

        // Cleanup - ensure proper shutdown
        try await app.asyncShutdown()
    }
}
