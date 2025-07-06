import Vapor
import XCTest

@testable import VaporOAuth

final class RARExtensionTests: XCTestCase {

    var app: Application!
    var rarExtension: RichAuthorizationRequestsExtension!

    override func setUp() async throws {
        try await super.setUp()
        app = try await Application.make(.testing)
        rarExtension = RichAuthorizationRequestsExtension()
    }

    override func tearDown() async throws {
        if let app = app {
            try await app.asyncShutdown()
        }
        app = nil
        rarExtension = nil
        try await super.tearDown()
    }

    // MARK: - OAuthExtension Protocol Conformance Tests

    func testOAuthExtensionConformance() {
        // Test required properties
        XCTAssertEqual(rarExtension.extensionID, "rar")
        XCTAssertEqual(rarExtension.extensionName, "Rich Authorization Requests")
        XCTAssertEqual(rarExtension.specificationVersion, "RFC 9396")

        // Test behavior flags
        XCTAssertTrue(rarExtension.modifiesAuthorizationRequest)
        XCTAssertTrue(rarExtension.modifiesTokenRequest)
        XCTAssertFalse(rarExtension.addsEndpoints)
        XCTAssertFalse(rarExtension.requiresConfiguration)
    }

    func testExtensionMetadata() {
        let metadata = rarExtension.getMetadata()

        XCTAssertEqual(metadata["extension_id"] as? String, "rar")
        XCTAssertEqual(metadata["extension_name"] as? String, "Rich Authorization Requests")
        XCTAssertEqual(metadata["specification_version"] as? String, "RFC 9396")
        XCTAssertEqual(metadata["modifies_authorization_request"] as? Bool, true)
        XCTAssertEqual(metadata["modifies_token_request"] as? Bool, true)
        XCTAssertEqual(metadata["adds_endpoints"] as? Bool, false)
        XCTAssertEqual(metadata["requires_configuration"] as? Bool, false)

        // Test rar_configuration metadata
        let config = metadata["rar_configuration"] as? [String: Any]
        XCTAssertNotNil(config)
        XCTAssertEqual(config?["allow_custom_types"] as? Bool, true)
        XCTAssertEqual(config?["max_authorization_details"] as? Int, 10)
        XCTAssertEqual(config?["validate_uris"] as? Bool, true)
    }

    // MARK: - Route Addition Tests

    func testRouteAddition() async throws {
        // Add routes to the application
        try await rarExtension.addRoutes(to: app)

        // Test that the routes are accessible
        // Note: In a real test, you would make actual HTTP requests
        // For now, we'll verify the routes are registered by checking the router

        // The extension should add these routes:
        // GET /oauth/rar/metadata
        // POST /oauth/rar/validate

        // We can't easily test the router directly, but we can verify the extension
        // doesn't throw when adding routes
        do {
            try await rarExtension.addRoutes(to: app)
        } catch {
            XCTFail("Route addition should not throw: \(error)")
        }
    }

    // MARK: - Request Validation Tests

    func testRequestValidationWithValidRAR() async throws {
        let request = Request(application: app, on: app.eventLoopGroup.next())
        request.url = URI(
            string:
                "https://example.com/oauth/authorize?authorization_details=%5B%7B%22type%22%3A%22account_access%22%2C%22actions%22%3A%5B%22read%22%5D%7D%5D"
        )

        let errors = try await rarExtension.validateRequest(request)
        XCTAssertTrue(errors.isEmpty)
    }

    func testRequestValidationWithInvalidRAR() async throws {
        let request = Request(application: app, on: app.eventLoopGroup.next())
        request.url = URI(
            string:
                "https://example.com/oauth/authorize?authorization_details=%5B%7B%22type%22%3A%22%22%2C%22actions%22%3A%5B%22read%22%5D%7D%5D"
        )

        let errors = try await rarExtension.validateRequest(request)
        XCTAssertFalse(errors.isEmpty)
        XCTAssertTrue(errors[0].localizedDescription.contains("empty type"))
    }

    func testRequestValidationWithoutRAR() async throws {
        let request = Request(application: app, on: app.eventLoopGroup.next())
        request.url = URI(string: "https://example.com/oauth/authorize")

        let errors = try await rarExtension.validateRequest(request)
        XCTAssertTrue(errors.isEmpty)
    }

    // MARK: - Authorization Request Processing Tests

    func testAuthorizationRequestProcessing() async throws {
        let request = Request(application: app, on: app.eventLoopGroup.next())
        request.url = URI(
            string:
                "https://example.com/oauth/authorize?authorization_details=%5B%7B%22type%22%3A%22account_access%22%2C%22actions%22%3A%5B%22read%22%5D%7D%5D"
        )

        // Create a mock authorization request object
        let authRequest = AuthorizationRequestObject(
            responseType: "code",
            clientID: "test-client",
            redirectURI: URI(string: "https://example.com/callback"),
            scope: ["read"],
            state: "test-state",
            csrfToken: "csrf-token",
            codeChallenge: nil,
            codeChallengeMethod: nil
        )

        let result = try await rarExtension.processValidatedAuthorizationRequest(request, authRequest: authRequest)

        // The extension should return nil (no modification) for now
        // In a real implementation, it might modify the request or store RAR data
        XCTAssertNil(result)
    }

    func testAuthorizationRequestProcessingWithoutRAR() async throws {
        let request = Request(application: app, on: app.eventLoopGroup.next())
        request.url = URI(string: "https://example.com/oauth/authorize")

        let authRequest = AuthorizationRequestObject(
            responseType: "code",
            clientID: "test-client",
            redirectURI: URI(string: "https://example.com/callback"),
            scope: ["read"],
            state: "test-state",
            csrfToken: "csrf-token",
            codeChallenge: nil,
            codeChallengeMethod: nil
        )

        let result = try await rarExtension.processValidatedAuthorizationRequest(request, authRequest: authRequest)
        XCTAssertNil(result)
    }

    // MARK: - Token Request Processing Tests

    func testTokenRequestProcessing() async throws {
        let request = Request(application: app, on: app.eventLoopGroup.next())
        request.headers.contentType = .formData

        let formData = ["authorization_details": "[{\"type\":\"account_access\",\"actions\":[\"read\"]}]"]
        try request.content.encode(formData, as: .urlEncodedForm)

        let result = try await rarExtension.processTokenRequest(request)

        // The extension should return the original request for now
        // In a real implementation, it might modify the request or store RAR data
        XCTAssertNotNil(result)
    }

    func testTokenRequestProcessingWithoutRAR() async throws {
        let request = Request(application: app, on: app.eventLoopGroup.next())
        request.headers.contentType = .formData

        let formData = ["grant_type": "authorization_code", "code": "test-code"]
        try request.content.encode(formData, as: .urlEncodedForm)

        let result = try await rarExtension.processTokenRequest(request)
        XCTAssertNil(result)
    }

    // MARK: - Configuration Tests

    func testExtensionWithCustomConfiguration() {
        let customConfig = RARConfiguration(
            allowCustomTypes: false,
            maxAuthorizationDetails: 5,
            validateURIs: false,
            allowedTypes: [.accountAccess],
            allowedActions: [.read],
            typeRegistry: DefaultRARTypeRegistry()
        )

        let customExtension = RichAuthorizationRequestsExtension(configuration: customConfig)

        XCTAssertEqual(customExtension.extensionID, "rar")
        XCTAssertEqual(customExtension.extensionName, "Rich Authorization Requests")

        let metadata = customExtension.getMetadata()
        let config = metadata["rar_configuration"] as? [String: Any]
        XCTAssertEqual(config?["allow_custom_types"] as? Bool, false)
        XCTAssertEqual(config?["max_authorization_details"] as? Int, 5)
        XCTAssertEqual(config?["validate_uris"] as? Bool, false)
    }

    // MARK: - Error Handling Tests

    func testRequestValidationWithMalformedJSON() async throws {
        let request = Request(application: app, on: app.eventLoopGroup.next())
        request.url = URI(string: "https://example.com/oauth/authorize?authorization_details=invalid-json")

        let errors = try await rarExtension.validateRequest(request)
        XCTAssertFalse(errors.isEmpty)
        XCTAssertTrue(errors[0].localizedDescription.contains("Invalid JSON format"))
    }

    func testRequestValidationWithTooManyDetails() async throws {
        let request = Request(application: app, on: app.eventLoopGroup.next())

        // Create a request with more than the default limit (10) authorization details
        let manyDetails = (1...11).map { i in
            """
            {
                "type": "account_access",
                "actions": ["read"]
            }
            """
        }.joined(separator: ",")

        let jsonString = "[\(manyDetails)]"
        let encodedJSON = jsonString.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
        request.url = URI(string: "https://example.com/oauth/authorize?authorization_details=\(encodedJSON)")

        let errors = try await rarExtension.validateRequest(request)
        XCTAssertFalse(errors.isEmpty)
        XCTAssertTrue(errors[0].localizedDescription.contains("Too many authorization details"))
    }

    // MARK: - Integration Tests

    func testEndToEndRARFlow() async throws {
        // Test the complete flow from request validation to processing

        // 1. Create a request with valid RAR data
        let request = Request(application: app, on: app.eventLoopGroup.next())
        request.url = URI(
            string:
                "https://example.com/oauth/authorize?authorization_details=%5B%7B%22type%22%3A%22payment_initiation%22%2C%22actions%22%3A%5B%22initiate%22%2C%22status%22%5D%2C%22locations%22%3A%5B%22https%3A%2F%2Fapi.example.com%2Fpayments%22%5D%7D%5D"
        )

        // 2. Validate the request
        let validationErrors = try await rarExtension.validateRequest(request)
        XCTAssertTrue(validationErrors.isEmpty)

        // 3. Process the authorization request
        let authRequest = AuthorizationRequestObject(
            responseType: "code",
            clientID: "test-client",
            redirectURI: URI(string: "https://example.com/callback"),
            scope: ["payment"],
            state: "test-state",
            csrfToken: "csrf-token",
            codeChallenge: nil,
            codeChallengeMethod: nil
        )

        let processedRequest = try await rarExtension.processValidatedAuthorizationRequest(request, authRequest: authRequest)
        XCTAssertNil(processedRequest)  // No modification for now

        // 4. Test token request processing
        let tokenRequest = Request(application: app, on: app.eventLoopGroup.next())
        tokenRequest.headers.contentType = .formData

        let tokenFormData = ["authorization_details": "[{\"type\":\"payment_initiation\",\"actions\":[\"initiate\",\"status\"]}]"]
        try tokenRequest.content.encode(tokenFormData, as: .urlEncodedForm)

        let processedTokenRequest = try await rarExtension.processTokenRequest(tokenRequest)
        XCTAssertNotNil(processedTokenRequest)
    }

    func testExtensionWithCustomTypes() async throws {
        // Test that the extension works with custom RAR types
        let customConfig = GenericRARConfiguration<CustomRARTypeRegistry>(
            allowCustomTypes: true,
            maxAuthorizationDetails: 5,
            validateURIs: true,
            allowedTypes: Set(CustomRARType.allCases),
            allowedActions: Set(CustomRARAction.allCases),
            typeRegistry: CustomRARTypeRegistry()
        )

        // Note: This would require a custom extension implementation
        // For now, we test that the configuration works
        XCTAssertTrue(customConfig.allowCustomTypes)
        XCTAssertEqual(customConfig.maxAuthorizationDetails, 5)
        XCTAssertEqual(customConfig.allowedTypes?.count, 4)  // CustomRARType.allCases.count
        XCTAssertGreaterThan(customConfig.allowedActions?.count ?? 0, 0)
    }

    func testExtensionDiscoveryEndpoint() async throws {
        // Given
        let app = try await Application.make(.testing)

        let extensionManager = OAuthExtensionManager()
        extensionManager.register(RichAuthorizationRequestsExtension())

        // Add extension routes
        try await extensionManager.addExtensionRoutes(to: app)

        // When
        let response = try await app.sendRequest(.GET, "/oauth/extensions/metadata")

        // Then
        XCTAssertEqual(response.status, .ok)

        let metadata = try response.content.decode(ExtensionsMetadataResponse.self)
        XCTAssertEqual(metadata.totalExtensions, 1)
        XCTAssertEqual(metadata.extensions.count, 1)

        let rarExtension = metadata.extensions.first
        XCTAssertNotNil(rarExtension)
        XCTAssertEqual(rarExtension?.id, "rar")
        XCTAssertEqual(rarExtension?.name, "Rich Authorization Requests")
        XCTAssertEqual(rarExtension?.specificationVersion, "RFC 9396")
        XCTAssertTrue(rarExtension?.modifiesAuthorizationRequest == true)
        XCTAssertTrue(rarExtension?.modifiesTokenRequest == true)
        XCTAssertTrue(rarExtension?.addsEndpoints == false)
        XCTAssertTrue(rarExtension?.requiresConfiguration == false)

        // Cleanup
        try await app.asyncShutdown()
    }

    func testExtensionValidationEndpoint() async throws {
        // Given
        let app = try await Application.make(.testing)

        let extensionManager = OAuthExtensionManager()
        extensionManager.register(RichAuthorizationRequestsExtension())

        // Add extension routes
        try await extensionManager.addExtensionRoutes(to: app)

        // When - Valid request
        let validRequestData = ["authorization_details": "[{\"type\":\"payment_initiation\",\"actions\":[\"initiate\"]}]"]
        let validRequestBody = ["requestData": validRequestData]

        let validResponse = try await app.sendRequest(
            .POST, "/oauth/extensions/validate",
            beforeRequest: { req in
                try req.content.encode(validRequestBody)
            })

        // Then - Valid request should pass
        XCTAssertEqual(validResponse.status, .ok)
        let validResult = try validResponse.content.decode(ExtensionsValidationResponse.self)
        XCTAssertTrue(validResult.valid)
        XCTAssertTrue(validResult.errors.isEmpty)
        XCTAssertEqual(validResult.validatedExtensions, ["rar"])

        // When - Invalid request
        let invalidRequestData = ["authorization_details": "[{\"type\":\"\",\"actions\":[\"initiate\"]}]"]
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
        XCTAssertEqual(invalidResult.validatedExtensions, ["rar"])

        let error = invalidResult.errors.first
        XCTAssertNotNil(error)
        XCTAssertEqual(error?.extensionID, "rar")
        XCTAssertEqual(error?.extensionName, "Rich Authorization Requests")
        XCTAssertTrue(error?.error.contains("empty type") == true)

        // Cleanup
        try await app.asyncShutdown()
    }
}
