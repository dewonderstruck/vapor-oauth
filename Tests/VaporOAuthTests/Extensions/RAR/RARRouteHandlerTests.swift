import Vapor
import XCTest

@testable import VaporOAuth

final class RARRouteHandlerTests: XCTestCase {

    var app: Application!
    var routeHandler: RARRouteHandler<DefaultRARTypeRegistry>!
    var customRouteHandler: RARRouteHandler<CustomRARTypeRegistry>!

    override func setUp() async throws {
        try await super.setUp()
        app = try await Application.make(.testing)

        let config = RARConfiguration.default
        let validator = RARValidator(configuration: config)
        routeHandler = RARRouteHandler(validator: validator)

        let customConfig = GenericRARConfiguration<CustomRARTypeRegistry>(
            allowCustomTypes: true,
            maxAuthorizationDetails: 5,
            validateURIs: true,
            allowedTypes: Set(CustomRARType.allCases),
            allowedActions: Set(CustomRARAction.allCases),
            typeRegistry: CustomRARTypeRegistry()
        )
        let customValidator = RARValidator(configuration: customConfig)
        customRouteHandler = RARRouteHandler(validator: customValidator)
    }

    override func tearDown() async throws {
        if let app = app {
            try await app.asyncShutdown()
        }
        app = nil
        routeHandler = nil
        customRouteHandler = nil
        try await super.tearDown()
    }

    // MARK: - Metadata Endpoint Tests

    func testMetadataRequest() async throws {
        let request = Request(application: app, on: app.eventLoopGroup.next())

        let response = try await routeHandler.handleMetadataRequest(request)

        // Test response structure
        XCTAssertFalse(response.supportedTypes.isEmpty)
        XCTAssertFalse(response.supportedActions.isEmpty)
        XCTAssertGreaterThan(response.maxAuthorizationDetails, 0)
        XCTAssertTrue(response.allowCustomTypes)
        XCTAssertEqual(response.specificationVersion, "RFC 9396")

        // Test that all predefined types are included
        XCTAssertTrue(response.supportedTypes.contains("payment_initiation"))
        XCTAssertTrue(response.supportedTypes.contains("account_access"))
        XCTAssertTrue(response.supportedTypes.contains("data_access"))

        // Test that all predefined actions are included
        XCTAssertTrue(response.supportedActions.contains("read"))
        XCTAssertTrue(response.supportedActions.contains("write"))
        XCTAssertTrue(response.supportedActions.contains("initiate"))
    }

    func testCustomMetadataRequest() async throws {
        let request = Request(application: app, on: app.eventLoopGroup.next())

        let response = try await customRouteHandler.handleMetadataRequest(request)

        // Test that custom types are included
        XCTAssertTrue(response.supportedTypes.contains("document_access"))
        XCTAssertTrue(response.supportedTypes.contains("user_profile"))
        XCTAssertTrue(response.supportedTypes.contains("notification_settings"))
        XCTAssertTrue(response.supportedTypes.contains("api_access"))

        // Test that custom actions are included
        XCTAssertTrue(response.supportedActions.contains("download"))
        XCTAssertTrue(response.supportedActions.contains("upload"))
        XCTAssertTrue(response.supportedActions.contains("update"))
        XCTAssertTrue(response.supportedActions.contains("execute"))

        // Test configuration values
        XCTAssertEqual(response.maxAuthorizationDetails, 5)
        XCTAssertTrue(response.allowCustomTypes)
    }

    // MARK: - Validation Endpoint Tests

    func testValidValidationRequest() async throws {
        let request = Request(application: app, on: app.eventLoopGroup.next())
        request.headers.contentType = .json

        let validationRequest = RARValidationRequest(
            authorizationDetails: """
                [
                    {
                        "type": "account_access",
                        "actions": ["read"],
                        "locations": ["https://api.example.com/accounts"]
                    }
                ]
                """
        )

        try request.content.encode(validationRequest)

        let response = try await routeHandler.handleValidationRequest(request)

        XCTAssertTrue(response.valid)
        XCTAssertTrue(response.errors.isEmpty)
        XCTAssertNotNil(response.authorizationDetails)
        XCTAssertEqual(response.authorizationDetails?.count, 1)
        XCTAssertEqual(response.authorizationDetails?[0].type, "account_access")
    }

    func testInvalidValidationRequest() async throws {
        let request = Request(application: app, on: app.eventLoopGroup.next())
        request.headers.contentType = .json

        let validationRequest = RARValidationRequest(
            authorizationDetails: """
                [
                    {
                        "type": "",
                        "actions": ["read"]
                    }
                ]
                """
        )

        try request.content.encode(validationRequest)

        let response = try await routeHandler.handleValidationRequest(request)

        XCTAssertFalse(response.valid)
        XCTAssertFalse(response.errors.isEmpty)
        XCTAssertNil(response.authorizationDetails)
        XCTAssertTrue(response.errors[0].contains("empty type"))
    }

    func testMultipleValidAuthorizationDetails() async throws {
        let request = Request(application: app, on: app.eventLoopGroup.next())
        request.headers.contentType = .json

        let validationRequest = RARValidationRequest(
            authorizationDetails: """
                [
                    {
                        "type": "account_access",
                        "actions": ["read"],
                        "locations": ["https://api.example.com/accounts"]
                    },
                    {
                        "type": "data_access",
                        "actions": ["read", "write"],
                        "locations": ["https://api.example.com/data"]
                    }
                ]
                """
        )

        try request.content.encode(validationRequest)

        let response = try await routeHandler.handleValidationRequest(request)

        XCTAssertTrue(response.valid)
        XCTAssertTrue(response.errors.isEmpty)
        XCTAssertNotNil(response.authorizationDetails)
        XCTAssertEqual(response.authorizationDetails?.count, 2)
        XCTAssertEqual(response.authorizationDetails?[0].type, "account_access")
        XCTAssertEqual(response.authorizationDetails?[1].type, "data_access")
    }

    func testCustomTypesValidation() async throws {
        let request = Request(application: app, on: app.eventLoopGroup.next())
        request.headers.contentType = .json

        let validationRequest = RARValidationRequest(
            authorizationDetails: """
                [
                    {
                        "type": "document_access",
                        "actions": ["read", "download"],
                        "locations": ["https://api.example.com/documents"],
                        "data": {
                            "documentId": "12345",
                            "maxSize": "10MB"
                        }
                    }
                ]
                """
        )

        try request.content.encode(validationRequest)

        let response = try await customRouteHandler.handleValidationRequest(request)

        XCTAssertTrue(response.valid)
        XCTAssertTrue(response.errors.isEmpty)
        XCTAssertNotNil(response.authorizationDetails)
        XCTAssertEqual(response.authorizationDetails?.count, 1)
        XCTAssertEqual(response.authorizationDetails?[0].type, "document_access")
        XCTAssertEqual(response.authorizationDetails?[0].actions, ["read", "download"])
    }

    func testInvalidJSONFormat() async throws {
        let request = Request(application: app, on: app.eventLoopGroup.next())
        request.headers.contentType = .json

        let validationRequest = RARValidationRequest(
            authorizationDetails: """
                [
                    {
                        "type": "account_access",
                        "actions": ["read"
                    }
                ]
                """
        )

        try request.content.encode(validationRequest)

        let response = try await routeHandler.handleValidationRequest(request)

        XCTAssertFalse(response.valid)
        XCTAssertFalse(response.errors.isEmpty)
        XCTAssertNil(response.authorizationDetails)
        XCTAssertTrue(response.errors[0].contains("Invalid JSON format"))
    }

    func testEmptyAuthorizationDetails() async throws {
        let request = Request(application: app, on: app.eventLoopGroup.next())
        request.headers.contentType = .json

        let validationRequest = RARValidationRequest(
            authorizationDetails: "[]"
        )

        try request.content.encode(validationRequest)

        let response = try await routeHandler.handleValidationRequest(request)

        XCTAssertTrue(response.valid)
        XCTAssertTrue(response.errors.isEmpty)
        XCTAssertNotNil(response.authorizationDetails)
        XCTAssertEqual(response.authorizationDetails?.count, 0)
    }

    func testUnexpectedErrorHandling() async throws {
        let request = Request(application: app, on: app.eventLoopGroup.next())
        request.headers.contentType = .json

        // This will cause an encoding error
        let validationRequest = RARValidationRequest(
            authorizationDetails: "invalid json that will cause parsing error"
        )

        try request.content.encode(validationRequest)

        let response = try await routeHandler.handleValidationRequest(request)

        XCTAssertFalse(response.valid)
        XCTAssertFalse(response.errors.isEmpty)
        XCTAssertNil(response.authorizationDetails)
        XCTAssertTrue(response.errors[0].contains("Invalid JSON format"))
    }

    // MARK: - Error Handling Tests

    func testValidationRequestDecodingError() async throws {
        let request = Request(application: app, on: app.eventLoopGroup.next())
        request.headers.contentType = .json

        // Send invalid JSON that can't be decoded as RARValidationRequest
        let invalidData = ["invalid": "json"]
        try request.content.encode(invalidData)

        // This should throw an error during decoding
        do {
            _ = try await routeHandler.handleValidationRequest(request)
            XCTFail("Expected error to be thrown")
        } catch {
            // Expected error
        }
    }

    func testEmptyRequest() async throws {
        let request = Request(application: app, on: app.eventLoopGroup.next())
        request.headers.contentType = .json

        // Send empty body
        let validationRequest = RARValidationRequest(authorizationDetails: "")
        try request.content.encode(validationRequest)

        let response = try await routeHandler.handleValidationRequest(request)

        XCTAssertFalse(response.valid)
        XCTAssertFalse(response.errors.isEmpty)
        XCTAssertNil(response.authorizationDetails)
        XCTAssertTrue(response.errors[0].contains("Invalid JSON format"))
    }
}

// MARK: - Content Conformance

extension RARValidationRequest: Content {
    public static var defaultContentType: HTTPMediaType {
        .json
    }
}
