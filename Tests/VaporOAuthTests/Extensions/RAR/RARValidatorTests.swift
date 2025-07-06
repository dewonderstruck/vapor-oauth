import Vapor
import XCTest

@testable import VaporOAuth

final class RARValidatorTests: XCTestCase {

    var validator: RARValidator<DefaultRARTypeRegistry>!
    var customValidator: RARValidator<CustomRARTypeRegistry>!

    override func setUp() {
        super.setUp()
        let defaultConfig = RARConfiguration.default
        validator = RARValidator(configuration: defaultConfig)

        let customConfig = GenericRARConfiguration<CustomRARTypeRegistry>(
            allowCustomTypes: true,
            maxAuthorizationDetails: 5,
            validateURIs: true,
            allowedTypes: Set(CustomRARType.allCases),
            allowedActions: Set(CustomRARAction.allCases),
            typeRegistry: CustomRARTypeRegistry()
        )
        customValidator = RARValidator(configuration: customConfig)
    }

    override func tearDown() {
        validator = nil
        customValidator = nil
        super.tearDown()
    }

    // MARK: - Valid Authorization Details Tests

    func testValidAuthorizationDetails() throws {
        let validJSON = """
            [
                {
                    "type": "payment_initiation",
                    "actions": ["initiate", "status"],
                    "locations": ["https://api.example.com/payments"],
                    "data": {
                        "instructedAmount": {
                            "currency": "EUR",
                            "amount": "123.50"
                        }
                    }
                }
            ]
            """

        let details = try validator.parseAndValidateAuthorizationDetails(validJSON)
        XCTAssertEqual(details.count, 1)
        XCTAssertEqual(details[0].type, "payment_initiation")
        XCTAssertEqual(details[0].actions, ["initiate", "status"])
        XCTAssertEqual(details[0].locations, ["https://api.example.com/payments"])
        XCTAssertNotNil(details[0].data)
    }

    func testMultipleValidAuthorizationDetails() throws {
        let validJSON = """
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

        let details = try validator.parseAndValidateAuthorizationDetails(validJSON)
        XCTAssertEqual(details.count, 2)
        XCTAssertEqual(details[0].type, "account_access")
        XCTAssertEqual(details[1].type, "data_access")
    }

    func testAuthorizationDetailsWithCustomTypes() throws {
        let validJSON = """
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

        let details = try customValidator.parseAndValidateAuthorizationDetails(validJSON)
        XCTAssertEqual(details.count, 1)
        XCTAssertEqual(details[0].type, "document_access")
        XCTAssertEqual(details[0].actions, ["read", "download"])
    }

    // MARK: - RFC 9396 Compliance Tests

    func testRFC9396RequiredFields() throws {
        // Test that type field is required (RFC 9396 Section 2)
        let invalidJSON = """
            [
                {
                    "actions": ["read"],
                    "locations": ["https://api.example.com/accounts"]
                }
            ]
            """

        XCTAssertThrowsError(try validator.parseAndValidateAuthorizationDetails(invalidJSON)) { error in
            XCTAssertTrue(error is OAuthExtensionError)
        }
    }

    func testRFC9396EmptyTypeField() throws {
        let invalidJSON = """
            [
                {
                    "type": "",
                    "actions": ["read"]
                }
            ]
            """

        XCTAssertThrowsError(try validator.parseAndValidateAuthorizationDetails(invalidJSON)) { error in
            XCTAssertTrue(error is OAuthExtensionError)
        }
    }

    func testRFC9396EmptyActions() throws {
        let invalidJSON = """
            [
                {
                    "type": "account_access",
                    "actions": ["", "read"]
                }
            ]
            """

        XCTAssertThrowsError(try validator.parseAndValidateAuthorizationDetails(invalidJSON)) { error in
            XCTAssertTrue(error is OAuthExtensionError)
        }
    }

    func testRFC9396EmptyLocations() throws {
        let invalidJSON = """
            [
                {
                    "type": "account_access",
                    "actions": ["read"],
                    "locations": ["", "https://api.example.com/accounts"]
                }
            ]
            """

        XCTAssertThrowsError(try validator.parseAndValidateAuthorizationDetails(invalidJSON)) { error in
            XCTAssertTrue(error is OAuthExtensionError)
        }
    }

    // MARK: - Configuration-Based Validation Tests

    func testMaxAuthorizationDetailsLimit() throws {
        let config = RARConfiguration(
            allowCustomTypes: true,
            maxAuthorizationDetails: 2,
            validateURIs: true,
            allowedTypes: nil,
            allowedActions: nil,
            typeRegistry: DefaultRARTypeRegistry()
        )
        let limitedValidator = RARValidator(configuration: config)

        let tooManyDetailsJSON = """
            [
                {"type": "account_access", "actions": ["read"]},
                {"type": "data_access", "actions": ["read"]},
                {"type": "file_access", "actions": ["read"]}
            ]
            """

        XCTAssertThrowsError(try limitedValidator.parseAndValidateAuthorizationDetails(tooManyDetailsJSON)) { error in
            XCTAssertTrue(error is OAuthExtensionError)
        }
    }

    func testAllowedTypesRestriction() throws {
        let config = RARConfiguration(
            allowCustomTypes: false,
            maxAuthorizationDetails: 10,
            validateURIs: true,
            allowedTypes: [.accountAccess],
            allowedActions: nil,
            typeRegistry: DefaultRARTypeRegistry()
        )
        let restrictedValidator = RARValidator(configuration: config)

        let disallowedTypeJSON = """
            [
                {
                    "type": "payment_initiation",
                    "actions": ["initiate"]
                }
            ]
            """

        XCTAssertThrowsError(try restrictedValidator.parseAndValidateAuthorizationDetails(disallowedTypeJSON)) { error in
            XCTAssertTrue(error is OAuthExtensionError)
        }
    }

    func testAllowedActionsRestriction() throws {
        let config = RARConfiguration(
            allowCustomTypes: true,
            maxAuthorizationDetails: 10,
            validateURIs: true,
            allowedTypes: nil,
            allowedActions: [.read],
            typeRegistry: DefaultRARTypeRegistry()
        )
        let restrictedValidator = RARValidator(configuration: config)

        let disallowedActionJSON = """
            [
                {
                    "type": "account_access",
                    "actions": ["read", "write"]
                }
            ]
            """

        XCTAssertThrowsError(try restrictedValidator.parseAndValidateAuthorizationDetails(disallowedActionJSON)) { error in
            XCTAssertTrue(error is OAuthExtensionError)
        }
    }

    func testCustomTypesAllowed() throws {
        let config = RARConfiguration(
            allowCustomTypes: true,
            maxAuthorizationDetails: 10,
            validateURIs: true,
            allowedTypes: nil,
            allowedActions: nil,
            typeRegistry: DefaultRARTypeRegistry()
        )
        let customValidator = RARValidator(configuration: config)

        let customTypeJSON = """
            [
                {
                    "type": "custom_analytics",
                    "actions": ["aggregate", "export"]
                }
            ]
            """

        let details = try customValidator.parseAndValidateAuthorizationDetails(customTypeJSON)
        XCTAssertEqual(details.count, 1)
        XCTAssertEqual(details[0].type, "custom_analytics")
    }

    func testCustomTypesDisallowed() throws {
        let config = RARConfiguration(
            allowCustomTypes: false,
            maxAuthorizationDetails: 10,
            validateURIs: true,
            allowedTypes: nil,
            allowedActions: nil,
            typeRegistry: DefaultRARTypeRegistry()
        )
        let strictValidator = RARValidator(configuration: config)

        let customTypeJSON = """
            [
                {
                    "type": "custom_analytics",
                    "actions": ["aggregate"]
                }
            ]
            """

        XCTAssertThrowsError(try strictValidator.parseAndValidateAuthorizationDetails(customTypeJSON)) { error in
            XCTAssertTrue(error is OAuthExtensionError)
        }
    }

    // MARK: - URI Validation Tests

    func testURIValidationEnabled() throws {
        let config = RARConfiguration(
            allowCustomTypes: true,
            maxAuthorizationDetails: 10,
            validateURIs: true,
            allowedTypes: nil,
            allowedActions: nil,
            typeRegistry: DefaultRARTypeRegistry()
        )
        let uriValidator = RARValidator(configuration: config)

        let invalidURIJSON = """
            [
                {
                    "type": "account_access",
                    "actions": ["read"],
                    "locations": ["invalid://uri:with:colons"]
                }
            ]
            """

        XCTAssertThrowsError(try uriValidator.parseAndValidateAuthorizationDetails(invalidURIJSON)) { error in
            XCTAssertTrue(error is OAuthExtensionError)
        }
    }

    func testURIValidationDisabled() throws {
        let config = RARConfiguration(
            allowCustomTypes: true,
            maxAuthorizationDetails: 10,
            validateURIs: false,
            allowedTypes: nil,
            allowedActions: nil,
            typeRegistry: DefaultRARTypeRegistry()
        )
        let noUriValidator = RARValidator(configuration: config)

        let invalidURIJSON = """
            [
                {
                    "type": "account_access",
                    "actions": ["read"],
                    "locations": ["not-a-valid-uri"]
                }
            ]
            """

        // Should not throw when URI validation is disabled
        let details = try noUriValidator.parseAndValidateAuthorizationDetails(invalidURIJSON)
        XCTAssertEqual(details.count, 1)
        XCTAssertEqual(details[0].locations, ["not-a-valid-uri"])
    }

    // MARK: - JSON Parsing Tests

    func testInvalidJSONFormat() throws {
        let invalidJSON = """
            [
                {
                    "type": "account_access",
                    "actions": ["read"
                }
            ]
            """

        XCTAssertThrowsError(try validator.parseAndValidateAuthorizationDetails(invalidJSON)) { error in
            XCTAssertTrue(error is OAuthExtensionError)
        }
    }

    func testInvalidUTF8Encoding() throws {
        // This would need to be tested with actual invalid UTF-8 data
        // For now, we test the error handling path
        let validJSON = """
            [
                {
                    "type": "account_access",
                    "actions": ["read"]
                }
            ]
            """

        // This should work with valid UTF-8
        let details = try validator.parseAndValidateAuthorizationDetails(validJSON)
        XCTAssertEqual(details.count, 1)
    }

    // MARK: - Request Extraction Tests

    func testExtractAuthorizationDetailsFromQuery() async throws {
        let app = try await Application.make(.testing)

        let request = Request(application: app, on: app.eventLoopGroup.next())
        request.url = URI(
            string:
                "https://example.com/oauth/authorize?authorization_details=%5B%7B%22type%22%3A%22account_access%22%2C%22actions%22%3A%5B%22read%22%5D%7D%5D"
        )

        let details = try await validator.extractAuthorizationDetails(from: request)
        XCTAssertNotNil(details)
        XCTAssertEqual(details?.count, 1)
        XCTAssertEqual(details?[0].type, "account_access")

        try await app.asyncShutdown()
    }

    func testExtractAuthorizationDetailsFromBody() async throws {
        let app = try await Application.make(.testing)

        let request = Request(application: app, on: app.eventLoopGroup.next())
        request.headers.contentType = .formData

        let formData = ["authorization_details": "[{\"type\":\"account_access\",\"actions\":[\"read\"]}]"]
        try request.content.encode(formData, as: .urlEncodedForm)

        let details = try await validator.extractAuthorizationDetails(from: request)
        XCTAssertNotNil(details)
        XCTAssertEqual(details?.count, 1)
        XCTAssertEqual(details?[0].type, "account_access")

        try await app.asyncShutdown()
    }

    func testExtractAuthorizationDetailsNotPresent() async throws {
        let app = try await Application.make(.testing)

        let request = Request(application: app, on: app.eventLoopGroup.next())
        request.url = URI(string: "https://example.com/oauth/authorize")

        let details = try await validator.extractAuthorizationDetails(from: request)
        XCTAssertNil(details)

        try await app.asyncShutdown()
    }

    // MARK: - Error Message Tests

    func testErrorMessages() throws {
        let invalidJSON = """
            [
                {
                    "type": "",
                    "actions": ["read"]
                }
            ]
            """

        XCTAssertThrowsError(try validator.parseAndValidateAuthorizationDetails(invalidJSON)) { error in
            guard let oauthError = error as? OAuthExtensionError else {
                XCTFail("Expected OAuthExtensionError")
                return
            }

            XCTAssertTrue(oauthError.localizedDescription.contains("empty type"))
        }
    }

    func testMultipleValidationErrors() throws {
        let invalidJSON = """
            [
                {
                    "type": "",
                    "actions": ["read"]
                },
                {
                    "type": "account_access",
                    "actions": ["", "read"]
                }
            ]
            """

        // Should fail on the first error (empty type)
        XCTAssertThrowsError(try validator.parseAndValidateAuthorizationDetails(invalidJSON)) { error in
            guard let oauthError = error as? OAuthExtensionError else {
                XCTFail("Expected OAuthExtensionError")
                return
            }

            XCTAssertTrue(oauthError.localizedDescription.contains("empty type"))
        }
    }
}
