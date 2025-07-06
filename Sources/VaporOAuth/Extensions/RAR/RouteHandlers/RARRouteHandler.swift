import Foundation
import Vapor

/// Route handler for Rich Authorization Requests (RAR) extension
public struct RARRouteHandler<Registry: RARTypeRegistry>: Sendable {
    private let validator: RARValidator<Registry>
    private let logger: Logger

    public init(validator: RARValidator<Registry>, logger: Logger = Logger(label: "rar-route-handler")) {
        self.validator = validator
        self.logger = logger
    }

    /// Handle RAR metadata endpoint
    /// - Parameter request: The incoming HTTP request
    /// - Returns: RAR metadata response
    public func handleMetadataRequest(_ request: Request) async throws -> RARMetadataResponse {
        logger.info("Handling RAR metadata request")

        return RARMetadataResponse(
            supportedTypes: Registry.RegistryType.allCases.map { $0.rawValue },
            supportedActions: Registry.RegistryAction.allCases.map { $0.rawValue },
            maxAuthorizationDetails: validator.configuration.maxAuthorizationDetails,
            allowCustomTypes: validator.configuration.allowCustomTypes
        )
    }

    /// Handle RAR validation endpoint
    /// - Parameter request: The incoming HTTP request
    /// - Returns: Validation response
    public func handleValidationRequest(_ request: Request) async throws -> RARValidationResponse {
        logger.info("Handling RAR validation request")

        // Extract authorization details from request body
        let validationRequest = try request.content.decode(RARValidationRequest.self)

        do {
            // Parse and validate the authorization details
            let authorizationDetails = try validator.parseAndValidateAuthorizationDetails(validationRequest.authorizationDetails)

            logger.info("RAR validation successful for \(authorizationDetails.count) authorization detail(s)")

            return RARValidationResponse(
                valid: true,
                errors: [],
                authorizationDetails: authorizationDetails
            )
        } catch let error as OAuthExtensionError {
            logger.warning("RAR validation failed: \(error.localizedDescription)")

            return RARValidationResponse(
                valid: false,
                errors: [error.localizedDescription],
                authorizationDetails: nil
            )
        } catch {
            logger.error("Unexpected error during RAR validation: \(error)")

            return RARValidationResponse(
                valid: false,
                errors: ["Unexpected error: \(error.localizedDescription)"],
                authorizationDetails: nil
            )
        }
    }
}

// MARK: - Request/Response Models

/// Request model for RAR validation
public struct RARValidationRequest: Codable, Sendable {
    /// The authorization_details parameter as a JSON string
    public let authorizationDetails: String

    public init(authorizationDetails: String) {
        self.authorizationDetails = authorizationDetails
    }
}

/// Response model for RAR validation
public struct RARValidationResponse: Codable, Sendable, AsyncResponseEncodable {
    /// Whether the authorization details are valid
    public let valid: Bool

    /// Array of validation errors (empty if valid)
    public let errors: [String]

    /// Parsed authorization details (nil if invalid)
    public let authorizationDetails: [AuthorizationDetail]?

    public init(valid: Bool, errors: [String], authorizationDetails: [AuthorizationDetail]?) {
        self.valid = valid
        self.errors = errors
        self.authorizationDetails = authorizationDetails
    }

    public func encodeResponse(for request: Request) async throws -> Response {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        let data = try encoder.encode(self)
        let response = Response(body: .init(data: data))
        response.headers.replaceOrAdd(name: .contentType, value: "application/json")
        return response
    }
}

/// Response model for RAR metadata
public struct RARMetadataResponse: Codable, Sendable, AsyncResponseEncodable {
    /// Supported RAR types
    public let supportedTypes: [String]

    /// Supported RAR actions
    public let supportedActions: [String]

    /// Maximum number of authorization details allowed per request
    public let maxAuthorizationDetails: Int

    /// Whether custom types are allowed
    public let allowCustomTypes: Bool

    /// RFC 9396 specification version
    public var specificationVersion: String { "RFC 9396" }

    public init(
        supportedTypes: [String],
        supportedActions: [String],
        maxAuthorizationDetails: Int,
        allowCustomTypes: Bool
    ) {
        self.supportedTypes = supportedTypes
        self.supportedActions = supportedActions
        self.maxAuthorizationDetails = maxAuthorizationDetails
        self.allowCustomTypes = allowCustomTypes
    }

    public func encodeResponse(for request: Request) async throws -> Response {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        let data = try encoder.encode(self)
        let response = Response(body: .init(data: data))
        response.headers.replaceOrAdd(name: .contentType, value: "application/json")
        return response
    }
}
