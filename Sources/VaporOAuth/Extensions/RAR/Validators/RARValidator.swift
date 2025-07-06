import Foundation
import Vapor

/// Validator for Rich Authorization Requests (RAR) according to [RFC 9396](https://datatracker.ietf.org/doc/html/rfc9396).
///
/// Parses and validates the `authorization_details` parameter for OAuth 2.0 requests.
/// Enforces all RFC 9396 requirements: required fields, allowed types/actions, URI validation, and limits.
/// Supports custom type registries and configuration for extensibility.
/// Returns detailed errors using `OAuthExtensionError` for all validation failures.
///
/// ## Validation Rules (per RFC 9396)
///
/// - Each authorization detail **MUST** have a non-empty `type` field.
/// - If custom types are not allowed, only predefined types are accepted.
/// - If allowed types/actions are specified, only those are accepted.
/// - Actions and locations arrays must not contain empty values.
/// - If URI validation is enabled, all locations must be valid URIs.
/// - The number of authorization details must not exceed the configured maximum.
///
/// ## Developer Guidance
///
/// - Use this validator in your RAR extension or custom extensions for robust, RFC-compliant validation.
/// - Extend the type registry for domain-specific types/actions.
/// - Log validation errors for security and auditability.
public struct RARValidator<Registry: RARTypeRegistry>: Sendable {
    internal let configuration: GenericRARConfiguration<Registry>
    private let logger: Logger

    /// Initialize the RAR validator with configuration and optional logger.
    ///
    /// - Parameters:
    ///   - configuration: Configuration for validation rules and behavior.
    ///   - logger: Logger instance for validation events. Defaults to a new logger with label "rar-validator".
    public init(configuration: GenericRARConfiguration<Registry>, logger: Logger = Logger(label: "rar-validator")) {
        self.configuration = configuration
        self.logger = logger
    }

    /// Parse and validate authorization details from a JSON string.
    ///
    /// - Parameter jsonString: The JSON string containing authorization details.
    /// - Returns: Parsed authorization details.
    /// - Throws: `OAuthExtensionError` if validation fails.
    public func parseAndValidateAuthorizationDetails(_ jsonString: String) throws -> [AuthorizationDetail] {
        // Parse the JSON string
        let authorizationDetails = try parseAuthorizationDetails(jsonString)

        // Validate the parsed details
        try validateAuthorizationDetails(authorizationDetails)

        return authorizationDetails
    }

    /// Parse authorization details from a JSON string.
    ///
    /// - Parameter jsonString: The JSON string to parse.
    /// - Returns: Parsed authorization details.
    /// - Throws: `OAuthExtensionError` if parsing fails.
    private func parseAuthorizationDetails(_ jsonString: String) throws -> [AuthorizationDetail] {
        guard let data = jsonString.data(using: .utf8) else {
            throw OAuthExtensionError.invalidParameter(OAuthRequestParameters.authorizationDetails, "Invalid UTF-8 encoding")
        }

        let decoder = JSONDecoder()
        do {
            return try decoder.decode([AuthorizationDetail].self, from: data)
        } catch {
            logger.error("Failed to parse authorization_details JSON: \(error)")
            throw OAuthExtensionError.invalidParameter(
                OAuthRequestParameters.authorizationDetails, "Invalid JSON format: \(error.localizedDescription)")
        }
    }

    /// Validate authorization details according to RFC 9396.
    ///
    /// - Parameter details: The authorization details to validate.
    /// - Throws: `OAuthExtensionError` if validation fails.
    public func validateAuthorizationDetails(_ details: [AuthorizationDetail]) throws {
        // Check maximum number of authorization details
        if details.count > configuration.maxAuthorizationDetails {
            throw OAuthExtensionError.invalidParameter(
                OAuthRequestParameters.authorizationDetails,
                "Too many authorization details. Maximum allowed: \(configuration.maxAuthorizationDetails), provided: \(details.count)"
            )
        }

        // Validate each authorization detail
        for (index, detail) in details.enumerated() {
            try validateAuthorizationDetail(detail, at: index)
        }
    }

    /// Validate a single authorization detail.
    ///
    /// - Parameters:
    ///   - detail: The authorization detail to validate.
    ///   - index: The index of the detail in the array.
    /// - Throws: `OAuthExtensionError` if validation fails.
    private func validateAuthorizationDetail(_ detail: AuthorizationDetail, at index: Int) throws {
        // RFC 9396 Section 2: Each authorization detail MUST have a "type" field
        if detail.type.isEmpty {
            throw OAuthExtensionError.invalidParameter(
                OAuthRequestParameters.authorizationDetails,
                "Authorization detail at index \(index) has empty type"
            )
        }

        // Check if this is a predefined type
        let rarType = Registry.RegistryType(rawValue: detail.type)

        // If custom types are not allowed and this is not a predefined type, reject it
        if !configuration.allowCustomTypes && rarType == nil {
            throw OAuthExtensionError.invalidParameter(
                OAuthRequestParameters.authorizationDetails,
                "Authorization detail at index \(index) has unsupported type: \(detail.type)"
            )
        }

        // Validate type if configuration restricts it to specific allowed types
        if let allowedTypes = configuration.allowedTypes {
            if let rarType = rarType, !allowedTypes.contains(rarType) {
                throw OAuthExtensionError.invalidParameter(
                    OAuthRequestParameters.authorizationDetails,
                    "Authorization detail at index \(index) has disallowed type: \(detail.type)"
                )
            }
        }

        // Validate actions if present
        if let actions = detail.actions {
            try validateActions(actions, at: index)
        }

        // Validate locations if present
        if let locations = detail.locations {
            try validateLocations(locations, at: index)
        }
    }

    /// Validate actions array.
    ///
    /// - Parameters:
    ///   - actions: The actions to validate.
    ///   - index: The index of the authorization detail.
    /// - Throws: `OAuthExtensionError` if validation fails.
    private func validateActions(_ actions: [String], at index: Int) throws {
        // Check for empty actions
        for (actionIndex, action) in actions.enumerated() {
            if action.isEmpty {
                throw OAuthExtensionError.invalidParameter(
                    OAuthRequestParameters.authorizationDetails,
                    "Authorization detail at index \(index) has empty action at position \(actionIndex)"
                )
            }
        }

        // Validate actions if configuration restricts them
        if let allowedActions = configuration.allowedActions {
            for action in actions {
                let rarAction = Registry.RegistryAction(rawValue: action)
                if rarAction == nil || !allowedActions.contains(rarAction!) {
                    throw OAuthExtensionError.invalidParameter(
                        OAuthRequestParameters.authorizationDetails,
                        "Authorization detail at index \(index) has disallowed action: \(action)"
                    )
                }
            }
        }
    }

    /// Validate locations array.
    ///
    /// - Parameters:
    ///   - locations: The locations to validate.
    ///   - index: The index of the authorization detail.
    /// - Throws: `OAuthExtensionError` if validation fails.
    private func validateLocations(_ locations: [String], at index: Int) throws {
        // Check for empty locations
        for (locationIndex, location) in locations.enumerated() {
            if location.isEmpty {
                throw OAuthExtensionError.invalidParameter(
                    OAuthRequestParameters.authorizationDetails,
                    "Authorization detail at index \(index) has empty location at position \(locationIndex)"
                )
            }
        }

        // Validate URI format if configuration requires it
        if configuration.validateURIs {
            for (locationIndex, location) in locations.enumerated() {
                guard URL(string: location) != nil else {
                    throw OAuthExtensionError.invalidParameter(
                        OAuthRequestParameters.authorizationDetails,
                        "Authorization detail at index \(index) has invalid location URI at position \(locationIndex): \(location)"
                    )
                }
            }
        }
    }

    /// Extract authorization details from a Vapor request.
    ///
    /// - Parameter request: The Vapor request.
    /// - Returns: Parsed authorization details if present, nil otherwise.
    /// - Throws: `OAuthExtensionError` if validation fails.
    public func extractAuthorizationDetails(from request: Request) async throws -> [AuthorizationDetail]? {
        // Try to get authorization_details from query parameters first
        let authorizationDetailsString =
            request.query[OAuthRequestParameters.authorizationDetails]
            ?? request.content[String.self, at: OAuthRequestParameters.authorizationDetails]

        guard let authDetailsString = authorizationDetailsString else {
            return nil  // No RAR data present
        }

        // Parse and validate the authorization_details
        return try parseAndValidateAuthorizationDetails(authDetailsString)
    }
}
