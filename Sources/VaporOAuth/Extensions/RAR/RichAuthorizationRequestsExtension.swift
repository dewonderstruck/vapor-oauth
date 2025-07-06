import Foundation
import Vapor

/// OAuth 2.0 Rich Authorization Requests (RAR) extension.
///
/// Implements [RFC 9396: OAuth 2.0 Rich Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9396), enabling clients to request fine-grained permissions using the `authorization_details` parameter in OAuth 2.0 flows.
///
/// ## Features
///
/// - **Authorization Details**: Accepts a JSON array of objects, each describing a requested permission.
/// - **Validation**: Enforces RFC 9396 rules (required fields, allowed types/actions, URI validation, etc.).
/// - **Metadata**: Discovery endpoint for supported types/actions and configuration.
/// - **Extensible**: Supports custom types/actions via configuration.
/// - **Error Handling**: Returns detailed errors per RFC 9396 and OAuth 2.0 error standards.
/// - **Logging**: Info, warning, and error logs for all major operations.
///
/// ## Usage
///
/// 1. Register the extension with your `OAuthExtensionManager`.
/// 2. Optionally configure allowed types, actions, and validation rules.
/// 3. Add the extension to your OAuth2 server instance.
/// 4. Use the RAR endpoints for metadata and validation.
///
/// ## Example Authorization Detail
///
/// ```json
/// {
///   "type": "payment_initiation",
///   "actions": ["initiate", "status", "cancel"],
///   "locations": ["https://example.com/payments"],
///   "data": {
///     "instructedAmount": {
///       "currency": "EUR",
///       "amount": "123.50"
///     }
///   }
/// }
/// ```
///
/// ## Endpoints
///
/// - `GET /oauth/rar/metadata`: Returns supported types, actions, and configuration.
/// - `POST /oauth/rar/validate`: Validates an `authorization_details` payload.
///
/// ## Developer Guidance
///
/// - Use the builder pattern for constructing authorization details.
/// - Validate all RAR requests using the provided endpoints or extension hooks.
/// - Extend with custom types/actions as needed for your domain.
/// - Review RFC 9396 for security and interoperability considerations.
public struct RichAuthorizationRequestsExtension: OAuthExtension {
    public let extensionID = "rar"
    public let extensionName = "Rich Authorization Requests"
    public let specificationVersion = "RFC 9396"

    public var modifiesAuthorizationRequest: Bool { true }
    public var modifiesTokenRequest: Bool { true }
    public var addsEndpoints: Bool { false }
    public var requiresConfiguration: Bool { false }

    private let validator: RARValidator<DefaultRARTypeRegistry>
    private let routeHandler: RARRouteHandler<DefaultRARTypeRegistry>
    private let logger: Logger

    /// Initialize the RAR extension with optional configuration.
    ///
    /// - Parameter configuration: Configuration for RAR validation and behavior. Defaults to `.default`.
    public init(configuration: RARConfiguration = .default) {
        self.validator = RARValidator(configuration: configuration)
        self.routeHandler = RARRouteHandler(validator: validator)
        self.logger = Logger(label: "rar-extension")
    }

    public func initialize(with oauth2: OAuth2) async throws {
        logger.info("Initializing Rich Authorization Requests extension")
        // No additional initialization required for RAR
    }

    public func processValidatedAuthorizationRequest(_ request: Request, authRequest: AuthorizationRequestObject) async throws
        -> AuthorizationRequestObject?
    {
        // Extract and validate authorization_details parameter
        guard let authorizationDetails = try await validator.extractAuthorizationDetails(from: request) else {
            return nil  // No RAR data present
        }

        logger.debug("Processing RAR authorization request with \(authorizationDetails.count) authorization detail(s)")

        // For now, return the original request since we can't easily modify AuthorizationRequestObject
        // In a real implementation, you might want to extend AuthorizationRequestObject to include RAR data
        // or store the parsed data in request storage for later use
        return nil
    }

    public func processTokenRequest(_ request: Request) async throws -> Request? {
        // Extract authorization_details from form data for token requests
        guard let authorizationDetails = try await validator.extractAuthorizationDetails(from: request) else {
            return nil  // No RAR data present
        }

        logger.debug("Processing RAR token request with \(authorizationDetails.count) authorization detail(s)")

        // For now, return the original request since we can't easily modify Vapor requests
        // In a real implementation, you might want to store the parsed data in request storage
        return request
    }

    public func addRoutes(to app: Application) async throws {
        logger.info("Adding RAR extension routes")

        // RFC 9396 does not define custom endpoints for RAR
        // The extension only adds validation and processing to existing OAuth 2.0 flows
        // Extension metadata and validation are now available through centralized endpoints:
        // - GET /oauth/extensions/metadata
        // - POST /oauth/extensions/validate
    }

    public func validateRequest(_ request: Request) async throws -> [OAuthExtensionError] {
        var errors: [OAuthExtensionError] = []

        // Check for authorization_details parameter
        if let authDetailsString = request.query[OAuthRequestParameters.authorizationDetails]
            ?? request.content[String.self, at: OAuthRequestParameters.authorizationDetails]
        {
            do {
                _ = try validator.parseAndValidateAuthorizationDetails(authDetailsString)
            } catch let error as OAuthExtensionError {
                errors.append(error)
            } catch {
                errors.append(
                    .invalidParameter(
                        OAuthRequestParameters.authorizationDetails, "Invalid authorization_details format: \(error.localizedDescription)"))
            }
        }

        return errors
    }

    public func getMetadata() -> [String: Any] {
        var metadata: [String: Any] = [
            "extension_id": extensionID,
            "extension_name": extensionName,
            "specification_version": specificationVersion,
            "modifies_authorization_request": modifiesAuthorizationRequest,
            "modifies_token_request": modifiesTokenRequest,
            "adds_endpoints": addsEndpoints,
            "requires_configuration": requiresConfiguration,
            "rfc_compliance": "RFC 9396",
            "description":
                "OAuth 2.0 Rich Authorization Requests extension enabling fine-grained permission requests using authorization_details parameter",
        ]

        // Add RAR-specific metadata
        metadata["rar_configuration"] = [
            "allow_custom_types": validator.configuration.allowCustomTypes,
            "max_authorization_details": validator.configuration.maxAuthorizationDetails,
            "validate_uris": validator.configuration.validateURIs,
            "allowed_types": validator.configuration.allowedTypes?.map { $0.rawValue } as Any,
            "allowed_actions": validator.configuration.allowedActions?.map { $0.rawValue } as Any,
        ]

        // Add supported RAR types and actions
        let typeRegistry = DefaultRARTypeRegistry()
        metadata["supported_types"] = typeRegistry.getAllTypes().map { type in
            [
                "type": type.rawValue,
                "description": type.description,
            ]
        }

        metadata["supported_actions"] = typeRegistry.getAllActions().map { action in
            [
                "action": action.rawValue,
                "description": action.description,
            ]
        }

        // Add usage examples
        metadata["usage_examples"] = [
            "authorization_request":
                "GET /oauth/authorize?response_type=code&client_id=client&authorization_details=[{\"type\":\"payment_initiation\",\"actions\":[\"initiate\"]}]",
            "token_request": "POST /oauth/token with form data including authorization_details parameter",
        ]

        // Add validation rules
        metadata["validation_rules"] = [
            "required_fields": ["type"],
            "optional_fields": ["actions", "locations", "data", "custom"],
            "type_validation": "Types must be predefined or allowed if custom types enabled",
            "action_validation": "Actions must be predefined or allowed if custom actions enabled",
            "uri_validation": "Locations must be valid URIs if URI validation enabled",
            "limits": "Number of authorization details must not exceed configured maximum",
        ]

        return metadata
    }
}
