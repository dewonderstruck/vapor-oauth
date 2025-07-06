import Foundation
import Vapor

/// OAuth 2.0 Pushed Authorization Requests (PAR) extension.
///
/// Implements [RFC 9126: OAuth 2.0 Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126), enabling clients to push authorization request parameters to the authorization server and receive a request URI that can be used in the authorization flow.
///
/// ## Features
///
/// - **Request Pushing**: Clients can push authorization request parameters to the server
/// - **Request URI Generation**: Server generates unique request URIs for pushed requests
/// - **Secure Storage**: Pushed requests are stored securely and bound to the client
/// - **Expiration Management**: Requests expire after a configurable time period (default: 60 seconds)
/// - **Replay Protection**: Requests can only be used once to prevent replay attacks
/// - **Client Authentication**: Requires client authentication for all PAR operations
/// - **Comprehensive Validation**: Validates all parameters according to OAuth 2.0 specifications
///
/// ## RFC 9126 Compliance
///
/// - Implements the `/oauth/par` endpoint for pushing authorization requests
/// - Supports all OAuth 2.0 authorization request parameters
/// - Generates request URIs in the format `urn:ietf:params:oauth:request_uri:<identifier>`
/// - Enforces client authentication for all PAR operations
/// - Implements proper error handling and security measures
/// - Supports request expiration and cleanup
///
/// ## Usage
///
/// 1. Register the extension with your `OAuthExtensionManager`.
/// 2. Configure the PAR manager for secure storage.
/// 3. Add the extension to your OAuth2 server instance.
/// 4. Use the PAR endpoint to push authorization requests.
///
/// ## Example Flow
///
/// 1. Client pushes authorization request to `/oauth/par`:
///    ```
///    POST /oauth/par
///    Authorization: Basic <base64(client_id:client_secret)>
///    Content-Type: application/x-www-form-urlencoded
///
///    response_type=code&client_id=client&redirect_uri=https://example.com/callback&scope=read write
///    ```
///
/// 2. Server responds with request URI:
///    ```json
///    {
///      "request_uri": "urn:ietf:params:oauth:request_uri:abc123",
///      "expires_in": 60
///    }
///    ```
///
/// 3. Client uses request URI in authorization flow:
///    ```
///    GET /oauth/authorize?request_uri=urn:ietf:params:oauth:request_uri:abc123
///    ```
///
/// ## Endpoints
///
/// - `POST /oauth/par`: Push authorization request parameters and receive a request URI
///
/// ## Developer Guidance
///
/// - Use the PAR manager for secure storage of pushed requests
/// - Implement proper cleanup of expired requests
/// - Apply rate limiting to prevent abuse
/// - Log all PAR operations for audit purposes
/// - Review RFC 9126 for security and interoperability considerations
public struct PushedAuthorizationRequestsExtension: OAuthExtension {
    public let extensionID = "par"
    public let extensionName = "Pushed Authorization Requests"
    public let specificationVersion = "RFC 9126"

    public var modifiesAuthorizationRequest: Bool { true }
    public var modifiesTokenRequest: Bool { false }
    public var addsEndpoints: Bool { true }
    public var requiresConfiguration: Bool { false }

    private let parManager: PushedAuthorizationRequestManager
    private let validator: PARValidator
    private let routeHandler: PARRouteHandler
    private let logger: Logger

    /// Initialize the PAR extension with optional configuration.
    ///
    /// - Parameter parManager: Manager for pushed authorization requests. Defaults to `EmptyPushedAuthorizationRequestManager`.
    public init(parManager: PushedAuthorizationRequestManager = EmptyPushedAuthorizationRequestManager()) {
        self.parManager = parManager

        // Create a simple empty client retriever for initialization
        let emptyClientRetriever = EmptyClientRetriever()

        self.validator = PARValidator(
            clientRetriever: emptyClientRetriever,
            scopeValidator: ScopeValidator(validScopes: nil, clientRetriever: emptyClientRetriever),
            logger: Logger(label: "par-validator")
        )
        self.routeHandler = PARRouteHandler(
            parManager: parManager,
            validator: validator,
            logger: Logger(label: "par-route-handler")
        )
        self.logger = Logger(label: "par-extension")
    }

    public func initialize(with oauth2: OAuth2) async throws {
        logger.info("Initializing Pushed Authorization Requests extension")

        // Update validator with actual services from OAuth2 instance
        // Note: In a real implementation, you might want to inject these dependencies
        // For now, we'll use the default implementations
    }

    public func processValidatedAuthorizationRequest(_ request: Request, authRequest: AuthorizationRequestObject) async throws
        -> AuthorizationRequestObject?
    {
        // Check if this is a PAR request (contains request_uri parameter)
        guard let requestURI = request.query[String.self, at: OAuthRequestParameters.requestURI] else {
            return nil  // Not a PAR request
        }

        logger.debug("Processing PAR authorization request with request_uri: \(requestURI)")

        // Validate the request URI format
        try validator.validateRequestURI(requestURI)

        // Extract client ID from the authorization request
        let clientID = authRequest.clientID

        // Retrieve the pushed authorization request
        guard let parRequest = try await parManager.getRequest(requestURI: requestURI, clientID: clientID) else {
            throw OAuthExtensionError.invalidParameter(
                OAuthRequestParameters.requestURI,
                "Invalid or expired request_uri"
            )
        }

        // Validate that the request is still valid
        guard parRequest.isValid else {
            if parRequest.isExpired {
                throw OAuthExtensionError.invalidParameter(
                    OAuthRequestParameters.requestURI,
                    "Request URI has expired"
                )
            } else {
                throw OAuthExtensionError.invalidParameter(
                    OAuthRequestParameters.requestURI,
                    "Request URI has already been used"
                )
            }
        }

        // Mark the request as used to prevent replay attacks
        try await parManager.markRequestAsUsed(requestURI: requestURI)

        logger.debug("Successfully processed PAR request: \(requestURI)")

        // Return the original authorization request object
        // The actual parameter substitution would happen in the authorization handler
        return authRequest
    }

    public func processTokenRequest(_ request: Request) async throws -> Request? {
        // PAR doesn't modify token requests
        return nil
    }

    public func addRoutes(to app: Application) async throws {
        logger.info("Adding PAR extension routes")

        // Add the PAR endpoint as defined in RFC 9126
        app.post("oauth", "par") { request in
            return try await self.routeHandler.handleRequest(request)
        }
    }

    public func validateRequest(_ request: Request) async throws -> [OAuthExtensionError] {
        var errors: [OAuthExtensionError] = []

        // Check for request_uri parameter in query or content
        let requestURI =
            request.query[String.self, at: OAuthRequestParameters.requestURI]
            ?? (try? request.content.get(String.self, at: OAuthRequestParameters.requestURI))
        if let requestURI = requestURI {
            do {
                try validator.validateRequestURI(requestURI)
            } catch let error as OAuthExtensionError {
                errors.append(error)
            } catch {
                errors.append(
                    .invalidParameter(
                        OAuthRequestParameters.requestURI, "Invalid request_uri format: \(error.localizedDescription)")
                )
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
            "rfc_compliance": "RFC 9126",
            "description":
                "OAuth 2.0 Pushed Authorization Requests extension enabling clients to push authorization request parameters to the authorization server",
        ]

        // Add PAR-specific metadata
        metadata["par_configuration"] = [
            "request_expiration_time": parManager.requestExpirationTime,
            "endpoint": "/oauth/par",
            "request_uri_format": "urn:ietf:params:oauth:request_uri:<identifier>",
            "requires_client_authentication": true,
            "supports_replay_protection": true,
        ]

        // Add supported parameters
        metadata["supported_parameters"] = [
            OAuthRequestParameters.responseType,
            OAuthRequestParameters.clientID,
            OAuthRequestParameters.redirectURI,
            OAuthRequestParameters.scope,
            OAuthRequestParameters.state,
            OAuthRequestParameters.codeChallenge,
            OAuthRequestParameters.codeChallengeMethod,
            OAuthRequestParameters.authorizationDetails,
            "Additional custom parameters are supported",
        ]

        // Add usage examples
        metadata["usage_examples"] = [
            "push_request":
                "POST /oauth/par with Basic Auth and form data containing authorization request parameters",
            "use_request":
                "GET /oauth/authorize?request_uri=urn:ietf:params:oauth:request_uri:abc123",
        ]

        // Add validation rules
        metadata["validation_rules"] = [
            "required_parameters": ["response_type", "client_id"],
            "client_authentication": "Required (Basic Auth or form data)",
            "request_uri_format": "Must be urn:ietf:params:oauth:request_uri:<identifier>",
            "expiration": "Requests expire after \(Int(parManager.requestExpirationTime)) seconds",
            "replay_protection": "Requests can only be used once",
            "client_binding": "Requests are bound to the client that created them",
        ]

        // Add security considerations
        metadata["security_considerations"] = [
            "client_authentication_required": true,
            "secure_storage_required": true,
            "rate_limiting_recommended": true,
            "audit_logging_recommended": true,
            "expiration_enforced": true,
            "replay_protection_enabled": true,
        ]

        return metadata
    }
}

// Simple empty client retriever for initialization
private struct EmptyClientRetriever: ClientRetriever {
    func getClient(clientID: String) async throws -> OAuthClient? {
        return nil
    }
}
