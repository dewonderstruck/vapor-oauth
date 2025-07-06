import Foundation
import Vapor

/// Protocol for OAuth 2.0 extensions that can be added to the authorization server.
///
/// This protocol enables modular, RFC-compliant addition of OAuth 2.0 extensions such as:
/// - Rich Authorization Requests (RAR) ([RFC 9396](https://datatracker.ietf.org/doc/html/rfc9396))
/// - Pushed Authorization Requests (PAR) ([RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126))
/// - JWT Secured Authorization Requests (JAR) ([RFC 9101](https://datatracker.ietf.org/doc/html/rfc9101))
/// - And other future extensions
///
/// ## Extension Lifecycle
///
/// 1. **Registration**: Register the extension with the `OAuthExtensionManager`.
/// 2. **Initialization**: Initialize with the OAuth2 server instance.
/// 3. **Processing**: Intercept and process requests at key OAuth flow points.
/// 4. **Validation**: Validate extension-specific parameters.
/// 5. **Route Addition**: Optionally add new endpoints.
///
/// ## RFC Compliance
///
/// Extensions should:
/// - Follow the relevant RFC for their specification.
/// - Validate and handle parameters as required by the RFC.
/// - Return errors using `OAuthExtensionError` with descriptive messages and recovery suggestions.
/// - Provide metadata for discovery endpoints if applicable.
///
/// ## Developer Guidance
///
/// - Implement this protocol for any new OAuth 2.0 extension.
/// - Use the default protocol extension for optional methods.
/// - Document the RFC and version your extension implements.
/// - Use comprehensive logging and error handling.
/// - Ensure your extension is idempotent and secure.
public protocol OAuthExtension: Sendable {
    /// Unique identifier for this extension (e.g., "rar", "par").
    var extensionID: String { get }

    /// Human-readable name for this extension.
    var extensionName: String { get }

    /// Version of the extension specification this implements (e.g., "RFC 9396").
    var specificationVersion: String { get }

    /// Whether this extension modifies the authorization request flow.
    var modifiesAuthorizationRequest: Bool { get }

    /// Whether this extension modifies the token request flow.
    var modifiesTokenRequest: Bool { get }

    /// Whether this extension modifies the token response flow.
    var modifiesTokenResponse: Bool { get }

    /// Whether this extension adds new endpoints.
    var addsEndpoints: Bool { get }

    /// Whether this extension requires configuration before use.
    var requiresConfiguration: Bool { get }

    /// Initialize the extension with the OAuth server configuration.
    ///
    /// - Parameter oauth2: The OAuth 2.0 server instance.
    /// - Throws: Any error that prevents initialization.
    func initialize(with oauth2: OAuth2) async throws

    /// Process an authorization request after validation but before user consent.
    ///
    /// - Parameters:
    ///   - request: The incoming HTTP request.
    ///   - authRequest: The validated authorization request object.
    /// - Returns: Modified authorization request object or nil if unchanged.
    /// - Throws: Any error encountered during processing.
    func processValidatedAuthorizationRequest(_ request: Request, authRequest: AuthorizationRequestObject) async throws
        -> AuthorizationRequestObject?

    /// Process a token request before validation.
    ///
    /// - Parameter request: The incoming HTTP request.
    /// - Returns: Modified request or nil if unchanged.
    /// - Throws: Any error encountered during processing.
    func processTokenRequest(_ request: Request) async throws -> Request?

    /// Process a token response after generation but before sending to client.
    ///
    /// This method allows extensions to modify the token response, such as
    /// changing the token_type from "bearer" to "DPoP" for DPoP extensions.
    ///
    /// - Parameters:
    ///   - request: The original HTTP request.
    ///   - response: The token response to modify.
    /// - Returns: Modified response or nil if unchanged.
    /// - Throws: Any error encountered during processing.
    func processTokenResponse(_ request: Request, response: Response) async throws -> Response?

    /// Add any additional routes required by this extension.
    ///
    /// - Parameter app: The Vapor application instance.
    /// - Throws: Any error encountered during route addition.
    func addRoutes(to app: Application) async throws

    /// Validate extension-specific parameters.
    ///
    /// - Parameter request: The incoming HTTP request.
    /// - Returns: Array of validation errors, empty if valid.
    /// - Throws: Any error encountered during validation.
    func validateRequest(_ request: Request) async throws -> [OAuthExtensionError]

    /// Get extension metadata for discovery endpoints.
    ///
    /// - Returns: Extension metadata dictionary.
    func getMetadata() -> [String: Any]
}

/// Default implementation for OAuthExtension protocol
extension OAuthExtension {
    public var modifiesAuthorizationRequest: Bool { false }
    public var modifiesTokenRequest: Bool { false }
    public var modifiesTokenResponse: Bool { false }
    public var addsEndpoints: Bool { false }
    public var requiresConfiguration: Bool { false }

    public func processValidatedAuthorizationRequest(_ request: Request, authRequest: AuthorizationRequestObject) async throws
        -> AuthorizationRequestObject?
    {
        return nil
    }

    public func processTokenRequest(_ request: Request) async throws -> Request? {
        return nil
    }

    public func processTokenResponse(_ request: Request, response: Response) async throws -> Response? {
        return nil
    }

    public func addRoutes(to app: Application) async throws {
        // Default implementation does nothing
    }

    public func validateRequest(_ request: Request) async throws -> [OAuthExtensionError] {
        return []
    }

    public func getMetadata() -> [String: Any] {
        return [
            "extension_id": extensionID,
            "extension_name": extensionName,
            "specification_version": specificationVersion,
            "modifies_authorization_request": modifiesAuthorizationRequest,
            "modifies_token_request": modifiesTokenRequest,
            "modifies_token_response": modifiesTokenResponse,
            "adds_endpoints": addsEndpoints,
            "requires_configuration": requiresConfiguration,
        ]
    }
}
