import Foundation
import Vapor
import JWTKit

/// OAuth 2.0 Demonstrating Proof of Possession (DPoP) extension.
///
/// Implements [RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449), enabling clients to demonstrate proof of possession of a private key when accessing protected resources.
///
/// ## Features
///
/// - **Proof of Possession**: Clients demonstrate possession of private keys through DPoP tokens
/// - **Binding to HTTP Request**: DPoP tokens are bound to specific HTTP methods and URIs
/// - **Replay Protection**: DPoP tokens include nonce and timestamp to prevent replay attacks
/// - **Key Rotation**: Supports multiple DPoP keys with automatic rotation
/// - **Comprehensive Validation**: Validates DPoP tokens according to RFC 9449 specifications
/// - **Access Token Binding**: Binds access tokens to DPoP keys for enhanced security
///
/// ## RFC 9449 Compliance
///
/// - Implements DPoP token validation and verification
/// - Supports DPoP nonce management
/// - Validates DPoP token claims (jti, iat, exp, htu, htm, ath)
/// - Implements access token binding to DPoP keys
/// - Supports DPoP key rotation and management
/// - Provides proper error handling and security measures
///
/// ## Usage
///
/// 1. Register the extension with your `OAuthExtensionManager`.
/// 2. Configure the DPoP manager for token validation and nonce management.
/// 3. Add the extension to your OAuth2 server instance.
/// 4. Clients include DPoP tokens in Authorization headers.
///
/// ## Example Flow
///
/// 1. Client creates DPoP token and includes it in request:
///    ```
///    POST /oauth/token
///    Authorization: DPoP <dpop_token>
///    Content-Type: application/x-www-form-urlencoded
///
///    grant_type=authorization_code&code=abc123&client_id=client
///    ```
///
/// 2. Server validates DPoP token and binds access token:
///    ```json
///    {
///      "access_token": "eyJ...",
///      "token_type": "DPoP",
///      "expires_in": 3600,
///      "dpop_nonce": "nonce123"
///    }
///    ```
///
/// 3. Client uses access token with DPoP proof:
///    ```
///    GET /api/protected
///    Authorization: DPoP <access_token>
///    DPoP: <dpop_proof_token>
///    ```
///
/// ## Endpoints
///
/// - `POST /oauth/token`: Accepts DPoP tokens in Authorization header
/// - `GET /oauth/dpop_nonce`: Provides DPoP nonce for replay protection
///
/// ## Developer Guidance
///
/// - Use the DPoP manager for token validation and nonce management
/// - Implement proper key rotation and management
/// - Apply rate limiting to prevent abuse
/// - Log all DPoP operations for audit purposes
/// - Review RFC 9449 for security and interoperability considerations
public struct DemonstratingProofOfPossessionExtension: OAuthExtension {
    public let extensionID = "dpop"
    public let extensionName = "Demonstrating Proof of Possession"
    public let specificationVersion = "RFC 9449"

    public var modifiesAuthorizationRequest: Bool { false }
    public var modifiesTokenRequest: Bool { true }
    public var addsEndpoints: Bool { true }
    public var requiresConfiguration: Bool { false }
    public var modifiesTokenResponse: Bool { true }

    private let dpopManager: DPoPManager
    private let validator: DPoPValidator
    private let routeHandler: DPoPRouteHandler
    private let logger: Logger

    /// Initialize the DPoP extension with optional configuration.
    ///
    /// - Parameter dpopManager: Manager for DPoP token validation and nonce management. Defaults to `EmptyDPoPManager`.
    public init(dpopManager: DPoPManager = EmptyDPoPManager()) {
        self.dpopManager = dpopManager

        self.validator = DPoPValidator(
            dpopManager: dpopManager,
            logger: Logger(label: "dpop-validator")
        )
        self.routeHandler = DPoPRouteHandler(
            dpopManager: dpopManager,
            validator: validator,
            logger: Logger(label: "dpop-route-handler")
        )
        self.logger = Logger(label: "dpop-extension")
    }

    public func initialize(with oauth2: OAuth2) async throws {
        logger.info("Initializing Demonstrating Proof of Possession extension")
        
        // Initialize DPoP manager with OAuth2 configuration
        try await dpopManager.initialize(with: oauth2)
    }

    public func processValidatedAuthorizationRequest(_ request: Request, authRequest: AuthorizationRequestObject) async throws
        -> AuthorizationRequestObject?
    {
        // DPoP doesn't modify authorization requests
        return nil
    }

    public func processTokenRequest(_ request: Request) async throws -> Request? {
        // Check if this is a DPoP request (contains DPoP Authorization header)
        guard let dpopToken = request.headers.first(name: "Authorization")?.replacingOccurrences(of: "DPoP ", with: "") else {
            return nil  // Not a DPoP request
        }

        logger.debug("Processing DPoP token request")

        // Validate the DPoP token
        let dpopClaims = try await validator.validateDPoPToken(dpopToken, for: request)
        
        // Store DPoP claims for later use in token generation
        request.storage[DPoPStorageKey.self] = dpopClaims
        
        // Return the modified request with DPoP context
        return request
    }

    public func processTokenResponse(_ request: Request, response: Response) async throws -> Response? {
        // Check if this was a DPoP request by looking for stored DPoP claims
        guard let _ = request.storage[DPoPStorageKey.self] else {
            return nil  // Not a DPoP request, don't modify response
        }

        logger.debug("Processing DPoP token response")

        // Parse the current response
        guard let responseData = response.body.data else {
            logger.error("No response data found")
            return nil
        }

        do {
            // Parse the JSON response
            guard let jsonObject = try JSONSerialization.jsonObject(with: responseData) as? [String: Any] else {
                logger.error("Invalid JSON response")
                return nil
            }

            // Modify the token_type from "bearer" to "DPoP" as required by RFC 9449
            var modifiedJson = jsonObject
            modifiedJson[OAuthResponseParameters.tokenType] = "DPoP"

            // Add DPoP nonce if available
            if let nonce = try? await dpopManager.generateNonce() {
                modifiedJson["dpop_nonce"] = nonce
            }

            // Create new response with modified JSON
            let modifiedData = try JSONSerialization.data(withJSONObject: modifiedJson)
            let modifiedResponse = Response(status: response.status)
            modifiedResponse.body = .init(data: modifiedData)
            modifiedResponse.headers.contentType = .json
            modifiedResponse.headers.replaceOrAdd(name: "pragma", value: "no-cache")
            modifiedResponse.headers.cacheControl = HTTPHeaders.CacheControl(noStore: true)

            logger.debug("Modified token response for DPoP: token_type=DPoP")
            return modifiedResponse

        } catch {
            logger.error("Failed to modify DPoP token response: \(error)")
            return nil
        }
    }

    public func addRoutes(to app: Application) async throws {
        logger.info("Adding DPoP extension routes")

        // Add the DPoP nonce endpoint as defined in RFC 9449
        app.get("oauth", "dpop_nonce") { request in
            return try await self.routeHandler.handleNonceRequest(request)
        }
    }

    public func validateRequest(_ request: Request) async throws -> [OAuthExtensionError] {
        var errors: [OAuthExtensionError] = []

        // Check for DPoP Authorization header
        if let authHeader = request.headers.first(name: "Authorization"),
           authHeader.hasPrefix("DPoP ") {
            
            let dpopToken = String(authHeader.dropFirst(5)) // Remove "DPoP " prefix
            
            do {
                _ = try await validator.validateDPoPToken(dpopToken, for: request)
            } catch let error as OAuthExtensionError {
                errors.append(error)
            } catch {
                errors.append(
                    .invalidParameter("dpop_token", "Invalid DPoP token: \(error.localizedDescription)")
                )
            }
        }

        return errors
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
            "dpop_nonce_endpoint": "/oauth/dpop_nonce",
            "supported_algorithms": ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
            "max_nonce_age": 300, // 5 minutes in seconds
        ]
    }
}

// MARK: - Storage Keys

private enum DPoPStorageKey: StorageKey {
    typealias Value = DPoPClaims
    case claims
} 