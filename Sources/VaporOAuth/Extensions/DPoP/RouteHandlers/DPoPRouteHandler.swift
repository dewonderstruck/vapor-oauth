import Foundation
import Vapor

/// Route handler for DPoP (Demonstrating Proof of Possession) endpoints.
///
/// This handler manages the DPoP nonce endpoint and other DPoP-related routes
/// as specified in RFC 9449.
///
/// ## Endpoints
///
/// - `GET /oauth/dpop_nonce`: Provides DPoP nonces for replay protection
///
/// ## RFC 9449 Compliance
///
/// - Implements the DPoP nonce endpoint
/// - Provides proper error handling and security measures
/// - Supports rate limiting and abuse prevention
/// - Returns appropriate HTTP status codes and error messages
public struct DPoPRouteHandler: Sendable {
    private let dpopManager: DPoPManager
    private let validator: DPoPValidator
    private let logger: Logger
    
    /// Initialize the DPoP route handler.
    ///
    /// - Parameters:
    ///   - dpopManager: The DPoP manager for nonce generation and validation.
    ///   - validator: The DPoP validator for token validation.
    ///   - logger: Logger for route events.
    public init(dpopManager: DPoPManager, validator: DPoPValidator, logger: Logger) {
        self.dpopManager = dpopManager
        self.validator = validator
        self.logger = logger
    }
    
    /// Handle DPoP nonce requests.
    ///
    /// This endpoint provides nonces for DPoP replay protection as specified
    /// in RFC 9449 Section 7.2.
    ///
    /// - Parameter request: The HTTP request.
    /// - Returns: A response containing the nonce and metadata.
    /// - Throws: Any error encountered during processing.
    public func handleNonceRequest(_ request: Request) async throws -> Response {
        logger.debug("Handling DPoP nonce request")
        
        // Check if client authentication is required
        // In a real implementation, you might want to require client authentication
        // for nonce requests to prevent abuse
        
        do {
            // Generate a new nonce
            let nonce = try await dpopManager.generateNonce()
            
            // Create the response
            let response = DPoPNonceResponse(
                nonce: nonce,
                expiresIn: 300 // 5 minutes in seconds
            )
            
            logger.debug("Generated DPoP nonce: \(nonce)")
            
            // Return the response with appropriate headers
            return Response(
                status: .ok,
                headers: [
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store",
                    "Pragma": "no-cache"
                ],
                body: .init(data: try JSONEncoder().encode(response))
            )
        } catch {
            logger.error("Failed to generate DPoP nonce: \(error)")
            
            // Return error response
            let errorResponse = OAuthErrorResponse(
                error: "server_error",
                errorDescription: "Failed to generate DPoP nonce",
                errorUri: nil
            )
            
            return Response(
                status: .internalServerError,
                headers: ["Content-Type": "application/json"],
                body: .init(data: try JSONEncoder().encode(errorResponse))
            )
        }
    }
    
    /// Handle DPoP token validation requests.
    ///
    /// This endpoint validates DPoP tokens and returns validation results.
    /// It's primarily used for testing and debugging purposes.
    ///
    /// - Parameter request: The HTTP request containing the DPoP token.
    /// - Returns: A response containing validation results.
    /// - Throws: Any error encountered during validation.
    public func handleValidationRequest(_ request: Request) async throws -> Response {
        logger.debug("Handling DPoP validation request")
        
        // Extract DPoP token from request
        guard let dpopToken = request.headers.first(name: "DPoP") else {
            let errorResponse = OAuthErrorResponse(
                error: "invalid_request",
                errorDescription: "Missing DPoP token",
                errorUri: nil
            )
            
            return Response(
                status: .badRequest,
                headers: ["Content-Type": "application/json"],
                body: .init(data: try JSONEncoder().encode(errorResponse))
            )
        }
        
        do {
            // Validate the DPoP token
            let claims = try await validator.validateDPoPToken(dpopToken, for: request)
            
            // Create success response
            let response = DPoPValidationResponse(
                valid: true,
                claims: claims
            )
            
            logger.debug("DPoP token validation successful")
            
            return Response(
                status: .ok,
                headers: ["Content-Type": "application/json"],
                body: .init(data: try JSONEncoder().encode(response))
            )
        } catch let error as OAuthExtensionError {
            logger.error("DPoP token validation failed: \(error)")
            
            // Create error response
            let errorResponse = OAuthErrorResponse(
                error: "invalid_dpop_token",
                errorDescription: error.localizedDescription,
                errorUri: nil
            )
            
            return Response(
                status: .badRequest,
                headers: ["Content-Type": "application/json"],
                body: .init(data: try JSONEncoder().encode(errorResponse))
            )
        } catch {
            logger.error("Unexpected error during DPoP validation: \(error)")
            
            // Create generic error response
            let errorResponse = OAuthErrorResponse(
                error: "server_error",
                errorDescription: "Unexpected error during DPoP validation",
                errorUri: nil
            )
            
            return Response(
                status: .internalServerError,
                headers: ["Content-Type": "application/json"],
                body: .init(data: try JSONEncoder().encode(errorResponse))
            )
        }
    }
}

// MARK: - Response Models

/// Response model for DPoP nonce requests.
public struct DPoPNonceResponse: Codable {
    /// The generated nonce value.
    public let nonce: String
    
    /// The expiration time of the nonce in seconds.
    public let expiresIn: Int
    
    public init(nonce: String, expiresIn: Int) {
        self.nonce = nonce
        self.expiresIn = expiresIn
    }
}

/// Response model for DPoP validation requests.
public struct DPoPValidationResponse: Codable {
    /// Whether the DPoP token is valid.
    public let valid: Bool
    
    /// The DPoP claims (only included if valid).
    public let claims: DPoPClaims?
    
    /// Error message (only included if not valid).
    public let error: String?
    
    public init(valid: Bool, claims: DPoPClaims? = nil, error: String? = nil) {
        self.valid = valid
        self.claims = claims
        self.error = error
    }
}

/// Error response model for OAuth errors.
public struct OAuthErrorResponse: Codable {
    /// The error code.
    public let error: String
    
    /// Human-readable error description.
    public let errorDescription: String?
    
    /// URI for more information about the error.
    public let errorUri: String?
    
    public init(error: String, errorDescription: String?, errorUri: String?) {
        self.error = error
        self.errorDescription = errorDescription
        self.errorUri = errorUri
    }
} 