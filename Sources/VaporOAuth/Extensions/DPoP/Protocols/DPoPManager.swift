import Foundation
import Vapor
import JWTKit

/// Protocol for managing DPoP (Demonstrating Proof of Possession) tokens and nonces.
///
/// This protocol defines the interface for DPoP token validation, nonce management,
/// and access token binding as specified in RFC 9449.
///
/// ## Responsibilities
///
/// - **Token Validation**: Validate DPoP tokens and their claims
/// - **Nonce Management**: Generate and validate nonces for replay protection
/// - **Key Management**: Manage DPoP public keys and their rotation
/// - **Access Token Binding**: Bind access tokens to DPoP keys
/// - **Replay Protection**: Prevent replay attacks through token tracking
///
/// ## RFC 9449 Compliance
///
/// - Implements nonce generation and validation
/// - Supports DPoP token validation with proper error handling
/// - Manages access token binding to DPoP keys
/// - Implements proper cleanup of expired tokens and nonces
/// - Provides secure key management and rotation
public protocol DPoPManager: Sendable {
    /// Initialize the DPoP manager with OAuth2 configuration.
    ///
    /// - Parameter oauth2: The OAuth 2.0 server instance.
    /// - Throws: Any error that prevents initialization.
    func initialize(with oauth2: OAuth2) async throws
    
    /// Validate a DPoP token for a specific request.
    ///
    /// - Parameters:
    ///   - token: The DPoP token to validate.
    ///   - request: The HTTP request context.
    /// - Returns: The validated DPoP claims.
    /// - Throws: `OAuthExtensionError` if validation fails.
    func validateToken(_ token: String, for request: Request) async throws -> DPoPClaims
    
    /// Generate a new nonce for replay protection.
    ///
    /// - Returns: A unique nonce string.
    /// - Throws: Any error encountered during nonce generation.
    func generateNonce() async throws -> String
    
    /// Validate a nonce and mark it as used.
    ///
    /// - Parameter nonce: The nonce to validate.
    /// - Returns: `true` if the nonce is valid and unused, `false` otherwise.
    /// - Throws: Any error encountered during validation.
    func validateAndUseNonce(_ nonce: String) async throws -> Bool
    
    /// Bind an access token to a DPoP key.
    ///
    /// - Parameters:
    ///   - accessToken: The access token to bind.
    ///   - dpopKeyID: The DPoP key identifier.
    /// - Throws: Any error encountered during binding.
    func bindAccessToken(_ accessToken: String, to dpopKeyID: String) async throws
    
    /// Verify that an access token is bound to a DPoP key.
    ///
    /// - Parameters:
    ///   - accessToken: The access token to verify.
    ///   - dpopKeyID: The DPoP key identifier.
    /// - Returns: `true` if the access token is bound to the key, `false` otherwise.
    /// - Throws: Any error encountered during verification.
    func verifyAccessTokenBinding(_ accessToken: String, to dpopKeyID: String) async throws -> Bool
    
    /// Store a DPoP public key for validation.
    ///
    /// - Parameters:
    ///   - keyID: The key identifier.
    ///   - jwk: The JSON Web Key.
    ///   - clientID: The client identifier (optional).
    /// - Throws: Any error encountered during storage.
    func storePublicKey(_ jwk: JWK, for keyID: String, clientID: String?) async throws
    
    /// Retrieve a DPoP public key for validation.
    ///
    /// - Parameter keyID: The key identifier.
    /// - Returns: The JSON Web Key if found, `nil` otherwise.
    /// - Throws: Any error encountered during retrieval.
    func getPublicKey(_ keyID: String) async throws -> JWK?
    
    /// Clean up expired tokens and nonces.
    ///
    /// This method should be called periodically to remove expired data.
    /// - Throws: Any error encountered during cleanup.
    func cleanup() async throws
}

/// Empty implementation of DPoPManager for testing and default behavior.
///
/// This implementation provides no-op behavior for all DPoP operations.
/// It's useful for testing or when DPoP functionality is not required.
public struct EmptyDPoPManager: DPoPManager {
    public init() {}
    
    public func initialize(with oauth2: OAuth2) async throws {
        // No initialization required
    }
    
    public func validateToken(_ token: String, for request: Request) async throws -> DPoPClaims {
        throw OAuthExtensionError.invalidParameter("dpop_token", "DPoP validation not implemented")
    }
    
    public func generateNonce() async throws -> String {
        return UUID().uuidString
    }
    
    public func validateAndUseNonce(_ nonce: String) async throws -> Bool {
        return true // Always accept nonces in empty implementation
    }
    
    public func bindAccessToken(_ accessToken: String, to dpopKeyID: String) async throws {
        // No binding in empty implementation
    }
    
    public func verifyAccessTokenBinding(_ accessToken: String, to dpopKeyID: String) async throws -> Bool {
        return true // Always return true in empty implementation
    }
    
    public func storePublicKey(_ jwk: JWK, for keyID: String, clientID: String?) async throws {
        // No storage in empty implementation
    }
    
    public func getPublicKey(_ keyID: String) async throws -> JWK? {
        return nil // No keys in empty implementation
    }
    
    public func cleanup() async throws {
        // No cleanup required
    }
} 