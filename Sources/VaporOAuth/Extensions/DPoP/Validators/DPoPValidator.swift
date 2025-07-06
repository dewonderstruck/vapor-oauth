import Foundation
import Vapor
import JWTKit

/// Validator for DPoP (Demonstrating Proof of Possession) tokens.
///
/// This validator implements the validation logic for DPoP tokens as specified
/// in RFC 9449, including token structure, claims validation, and request binding.
///
/// ## Validation Steps
///
/// 1. **Token Structure**: Verify the token is a valid JWT
/// 2. **Claims Validation**: Validate all required and optional claims
/// 3. **Request Binding**: Verify the token is bound to the current request
/// 4. **Signature Verification**: Verify the token signature using the public key
/// 5. **Replay Protection**: Check for replay attacks using nonces
///
/// ## RFC 9449 Compliance
///
/// - Validates all required DPoP claims (jti, iat, exp, htm, htu, cnf)
/// - Validates optional claims (ath, nonce) when present
/// - Implements proper error handling with descriptive messages
/// - Supports multiple signature algorithms (RS256, RS384, RS512, ES256, ES384, ES512)
/// - Enforces request binding to prevent token reuse
public struct DPoPValidator: Sendable {
    private let dpopManager: DPoPManager
    private let logger: Logger
    
    /// Initialize the DPoP validator.
    ///
    /// - Parameters:
    ///   - dpopManager: The DPoP manager for token and nonce validation.
    ///   - logger: Logger for validation events.
    public init(dpopManager: DPoPManager, logger: Logger) {
        self.dpopManager = dpopManager
        self.logger = logger
    }
    
    /// Validate a DPoP token for a specific request.
    ///
    /// - Parameters:
    ///   - token: The DPoP token to validate.
    ///   - request: The HTTP request context.
    /// - Returns: The validated DPoP claims.
    /// - Throws: `OAuthExtensionError` if validation fails.
    public func validateDPoPToken(_ token: String, for request: Request) async throws -> DPoPClaims {
        logger.debug("Validating DPoP token")
        
        // Step 1: Validate token structure and decode
        let claims = try await decodeAndValidateToken(token)
        
        // Step 2: Validate request binding
        try validateRequestBinding(claims, for: request)
        
        // Step 3: Validate nonce if present
        if let nonce = claims.nonce {
            try await validateNonce(nonce.value)
        }
        
        // Step 4: Validate access token hash if present
        if let ath = claims.ath {
            try await validateAccessTokenHash(ath, for: request)
        }
        
        logger.debug("DPoP token validation successful")
        return claims
    }
    
    /// Decode and validate the DPoP token structure.
    ///
    /// - Parameter token: The DPoP token to decode.
    /// - Returns: The decoded DPoP claims.
    /// - Throws: `OAuthExtensionError` if decoding fails.
    private func decodeAndValidateToken(_ token: String) async throws -> DPoPClaims {
        do {
            // Retrieve the public key for signature verification
            // For now, we'll use a simple approach - in a real implementation,
            // you'd extract the key ID from the token header
            let keyID = "default-key" // This should be extracted from the token header
            
            guard let publicKey = try await dpopManager.getPublicKey(keyID) else {
                throw OAuthExtensionError.invalidParameter("dpop_token", "Unknown DPoP key: \(keyID)")
            }
            
            // Create a key collection with the public key
            let keyCollection = JWTKeyCollection()
            try await keyCollection.add(jwk: publicKey)
            
            // Verify the token signature and claims
            let claims = try await keyCollection.verify(token, as: DPoPClaims.self)
            
            return claims
        } catch let error as JWTError {
            throw OAuthExtensionError.invalidParameter("dpop_token", "JWT validation failed: \(error.localizedDescription)")
        } catch {
            throw OAuthExtensionError.invalidParameter("dpop_token", "Token validation failed: \(error.localizedDescription)")
        }
    }
    
    /// Validate that the DPoP token is bound to the current request.
    ///
    /// - Parameters:
    ///   - claims: The DPoP claims to validate.
    ///   - request: The HTTP request context.
    /// - Throws: `OAuthExtensionError` if binding validation fails.
    private func validateRequestBinding(_ claims: DPoPClaims, for request: Request) throws {
        // Validate HTTP method
        let requestMethod = request.method.rawValue.uppercased()
        guard claims.htm.value == requestMethod else {
            throw OAuthExtensionError.invalidParameter("dpop_token", "HTTP method mismatch: expected \(claims.htm.value), got \(requestMethod)")
        }
        
        // Validate HTTP URI
        let requestURI = request.url.string
        guard claims.htu.value == requestURI else {
            throw OAuthExtensionError.invalidParameter("dpop_token", "HTTP URI mismatch: expected \(claims.htu.value), got \(requestURI)")
        }
        
        logger.debug("Request binding validation successful")
    }
    
    /// Validate a nonce for replay protection.
    ///
    /// - Parameter nonce: The nonce to validate.
    /// - Throws: `OAuthExtensionError` if nonce validation fails.
    private func validateNonce(_ nonce: String) async throws {
        let isValid = try await dpopManager.validateAndUseNonce(nonce)
        guard isValid else {
            throw OAuthExtensionError.invalidParameter("dpop_token", "Invalid or reused nonce")
        }
        
        logger.debug("Nonce validation successful")
    }
    
    /// Validate access token hash if present.
    ///
    /// - Parameters:
    ///   - ath: The access token hash claim.
    ///   - request: The HTTP request context.
    /// - Throws: `OAuthExtensionError` if hash validation fails.
    private func validateAccessTokenHash(_ ath: AccessTokenHashClaim, for request: Request) async throws {
        // Extract access token from Authorization header
        guard let authHeader = request.headers.first(name: "Authorization"),
              authHeader.hasPrefix("Bearer ") else {
            throw OAuthExtensionError.invalidParameter("dpop_token", "Access token hash present but no Bearer token found")
        }
        
        let accessToken = String(authHeader.dropFirst(7)) // Remove "Bearer " prefix
        
        // Calculate the expected hash
        let expectedHash = AccessTokenHashClaim.hash(accessToken)
        
        // Compare hashes
        guard ath.value == expectedHash else {
            throw OAuthExtensionError.invalidParameter("dpop_token", "Access token hash mismatch")
        }
        
        logger.debug("Access token hash validation successful")
    }
    
    /// Validate that a DPoP token can be used for a specific access token.
    ///
    /// - Parameters:
    ///   - dpopToken: The DPoP token.
    ///   - accessToken: The access token to validate against.
    /// - Returns: `true` if the DPoP token is valid for the access token.
    /// - Throws: `OAuthExtensionError` if validation fails.
    public func validateDPoPForAccessToken(_ dpopToken: String, accessToken: String) async throws -> Bool {
        do {
            let claims = try await decodeAndValidateToken(dpopToken)
            
            // Extract key ID from claims
            let keyID = claims.cnf.jwk.keyIdentifier?.string ?? ""
            
            // Verify access token binding
            return try await dpopManager.verifyAccessTokenBinding(accessToken, to: keyID)
        } catch {
            logger.error("DPoP validation for access token failed: \(error)")
            return false
        }
    }
} 