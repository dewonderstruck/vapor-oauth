import Foundation
import JWTKit
import Crypto

/// DPoP token claims as defined in RFC 9449.
///
/// DPoP tokens are JWTs that contain claims demonstrating proof of possession
/// of a private key. The claims are bound to specific HTTP requests to prevent
/// replay attacks and ensure request integrity.
///
/// ## RFC 9449 Claims
///
/// - `jti`: Unique identifier for the DPoP token
/// - `iat`: Issued at timestamp
/// - `exp`: Expiration timestamp
/// - `htm`: HTTP method (e.g., "GET", "POST")
/// - `htu`: HTTP URI (the target URI)
/// - `ath`: Access token hash (when binding to access tokens)
/// - `cnf`: Confirmation claim containing the public key
///
/// ## Security Considerations
///
/// - DPoP tokens should have short lifetimes (typically 5-10 minutes)
/// - The `jti` claim should be unique to prevent replay attacks
/// - The `htm` and `htu` claims should exactly match the request
/// - The `ath` claim should be present when binding to access tokens
public struct DPoPClaims: JWTPayload {
    /// Unique identifier for the DPoP token (JWT ID).
    /// Must be unique to prevent replay attacks.
    public let jti: String
    
    /// Issued at timestamp.
    /// The time when the DPoP token was created.
    public let iat: IssuedAtClaim
    
    /// Expiration timestamp.
    /// The time when the DPoP token expires.
    public let exp: ExpirationClaim
    
    /// HTTP method claim.
    /// The HTTP method of the request (e.g., "GET", "POST", "PUT").
    public let htm: HTTPMethodClaim
    
    /// HTTP URI claim.
    /// The target URI of the request.
    public let htu: HTTPURIClaim
    
    /// Access token hash claim (optional).
    /// Hash of the access token when binding DPoP to access tokens.
    public let ath: AccessTokenHashClaim?
    
    /// Confirmation claim.
    /// Contains the public key used to sign the DPoP token.
    public let cnf: ConfirmationClaim
    
    /// Nonce claim (optional).
    /// Server-provided nonce for additional replay protection.
    public let nonce: NonceClaim?
    
    public init(
        jti: String,
        iat: IssuedAtClaim,
        exp: ExpirationClaim,
        htm: HTTPMethodClaim,
        htu: HTTPURIClaim,
        ath: AccessTokenHashClaim? = nil,
        cnf: ConfirmationClaim,
        nonce: NonceClaim? = nil
    ) {
        self.jti = jti
        self.iat = iat
        self.exp = exp
        self.htm = htm
        self.htu = htu
        self.ath = ath
        self.cnf = cnf
        self.nonce = nonce
    }
    
    public func verify(using algorithm: some JWTAlgorithm) async throws {
        // Verify expiration
        try exp.verifyNotExpired()
        
        // Verify issued at is not in the future
        if iat.value > Date() {
            throw JWTError.claimVerificationFailure(failedClaim: iat, reason: "Issued at time is in the future")
        }
        
        // Verify HTTP method is valid
        try await htm.verify(using: algorithm)
        
        // Verify HTTP URI is valid
        try await htu.verify(using: algorithm)
        
        // Verify confirmation claim
        try await cnf.verify(using: algorithm)
        
        // Verify nonce if present
        if let nonce = nonce {
            try await nonce.verify(using: algorithm)
        }
    }
}

// MARK: - Custom Claims

/// HTTP method claim for DPoP tokens.
public struct HTTPMethodClaim: JWTPayload {
    public let value: String
    
    public init(_ value: String) {
        self.value = value.uppercased()
    }
    
    public func verify(using algorithm: some JWTAlgorithm) async throws {
        // Validate HTTP method
        let validMethods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
        guard validMethods.contains(value) else {
            throw JWTError.generic(identifier: "htm", reason: "Invalid HTTP method: \(value)")
        }
    }
}

/// HTTP URI claim for DPoP tokens.
public struct HTTPURIClaim: JWTPayload {
    public let value: String
    
    public init(_ value: String) {
        self.value = value
    }
    
    public func verify(using algorithm: some JWTAlgorithm) async throws {
        // Validate URI format
        guard let url = URL(string: value), url.scheme != nil else {
            throw JWTError.generic(identifier: "htu", reason: "Invalid URI format: \(value)")
        }
    }
}

/// Access token hash claim for DPoP tokens.
public struct AccessTokenHashClaim: JWTPayload {
    public let value: String
    
    public init(_ value: String) {
        self.value = value
    }
    
    public func verify(using algorithm: some JWTAlgorithm) async throws {
        // No additional verification needed for hash values
    }
    
    public static func hash(_ accessToken: String) -> String {
        // SHA-256 hash of the access token, base64url encoded
        let data = accessToken.data(using: .utf8)!
        let hash = SHA256.hash(data: data)
        return Data(hash).base64URLEncodedString()
    }
}

/// Confirmation claim containing the public key.
public struct ConfirmationClaim: JWTPayload {
    public let jwk: JWK
    
    public init(jwk: JWK) {
        self.jwk = jwk
    }
    
    public func verify(using algorithm: some JWTAlgorithm) async throws {
        // Verify JWK is valid
        guard jwk.keyIdentifier != nil else {
            throw JWTError.generic(identifier: "cnf", reason: "JWK must have a key identifier")
        }
    }
}

/// Nonce claim for additional replay protection.
public struct NonceClaim: JWTPayload {
    public let value: String
    
    public init(_ value: String) {
        self.value = value
    }
    
    public func verify(using algorithm: some JWTAlgorithm) async throws {
        // Nonce validation is handled by the DPoP manager
        // This is just a placeholder for the claim structure
    }
} 