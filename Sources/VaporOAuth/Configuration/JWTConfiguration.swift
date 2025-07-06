import Crypto
import Foundation
import JWTKit
import Vapor

/// Configuration for JWT token generation and validation
public struct JWTConfiguration: Sendable {

    /// The issuer identifier for the OAuth 2.0 authorization server
    public let issuer: String

    /// The JWT key collection for signing and verification
    public let keyCollection: JWTKeyCollection

    /// Whether to use JWT tokens instead of opaque tokens
    public let useJWT: Bool

    /// The default expiration time for access tokens in seconds
    public let defaultAccessTokenExpiration: Int

    /// The default expiration time for refresh tokens in seconds (optional)
    public let defaultRefreshTokenExpiration: Int?

    /// Custom claims to include in JWT tokens
    public let customClaims: [String: String]?

    /// The public JWKs to expose via JWKS endpoint (RSA/ECDSA/EdDSA only)
    public let publicJWKs: [JWK]

    /// Initialize JWT configuration with a pre-built key collection
    public init(
        issuer: String,
        keyCollection: JWTKeyCollection,
        useJWT: Bool = false,
        defaultAccessTokenExpiration: Int = 3600,
        defaultRefreshTokenExpiration: Int? = nil,
        customClaims: [String: String]? = nil,
        publicJWKs: [JWK] = []
    ) {
        self.issuer = issuer
        self.keyCollection = keyCollection
        self.useJWT = useJWT
        self.defaultAccessTokenExpiration = defaultAccessTokenExpiration
        self.defaultRefreshTokenExpiration = defaultRefreshTokenExpiration
        self.customClaims = customClaims
        self.publicJWKs = publicJWKs
    }

    /// Create a JWT configuration with a single HMAC key
    public static func hmac(
        issuer: String,
        secret: String,
        kid: String? = nil,
        useJWT: Bool = false
    ) async -> JWTConfiguration {
        let keyCollection = JWTKeyCollection()
        let keyID = JWKIdentifier(string: kid ?? UUID().uuidString)
        await keyCollection.add(hmac: HMACKey(from: secret), digestAlgorithm: .sha256, kid: keyID)
        return JWTConfiguration(
            issuer: issuer,
            keyCollection: keyCollection,
            useJWT: useJWT,
            publicJWKs: []
        )
    }

    /// Create a JWT configuration with a single RSA key (PEM or DER string)
    public static func rsa(
        issuer: String,
        privateKeyPEM: String,
        kid: String? = nil,
        useJWT: Bool = false
    ) async throws -> JWTConfiguration {
        let keyCollection = JWTKeyCollection()
        let keyID = JWKIdentifier(string: kid ?? UUID().uuidString)
        let rsaKey = try Insecure.RSA.PrivateKey(pem: privateKeyPEM)
        await keyCollection.add(rsa: rsaKey, digestAlgorithm: .sha256, kid: keyID)
        // Build public JWK
        let publicKey = rsaKey.publicKey
        let (modulusData, exponentData) = try publicKey.getKeyPrimitives()
        let modulus = modulusData.base64URLEncodedString()
        let exponent = exponentData.base64URLEncodedString()
        let publicJWK = JWK.rsa(
            .rs256,
            identifier: keyID,
            modulus: modulus,
            exponent: exponent
        )
        return JWTConfiguration(
            issuer: issuer,
            keyCollection: keyCollection,
            useJWT: useJWT,
            publicJWKs: [publicJWK]
        )
    }

    /// Create a JWT configuration with a single ECDSA key (PEM string)
    public static func ecdsa(
        issuer: String,
        privateKeyPEM: String,
        curve: ECDSACurve = .p256,
        kid: String? = nil,
        useJWT: Bool = false
    ) async throws -> JWTConfiguration {
        let keyCollection = JWTKeyCollection()
        let keyID = JWKIdentifier(string: kid ?? UUID().uuidString)

        // Create ECDSA key based on curve
        let ecdsaKey: any ECDSAKey
        let algorithm: JWK.Algorithm
        let parameters: (x: String, y: String)

        switch curve {
        case .p256:
            let key = try ECDSA.PrivateKey<P256>(pem: privateKeyPEM)
            ecdsaKey = key
            algorithm = .es256
            parameters = key.publicKey.parameters!
        case .p384:
            let key = try ECDSA.PrivateKey<P384>(pem: privateKeyPEM)
            ecdsaKey = key
            algorithm = .es384
            parameters = key.publicKey.parameters!
        case .p521:
            let key = try ECDSA.PrivateKey<P521>(pem: privateKeyPEM)
            ecdsaKey = key
            algorithm = .es512
            parameters = key.publicKey.parameters!
        default:
            throw JWTError.generic(identifier: "ecdsa", reason: "Unsupported ECDSA curve: \(curve)")
        }

        await keyCollection.add(ecdsa: ecdsaKey, kid: keyID)

        // Build public JWK
        let publicJWK = JWK.ecdsa(
            algorithm,
            identifier: keyID,
            x: parameters.x,
            y: parameters.y,
            curve: curve
        )
        return JWTConfiguration(
            issuer: issuer,
            keyCollection: keyCollection,
            useJWT: useJWT,
            publicJWKs: [publicJWK]
        )
    }

    /// Create a JWT configuration with a single EdDSA key (PEM string)
    /// Note: EdDSA support is limited in JWTKit v5, so this method is not implemented yet
    public static func eddsa(
        issuer: String,
        privateKeyPEM: String,
        kid: String? = nil,
        useJWT: Bool = false
    ) async throws -> JWTConfiguration {
        // TODO: Implement EdDSA support when JWTKit v5 provides better PEM support
        throw JWTError.generic(identifier: "eddsa", reason: "EdDSA support not yet implemented in JWTKit v5")
    }

    /// Add a key to an existing configuration (returns a new config with the key added)
    public func addingHMAC(secret: String, kid: String? = nil) async -> JWTConfiguration {
        let newCollection = JWTKeyCollection()
        // Copy existing keys
        // (JWTKit v5 does not provide a direct copy, so this is a placeholder for now)
        // TODO: Implement copying keys if needed
        let keyID = JWKIdentifier(string: kid ?? UUID().uuidString)
        await newCollection.add(hmac: HMACKey(from: secret), digestAlgorithm: .sha256, kid: keyID)
        return JWTConfiguration(
            issuer: issuer,
            keyCollection: newCollection,
            useJWT: useJWT,
            defaultAccessTokenExpiration: defaultAccessTokenExpiration,
            defaultRefreshTokenExpiration: defaultRefreshTokenExpiration,
            customClaims: customClaims,
            publicJWKs: publicJWKs
        )
    }
    // Similar methods for RSA, ECDSA, EdDSA can be added as needed
}

// MARK: - Default Configuration

extension JWTConfiguration {
    /// Default JWT configuration that disables JWT tokens
    public static let disabled = JWTConfiguration(
        issuer: "vapor-oauth",
        keyCollection: JWTKeyCollection(),
        useJWT: false
    )
}
