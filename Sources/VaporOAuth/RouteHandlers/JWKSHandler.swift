import JWTKit
import Vapor

/// Handler for JWKS (JSON Web Key Set) endpoint
///
/// This endpoint exposes the public keys used for JWT verification,
/// following RFC 7517 (JSON Web Key) and RFC 8414 (OAuth 2.0 Authorization Server Metadata).
public struct JWKSHandler: Sendable {

    private let jwtConfiguration: JWTConfiguration?

    /// Initialize JWKS handler
    /// - Parameter jwtConfiguration: JWT configuration containing the signing key
    public init(jwtConfiguration: JWTConfiguration?) {
        self.jwtConfiguration = jwtConfiguration
    }

    /// Handle JWKS endpoint requests
    /// - Parameter request: The incoming request
    /// - Returns: JSON response containing the JWKS
    public func handleRequest(_ request: Request) async throws -> Response {
        guard let jwtConfiguration = jwtConfiguration, jwtConfiguration.useJWT else {
            throw Abort(.notFound, reason: "JWKS endpoint not available - JWT is not enabled")
        }

        let jwks = JWKS(keys: jwtConfiguration.publicJWKs)

        let response = Response(status: .ok)
        try response.content.encode(jwks)
        response.headers.contentType = .json

        return response
    }
}
