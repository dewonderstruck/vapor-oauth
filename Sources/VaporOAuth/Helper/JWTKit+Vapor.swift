import JWTKit
import Vapor

// MARK: - JWTKit + Vapor Extensions

/// Make JWTKit's JWKS compatible with Vapor's Content protocol for HTTP responses
extension JWKS: @retroactive AsyncResponseEncodable {}
extension JWKS: @retroactive AsyncRequestDecodable {}
extension JWKS: @retroactive ResponseEncodable {}
extension JWKS: @retroactive RequestDecodable {}
extension JWKS: @retroactive Content {}
