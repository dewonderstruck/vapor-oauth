import Crypto
import Foundation
import Vapor

/// Protocol for managing Pushed Authorization Requests (PAR) as defined in RFC 9126.
///
/// This protocol defines the interface for storing, retrieving, and managing
/// pushed authorization requests on the authorization server.
///
/// ## RFC 9126 Requirements
///
/// - Requests must be stored securely and bound to the client that created them
/// - Requests must have a reasonable expiration time (typically 60 seconds)
/// - Requests must be protected against replay attacks
/// - Requests must be validated against client configuration
/// - Requests must be accessible only by the client that created them
/// - Request URIs must be cryptographically secure and unpredictable
///
/// ## Implementation Guidelines
///
/// - Use secure storage (encrypted database, secure cache, etc.)
/// - Implement proper cleanup of expired requests
/// - Use cryptographically secure random identifiers
/// - Implement rate limiting to prevent abuse
/// - Log all operations for audit purposes
/// - Use Swift Crypto for all cryptographic operations
public protocol PushedAuthorizationRequestManager: Sendable {
    /// Store a pushed authorization request
    /// - Parameter request: The pushed authorization request to store
    /// - Throws: Any error that prevents storing the request
    func storeRequest(_ request: PushedAuthorizationRequest) async throws

    /// Retrieve a pushed authorization request by its request URI
    /// - Parameters:
    ///   - requestURI: The request URI to look up
    ///   - clientID: The client ID that should own the request
    /// - Returns: The pushed authorization request if found and valid
    /// - Throws: Any error that prevents retrieving the request
    func getRequest(requestURI: String, clientID: String) async throws -> PushedAuthorizationRequest?

    /// Mark a pushed authorization request as used
    /// - Parameter requestURI: The request URI to mark as used
    /// - Throws: Any error that prevents marking the request as used
    func markRequestAsUsed(requestURI: String) async throws

    /// Delete a pushed authorization request
    /// - Parameter requestURI: The request URI to delete
    /// - Throws: Any error that prevents deleting the request
    func deleteRequest(requestURI: String) async throws

    /// Clean up expired requests
    /// - Throws: Any error that prevents cleanup
    func cleanupExpiredRequests() async throws

    /// Generate a cryptographically secure unique request URI
    /// - Returns: A unique request URI with cryptographically secure identifier
    /// - Throws: Any error that prevents generating the URI
    func generateRequestURI() async throws -> String

    /// Get the expiration time in seconds for pushed authorization requests
    /// - Returns: The expiration time in seconds
    var requestExpirationTime: TimeInterval { get }
}

/// Default implementation of PushedAuthorizationRequestManager with Swift Crypto
public struct EmptyPushedAuthorizationRequestManager: PushedAuthorizationRequestManager {
    public let requestExpirationTime: TimeInterval = 60  // 60 seconds as per RFC 9126

    public init() {}

    public func storeRequest(_ request: PushedAuthorizationRequest) async throws {
        // No-op implementation
    }

    public func getRequest(requestURI: String, clientID: String) async throws -> PushedAuthorizationRequest? {
        return nil
    }

    public func markRequestAsUsed(requestURI: String) async throws {
        // No-op implementation
    }

    public func deleteRequest(requestURI: String) async throws {
        // No-op implementation
    }

    public func cleanupExpiredRequests() async throws {
        // No-op implementation
    }

    public func generateRequestURI() async throws -> String {
        // Generate a cryptographically secure random URI using Swift Crypto
        // RFC 9126 requires the identifier to be cryptographically secure and unpredictable
        var randomBytes = [UInt8](repeating: 0, count: 32)  // 256 bits for security

        // Use Swift's SystemRandomNumberGenerator for cryptographically secure random generation
        // This is cross-platform and available on both macOS and Linux
        var generator = SystemRandomNumberGenerator()
        for i in 0..<randomBytes.count {
            randomBytes[i] = UInt8.random(in: 0...255, using: &generator)
        }

        // Convert to base64url encoding (RFC 4648) for URL safety
        let base64String = Data(randomBytes).base64EncodedString()
        let base64urlString =
            base64String
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        return "urn:ietf:params:oauth:request_uri:\(base64urlString)"
    }
}
