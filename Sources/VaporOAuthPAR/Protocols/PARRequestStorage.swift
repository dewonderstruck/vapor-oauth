import Vapor
import VaporOAuth

public protocol PARRequestStorage: Sendable {
    /// Store a PAR request with its associated URI
    func store(_ request: PARRequest, withURI requestURI: String) async throws
    
    /// Retrieve a PAR request by its URI
    func retrieve(requestURI: String) async throws -> PARRequest?
    
    /// Remove a PAR request (should be called after use or expiration)
    func remove(requestURI: String) async throws
    
    /// Clean up expired requests
    func removeExpired() async throws
}
