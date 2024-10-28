import Foundation
import Vapor

public actor InMemoryPARStorage: PARRequestStorage {
    private var storage: [String: (request: PARRequest, expiresAt: Date)]
    private let expirationInterval: TimeInterval
    
    public init(expirationInterval: TimeInterval = 60) {
        self.storage = [:]
        self.expirationInterval = expirationInterval
    }
    
    public func store(_ request: PARRequest, withURI requestURI: String) async throws {
        let expiresAt = Date().addingTimeInterval(expirationInterval)
        storage[requestURI] = (request, expiresAt)
    }
    
    public func retrieve(requestURI: String) async throws -> PARRequest? {
        guard let (request, expiresAt) = storage[requestURI] else {
            return nil
        }
        
        // Check if expired
        guard expiresAt > Date() else {
            try await remove(requestURI: requestURI)
            return nil
        }
        
        return request
    }
    
    public func remove(requestURI: String) async throws {
        storage.removeValue(forKey: requestURI)
    }
    
    public func removeExpired() async throws {
        let now = Date()
        storage = storage.filter { $0.value.expiresAt > now }
    }
}

