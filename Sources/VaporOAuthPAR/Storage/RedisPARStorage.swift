import Redis
import Vapor
import Foundation

public actor RedisPARStorage: PARRequestStorage {
    private let redis: RedisClient
    private let keyPrefix: String
    private let expirationInterval: Int
    
    public init(redis: RedisClient, keyPrefix: String = "par:", expirationInterval: Int = 60) {
        self.redis = redis
        self.keyPrefix = keyPrefix
        self.expirationInterval = expirationInterval
    }
    
    public func store(_ request: PARRequest, withURI requestURI: String) async throws {
        let key = RedisKey(stringLiteral: "\(keyPrefix)\(requestURI)")
        let data = try JSONEncoder().encode(request)
        try await redis.setex(key, to: data, expirationInSeconds: expirationInterval).get()
    }
    
    public func retrieve(requestURI: String) async throws -> PARRequest? {
        let key = RedisKey(stringLiteral: "\(keyPrefix)\(requestURI)")
        guard let data = try await redis.get(key, as: Data.self).get() else {
            return nil
        }
        return try JSONDecoder().decode(PARRequest.self, from: data)
    }
    
    public func remove(requestURI: String) async throws {
        let key = RedisKey(stringLiteral: "\(keyPrefix)\(requestURI)")
        _ = try await redis.delete(key).get()
    }
    
    public func removeExpired() async throws {
        // Redis automatically removes expired keys, so no additional implementation needed
    }
}
