import Vapor
import Fluent
import VaporOAuth

final class FluentTokenManager: TokenManager, @unchecked Sendable {
    private let db: any Database
    
    init(db: any Database) {
        self.db = db
    }
    
    func generateAccessRefreshTokens(
        clientID: String,
        userID: String?,
        scopes: [String]?,
        accessTokenExpiryTime: Int
    ) async throws -> (any AccessToken, any RefreshToken) {
        let accessToken = OAuthAccessToken(
            tokenString: UUID().uuidString,
            clientID: clientID,
            userID: userID,
            scopes: scopes,
            expiryTime: Date().addingTimeInterval(TimeInterval(accessTokenExpiryTime))
        )
        
        let refreshToken = OAuthRefreshToken(
            tokenString: UUID().uuidString,
            clientID: clientID,
            userID: userID,
            scopes: scopes,
            expiryTime: Date().addingTimeInterval(TimeInterval(accessTokenExpiryTime * 2))
        )
        
        try await accessToken.save(on: db)
        try await refreshToken.save(on: db)
        
        return (accessToken, refreshToken)
    }
    
    func generateAccessToken(
        clientID: String,
        userID: String?,
        scopes: [String]?,
        expiryTime: Int
    ) async throws -> any AccessToken {
        let accessToken = OAuthAccessToken(
            tokenString: UUID().uuidString,
            clientID: clientID,
            userID: userID,
            scopes: scopes,
            expiryTime: Date().addingTimeInterval(TimeInterval(expiryTime))
        )
        
        try await accessToken.save(on: db)
        return accessToken
    }
    
    func getRefreshToken(_ refreshToken: String) async throws -> (any RefreshToken)? {
        return try await OAuthRefreshToken.query(on: db)
            .filter(\.$tokenString == refreshToken)
            .first()
    }
    
    func getAccessToken(_ accessToken: String) async throws -> (any AccessToken)? {
        return try await OAuthAccessToken.query(on: db)
            .filter(\.$tokenString == accessToken)
            .first()
    }
    
    func updateRefreshToken(_ refreshToken: any RefreshToken, scopes: [String]) async throws {
        guard let token = refreshToken as? OAuthRefreshToken else {
            throw Abort(.internalServerError)
        }
        
        token.scopes = scopes
        try await token.save(on: db)
    }
    
    func revokeAccessToken(_ token: String) async throws {
        try await OAuthAccessToken.query(on: db)
            .filter(\.$tokenString == token)
            .delete()
    }
    
    func revokeRefreshToken(_ token: String) async throws {
        try await OAuthRefreshToken.query(on: db)
            .filter(\.$tokenString == token)
            .delete()
    }
} 