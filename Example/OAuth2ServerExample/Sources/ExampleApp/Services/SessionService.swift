import Vapor
import Crypto
import Fluent

final class SessionService: @unchecked Sendable {
    private let db: any Database
    
    init(db: any Database) {
        self.db = db
    }
    
    func createSession(for userID: UUID, req: Request) async throws -> String {
        let token = [UInt8].random(count: 32).base64
        let expiresAt = Date().addingTimeInterval(24 * 60 * 60) // 24 hours
        
        let session = Session(
            token: token,
            userID: userID,
            expiresAt: expiresAt,
            ipAddress: req.remoteAddress?.description,
            userAgent: req.headers.first(name: "User-Agent")
        )
        
        try await session.save(on: db)
        return token
    }
    
    func validateSession(_ token: String) async throws -> UUID? {
        guard let session = try await Session.query(on: db)
            .filter(\.$token == token)
            .filter(\.$expiresAt > Date())
            .first() else {
            return nil
        }
        
        return session.userID
    }
    
    func invalidateSession(_ token: String) async throws {
        try await Session.query(on: db)
            .filter(\.$token == token)
            .delete()
    }
    
    func invalidateAllSessions(for userID: UUID) async throws {
        try await Session.query(on: db)
            .filter(\.$userID == userID)
            .delete()
    }
    
    func cleanupExpiredSessions() async throws {
        try await Session.query(on: db)
            .filter(\.$expiresAt <= Date())
            .delete()
    }
} 