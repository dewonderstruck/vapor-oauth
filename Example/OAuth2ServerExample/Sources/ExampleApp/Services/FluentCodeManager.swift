import Vapor
import Fluent
import VaporOAuth

final class FluentCodeManager: CodeManager, @unchecked Sendable {
    private let db: any Database
    
    init(db: any Database) {
        self.db = db
    }
    
    func generateCode(
        userID: String,
        clientID: String,
        redirectURI: String,
        scopes: [String]?,
        codeChallenge: String?,
        codeChallengeMethod: String?
    ) async throws -> String {
        let codeID = UUID().uuidString
        let expiryDate = Date().addingTimeInterval(600) // 10 minutes
        
        let code = OAuthCode(
            codeID: codeID,
            clientID: clientID,
            redirectURI: redirectURI,
            userID: userID,
            scopes: scopes,
            expiryDate: expiryDate,
            codeChallenge: codeChallenge,
            codeChallengeMethod: codeChallengeMethod,
            used: false
        )
        
        try await code.save(on: db)
        return codeID
    }
    
    func getCode(_ code: String) async throws -> VaporOAuth.OAuthCode? {
        guard let fluentCode = try await OAuthCode.query(on: db)
            .filter(\.$codeID == code)
            .filter(\.$used == false)
            .first() else {
            return nil
        }
        
        return fluentCode.toOAuthCode()
    }
    
    func codeUsed(_ code: VaporOAuth.OAuthCode) async throws {
        // Find the Fluent model and mark it as used
        guard let fluentCode = try await OAuthCode.query(on: db)
            .filter(\.$codeID == code.codeID)
            .first() else {
            throw Abort(.internalServerError)
        }
        
        fluentCode.used = true
        try await fluentCode.save(on: db)
    }
    
    func cleanupExpiredCodes() async throws {
        try await OAuthCode.query(on: db)
            .filter(\.$expiryDate <= Date())
            .delete()
    }
} 