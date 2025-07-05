import Vapor
import Fluent
import VaporOAuth

final class FluentResourceServerRetriever: ResourceServerRetriever, @unchecked Sendable {
    private let db: any Database
    
    init(db: any Database) {
        self.db = db
    }
    
    func getServer(_ username: String) async throws -> OAuthResourceServer? {
        guard let resourceServerModel = try await OAuthResourceServerModel.query(on: db)
            .filter(\.$username == username)
            .first() else {
            return nil
        }
        
        return resourceServerModel.toOAuthResourceServer()
    }
} 