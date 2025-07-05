import Vapor
import Fluent
import VaporOAuth

final class FluentClientRetriever: ClientRetriever, @unchecked Sendable {
    private let db: any Database
    
    init(db: any Database) {
        self.db = db
    }
    
    func getClient(clientID: String) async throws -> OAuthClient? {
        guard let clientModel = try await OAuthClientModel.query(on: db)
            .filter(\.$clientID == clientID)
            .first() else {
            return nil
        }
        
        return clientModel.toOAuthClient()
    }
    
    func getAllClients() async throws -> [OAuthClient] {
        let clientModels = try await OAuthClientModel.query(on: db).all()
        return clientModels.map { $0.toOAuthClient() }
    }
} 