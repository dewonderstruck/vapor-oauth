import VaporOAuth

public class FakeClientGetter: ClientRetriever, @unchecked Sendable {
    
    var validClients: [String: OAuthClient] = [:]
    
    public func getClient(clientID: String) async throws -> OAuthClient? {
        return validClients[clientID]
    }
}
