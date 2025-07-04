import VaporOAuth

class FakeResourceServerRetriever: ResourceServerRetriever, @unchecked Sendable {

    var resourceServers: [String: OAuthResourceServer] = [:]

    func getServer(_ username: String) async throws -> OAuthResourceServer? {
        return resourceServers[username]
    }
}
