import Vapor
import Fluent
import VaporOAuth

final class OAuthResourceServerModel: Model, @unchecked Sendable {
    static let schema = "oauth_resource_servers"
    
    @ID(key: .id)
    var id: UUID?
    
    @Field(key: "username")
    var username: String
    
    @Field(key: "password")
    var password: String
    
    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?
    
    init() {}
    
    init(
        id: UUID? = nil,
        username: String,
        password: String
    ) {
        self.id = id
        self.username = username
        self.password = password
    }
    
    func toOAuthResourceServer() -> OAuthResourceServer {
        return OAuthResourceServer(
            username: self.username,
            password: self.password
        )
    }
} 