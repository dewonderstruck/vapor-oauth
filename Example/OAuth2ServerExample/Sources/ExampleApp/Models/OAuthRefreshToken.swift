import Vapor
import Fluent
import VaporOAuth

final class OAuthRefreshToken: Model, RefreshToken, @unchecked Sendable {
    static let schema = "oauth_refresh_tokens"
    
    @ID(key: .id)
    var id: UUID?
    
    @Field(key: "token_string")
    var tokenString: String
    
    @Field(key: "client_id")
    var clientID: String
    
    @Field(key: "user_id")
    var userID: String?
    
    @Field(key: "scopes")
    var scopes: [String]?
    
    @Field(key: "expiry_time")
    var expiryTime: Date
    
    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?
    
    init() {}
    
    init(
        id: UUID? = nil,
        tokenString: String,
        clientID: String,
        userID: String? = nil,
        scopes: [String]? = nil,
        expiryTime: Date
    ) {
        self.id = id
        self.tokenString = tokenString
        self.clientID = clientID
        self.userID = userID
        self.scopes = scopes
        self.expiryTime = expiryTime
    }
} 
