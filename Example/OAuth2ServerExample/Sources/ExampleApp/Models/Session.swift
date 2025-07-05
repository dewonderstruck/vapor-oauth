import Vapor
import Fluent

final class Session: Model, @unchecked Sendable {
    static let schema = "sessions"
    
    @ID(key: .id)
    var id: UUID?
    
    @Field(key: "token")
    var token: String
    
    @Field(key: "user_id")
    var userID: UUID
    
    @Field(key: "expires_at")
    var expiresAt: Date
    
    @Field(key: "ip_address")
    var ipAddress: String?
    
    @Field(key: "user_agent")
    var userAgent: String?
    
    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?
    
    init() {}
    
    init(
        id: UUID? = nil,
        token: String,
        userID: UUID,
        expiresAt: Date,
        ipAddress: String? = nil,
        userAgent: String? = nil
    ) {
        self.id = id
        self.token = token
        self.userID = userID
        self.expiresAt = expiresAt
        self.ipAddress = ipAddress
        self.userAgent = userAgent
    }
} 