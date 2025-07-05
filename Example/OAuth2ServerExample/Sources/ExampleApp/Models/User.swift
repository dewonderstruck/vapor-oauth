import Vapor
import Fluent
import VaporOAuth
import Leaf

final class User: Model, @unchecked Sendable {
    static let schema = "users"
    
    @ID(key: .id)
    var id: UUID?
    
    @Field(key: "username")
    var username: String
    
    @Field(key: "email")
    var email: String
    
    @Field(key: "password_hash")
    var passwordHash: String
    
    @Field(key: "first_name")
    var firstName: String?
    
    @Field(key: "last_name")
    var lastName: String?
    
    @Field(key: "is_active")
    var isActive: Bool
    
    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?
    
    @Timestamp(key: "updated_at", on: .update)
    var updatedAt: Date?
    
    init() {}
    
    init(
        id: UUID? = nil,
        username: String,
        email: String,
        passwordHash: String,
        firstName: String? = nil,
        lastName: String? = nil,
        isActive: Bool = true
    ) {
        self.id = id
        self.username = username
        self.email = email
        self.passwordHash = passwordHash
        self.firstName = firstName
        self.lastName = lastName
        self.isActive = isActive
    }
}

// MARK: - OAuthUser Conformance
extension User {
    func toOAuthUser() -> OAuthUser {
        return OAuthUser(
            userID: self.id?.uuidString,
            username: self.username,
            emailAddress: self.email,
            password: self.passwordHash
        )
    }
}

// MARK: - User DTOs
extension User {
    struct Create: Content {
        let username: String
        let email: String
        let password: String
        let firstName: String?
        let lastName: String?
    }
    
    struct Update: Content {
        let firstName: String?
        let lastName: String?
        let email: String?
    }
    
    struct Public: Content, Authenticatable {
        let id: UUID
        let username: String
        let email: String
        let firstName: String?
        let lastName: String?
        let isActive: Bool
        let createdAt: Date?
        
        init(from user: User) {
            self.id = user.id!
            self.username = user.username
            self.email = user.email
            self.firstName = user.firstName
            self.lastName = user.lastName
            self.isActive = user.isActive
            self.createdAt = user.createdAt
        }
    }
} 