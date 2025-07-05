import Vapor
import Crypto
import Fluent

final class AuthService: @unchecked Sendable {
    private let db: any Database
    
    init(db: any Database) {
        self.db = db
    }
    
    func register(_ userData: User.Create) async throws -> User.Public {
        // Check if user already exists
        let existingUser = try await User.query(on: db)
            .group(.or) { group in
                group.filter(\.$username == userData.username)
                group.filter(\.$email == userData.email)
            }
            .first()
        
        if existingUser != nil {
            throw Abort(.conflict, reason: "User with this username or email already exists")
        }
        
        // Hash password
        let hashedPassword = try Bcrypt.hash(userData.password)
        
        // Create user
        let user = User(
            username: userData.username,
            email: userData.email,
            passwordHash: hashedPassword,
            firstName: userData.firstName,
            lastName: userData.lastName
        )
        
        try await user.save(on: db)
        return User.Public(from: user)
    }
    
    func login(username: String, password: String) async throws -> User.Public {
        guard let user = try await User.query(on: db)
            .filter(\.$username == username)
            .first() else {
            throw Abort(.unauthorized, reason: "Invalid credentials")
        }
        
        guard user.isActive else {
            throw Abort(.forbidden, reason: "Account is deactivated")
        }
        
        guard try Bcrypt.verify(password, created: user.passwordHash) else {
            throw Abort(.unauthorized, reason: "Invalid credentials")
        }
        
        return User.Public(from: user)
    }
    
    func getUser(by id: UUID) async throws -> User.Public? {
        guard let user = try await User.find(id, on: db) else {
            return nil
        }
        return User.Public(from: user)
    }
    
    func getUser(by username: String) async throws -> User? {
        return try await User.query(on: db)
            .filter(\.$username == username)
            .first()
    }
    
    func updateUser(_ id: UUID, with data: User.Update) async throws -> User.Public {
        guard let user = try await User.find(id, on: db) else {
            throw Abort(.notFound, reason: "User not found")
        }
        
        if let firstName = data.firstName {
            user.firstName = firstName
        }
        if let lastName = data.lastName {
            user.lastName = lastName
        }
        if let email = data.email {
            // Check if email is already taken
            if let existingUser = try await User.query(on: db)
                .filter(\.$email == email)
                .filter(\.$id != id)
                .first() {
                throw Abort(.conflict, reason: "Email already in use")
            }
            user.email = email
        }
        
        try await user.save(on: db)
        return User.Public(from: user)
    }
    
    func changePassword(for userId: UUID, oldPassword: String, newPassword: String) async throws {
        guard let user = try await User.find(userId, on: db) else {
            throw Abort(.notFound, reason: "User not found")
        }
        
        guard try Bcrypt.verify(oldPassword, created: user.passwordHash) else {
            throw Abort(.unauthorized, reason: "Current password is incorrect")
        }
        
        user.passwordHash = try Bcrypt.hash(newPassword)
        try await user.save(on: db)
    }
} 