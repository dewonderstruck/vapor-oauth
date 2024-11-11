import Vapor

/// A user account in the OAuth 2.0 authorization server
///
/// This represents a user account that can authenticate with the authorization server.
/// While related to the concept of a resource owner in [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749),
/// this model specifically represents the user's credentials and profile information stored by
/// the authorization server, rather than their role as a resource owner.
///
/// The user account enables:
/// - Authentication during the authorization process
/// - Storage of user profile information
/// - Association with granted authorizations and tokens
/// 
/// This separation of concerns allows the authorization server to manage user accounts
/// independently of their role in OAuth flows.
public final class OAuthUser: Authenticatable, Extendable, Encodable, @unchecked Sendable {
    /// The username used to identify this user
    public let username: String
    
    /// The email address associated with this user account, if any
    public let emailAddress: String?
    
    /// The password used to authenticate this user
    public var password: String
    
    /// A unique identifier for this user account
    // swiftlint:disable:next identifier_name
    public var id: String?

    /// Storage for custom extensions
    public var extend: Extend = .init()

    /// Initialize a new user account
    /// - Parameters:
    ///   - userID: A unique identifier for this user account
    ///   - username: The username used to identify this user
    ///   - emailAddress: The email address associated with this user account
    ///   - password: The password used to authenticate this user
    public init(userID: String? = nil, username: String, emailAddress: String?, password: String) {
        self.username = username
        self.emailAddress = emailAddress
        self.password = password
        self.id = userID
    }
}
