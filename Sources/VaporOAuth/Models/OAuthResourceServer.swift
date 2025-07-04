import Vapor

/// A resource server that can validate OAuth 2.0 access tokens
///
/// Resource servers are OAuth 2.0 protected API endpoints that accept and validate access tokens.
/// They authenticate to the authorization server using client credentials to perform token introspection.
///
/// As defined in [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662), resource servers
/// can use the token introspection endpoint to determine the state and validity of an access token
/// before allowing access to protected resources.
///
/// The resource server authenticates to the authorization server using HTTP Basic authentication
/// with a username and password (client credentials).
public final class OAuthResourceServer: Extendable, @unchecked Sendable {
    /// The client ID used to authenticate with the authorization server
    public let username: String

    /// The client secret used to authenticate with the authorization server
    public let password: String

    /// Storage for custom extensions
    public var extend: Vapor.Extend = .init()

    /// Initialize a new resource server with client credentials
    /// - Parameters:
    ///   - username: The client ID for authenticating to the authorization server
    ///   - password: The client secret for authenticating to the authorization server
    public init(username: String, password: String) {
        self.username = username
        self.password = password
    }
}
