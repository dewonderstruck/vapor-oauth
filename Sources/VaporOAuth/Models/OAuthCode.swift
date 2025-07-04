import Foundation

/// An OAuth 2.0 authorization code issued during the authorization code grant flow
///
/// Authorization codes are short-lived credentials issued to the client by the authorization server
/// after the resource owner grants authorization. As defined in [RFC 6749 Section 4.1.2](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2),
/// the code is bound to:
/// - The client identifier
/// - The redirect URI
/// - The resource owner's authorization
/// - The requested scope
///
/// The code can then be exchanged for an access token as described in [RFC 6749 Section 4.1.3](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3).
///
/// For PKCE support as specified in [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636),
/// the code may also be bound to a code challenge and challenge method.
public final class OAuthCode: @unchecked Sendable {
    /// Unique identifier for this authorization code
    public let codeID: String

    /// The client identifier the code was issued to
    public let clientID: String

    /// The redirect URI specified in the authorization request
    public let redirectURI: String

    /// Identifier of the resource owner who granted authorization
    public let userID: String

    /// When this authorization code expires
    public let expiryDate: Date

    /// The scope of access authorized by the resource owner
    public let scopes: [String]?

    /// The PKCE code challenge provided in the authorization request
    public let codeChallenge: String?

    /// The PKCE code challenge method (e.g. "S256" or "plain")
    public let codeChallengeMethod: String?

    /// Storage for custom extensions
    public var extend: [String: Any] = [:]

    /// Initialize a new authorization code
    /// - Parameters:
    ///   - codeID: Unique identifier for this authorization code
    ///   - clientID: The client identifier the code was issued to
    ///   - redirectURI: The redirect URI specified in the authorization request
    ///   - userID: Identifier of the resource owner who granted authorization
    ///   - expiryDate: When this authorization code expires
    ///   - scopes: The scope of access authorized by the resource owner
    ///   - codeChallenge: The PKCE code challenge provided in the authorization request
    ///   - codeChallengeMethod: The PKCE code challenge method (e.g. "S256" or "plain")
    public init(
        codeID: String,
        clientID: String,
        redirectURI: String,
        userID: String,
        expiryDate: Date,
        scopes: [String]?,
        codeChallenge: String?,
        codeChallengeMethod: String?
    ) {
        self.codeID = codeID
        self.clientID = clientID
        self.redirectURI = redirectURI
        self.userID = userID
        self.expiryDate = expiryDate
        self.scopes = scopes
        self.codeChallenge = codeChallenge
        self.codeChallengeMethod = codeChallengeMethod
    }
}
