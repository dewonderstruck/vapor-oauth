import Vapor

/// An OAuth 2.0 client application registered with the authorization server
///
/// OAuth clients are applications that request access to protected resources on behalf of the resource owner.
/// As defined in [RFC 6749 Section 2](https://datatracker.ietf.org/doc/html/rfc6749#section-2), clients can be:
/// - Confidential: Capable of maintaining confidentiality of credentials
/// - Public: Cannot maintain credential confidentiality
///
/// Clients must register with the authorization server and be issued client credentials
/// (client ID and optionally client secret) as described in [RFC 6749 Section 2.3](https://datatracker.ietf.org/doc/html/rfc6749#section-2.3).
public final class OAuthClient: Extendable, @unchecked Sendable {

    /// The client identifier issued to the client during registration
    public let clientID: String

    /// List of allowed redirect URIs for authorization requests
    ///
    /// As specified in [RFC 6749 Section 3.1.2](https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2),
    /// the authorization server must validate that redirect URIs in authorization requests
    /// match one of the pre-registered URIs.
    public let redirectURIs: [String]?

    /// The client secret issued to confidential clients
    ///
    /// As defined in [RFC 6749 Section 2.3.1](https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1),
    /// confidential clients are issued client credentials including a client secret
    /// for authenticating with the authorization server.
    public let clientSecret: String?

    /// List of OAuth scopes this client is allowed to request
    ///
    /// Scopes represent access privileges as defined in [RFC 6749 Section 3.3](https://datatracker.ietf.org/doc/html/rfc6749#section-3.3).
    /// The authorization server should validate requested scopes against this list.
    public let validScopes: [String]?

    /// Whether this is a confidential client that can securely store credentials
    ///
    /// As specified in [RFC 6749 Section 2.1](https://datatracker.ietf.org/doc/html/rfc6749#section-2.1),
    /// confidential clients can maintain the confidentiality of their credentials.
    public let confidentialClient: Bool?

    /// Whether this is a first-party client application
    ///
    /// First-party clients are typically applications created by the same organization
    /// as the authorization server and may receive special handling.
    public let firstParty: Bool

    /// The OAuth flow type this client is allowed to use
    ///
    /// Restricts which grant type the client can use to obtain access tokens
    /// as defined in [RFC 6749 Section 1.3](https://datatracker.ietf.org/doc/html/rfc6749#section-1.3).
    public let allowedGrantType: OAuthFlowType

    public var extend: Vapor.Extend = .init()

    public init(
        clientID: String, redirectURIs: [String]?, clientSecret: String? = nil, validScopes: [String]? = nil,
        confidential: Bool? = nil, firstParty: Bool = false, allowedGrantType: OAuthFlowType
    ) {
        self.clientID = clientID
        self.redirectURIs = redirectURIs
        self.clientSecret = clientSecret
        self.validScopes = validScopes
        self.confidentialClient = confidential
        self.firstParty = firstParty
        self.allowedGrantType = allowedGrantType
    }

    /// Validates if a redirect URI matches one of the pre-registered URIs for this client
    ///
    /// As required by [RFC 6749 Section 3.1.2.3](https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.3),
    /// the authorization server must ensure the redirect URI in authorization requests
    /// exactly matches one of the pre-registered redirect URIs.
    /// - Parameter redirectURI: The redirect URI to validate
    /// - Returns: Whether the URI is valid for this client
    func validateRedirectURI(_ redirectURI: String) -> Bool {
        guard let redirectURIs = redirectURIs else {
            return false
        }

        if redirectURIs.contains(redirectURI) {
            return true
        }

        return false
    }

}
