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

    /// List of authorized origins for this client
    ///
    /// Origins are validated against the Origin header in authorization requests.
    /// Supports exact matches and wildcard patterns (e.g., "*.example.com").
    /// If nil or empty, origin validation is disabled for backward compatibility.
    /// This helps prevent CSRF attacks by ensuring only trusted origins can initiate OAuth flows.
    public let authorizedOrigins: [String]?

    public var extend: Vapor.Extend = .init()

    public init(
        clientID: String, redirectURIs: [String]?, clientSecret: String? = nil, validScopes: [String]? = nil,
        confidential: Bool? = nil, firstParty: Bool = false, allowedGrantType: OAuthFlowType,
        authorizedOrigins: [String]? = nil
    ) {
        self.clientID = clientID
        self.redirectURIs = redirectURIs
        self.clientSecret = clientSecret
        self.validScopes = validScopes
        self.confidentialClient = confidential
        self.firstParty = firstParty
        self.allowedGrantType = allowedGrantType
        self.authorizedOrigins = authorizedOrigins
    }
    
    /// Creates an OAuthClient with validated authorized origins
    /// 
    /// This convenience initializer validates the authorized origins configuration
    /// to ensure security best practices are followed.
    /// 
    /// - Parameters:
    ///   - clientID: The client identifier
    ///   - redirectURIs: List of allowed redirect URIs
    ///   - clientSecret: The client secret for confidential clients
    ///   - validScopes: List of valid scopes for this client
    ///   - confidential: Whether this is a confidential client
    ///   - firstParty: Whether this is a first-party client
    ///   - allowedGrantType: The allowed grant type for this client
    ///   - authorizedOrigins: List of authorized origins (will be validated)
    ///   - requireHTTPS: Whether to require HTTPS origins (recommended for production)
    /// - Throws: OriginValidationError if origin configuration is insecure
    public static func createWithValidatedOrigins(
        clientID: String, 
        redirectURIs: [String]?, 
        clientSecret: String? = nil, 
        validScopes: [String]? = nil,
        confidential: Bool? = nil, 
        firstParty: Bool = false, 
        allowedGrantType: OAuthFlowType,
        authorizedOrigins: [String]? = nil,
        requireHTTPS: Bool = false
    ) throws -> OAuthClient {
        // Validate authorized origins configuration
        let validator = OriginValidator()
        try validator.validateOriginConfiguration(authorizedOrigins, requireHTTPS: requireHTTPS)
        
        return OAuthClient(
            clientID: clientID,
            redirectURIs: redirectURIs,
            clientSecret: clientSecret,
            validScopes: validScopes,
            confidential: confidential,
            firstParty: firstParty,
            allowedGrantType: allowedGrantType,
            authorizedOrigins: authorizedOrigins
        )
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

    /// Validates if an origin is authorized for this client
    ///
    /// Performs basic origin validation against the configured authorized origins.
    /// Supports exact matching and basic wildcard patterns for subdomains.
    /// If no authorized origins are configured, validation is skipped for backward compatibility.
    /// - Parameter origin: The origin to validate (e.g., "https://example.com")
    /// - Returns: Whether the origin is authorized for this client
    func validateOrigin(_ origin: String) -> Bool {
        // If no authorized origins are configured, allow all origins (backward compatibility)
        guard let authorizedOrigins = authorizedOrigins, !authorizedOrigins.isEmpty else {
            return true
        }

        // Check for exact match first (case-insensitive for domains, but port-sensitive)
        for authorizedOrigin in authorizedOrigins {
            if exactMatch(origin: origin, authorized: authorizedOrigin) {
                return true
            }
        }

        // Check for wildcard pattern matches
        for authorizedOrigin in authorizedOrigins {
            if matchesWildcardPattern(origin: origin, pattern: authorizedOrigin) {
                return true
            }
        }

        return false
    }

    /// Checks for exact match between origin and authorized origin (case-insensitive domains, port-sensitive)
    /// - Parameters:
    ///   - origin: The origin to check
    ///   - authorized: The authorized origin to match against
    /// - Returns: Whether they match exactly
    private func exactMatch(origin: String, authorized: String) -> Bool {
        // Normalize both origins for case-insensitive comparison while preserving ports
        let normalizedOrigin = normalizeOriginWithPort(origin)
        let normalizedAuthorized = normalizeOriginWithPort(authorized)
        return normalizedOrigin == normalizedAuthorized
    }

    /// Normalizes an origin for comparison (case-insensitive domains, preserve protocol and port)
    /// - Parameter origin: The origin to normalize
    /// - Returns: The normalized origin
    private func normalizeOriginWithPort(_ origin: String) -> String {
        // Split protocol and domain parts
        if let protocolRange = origin.range(of: "://") {
            let protocolPart = String(origin[..<protocolRange.upperBound])
            let domainPart = String(origin[protocolRange.upperBound...])
            return protocolPart + domainPart.lowercased()
        } else {
            // No protocol, just lowercase the whole thing
            return origin.lowercased()
        }
    }

    /// Checks if an origin matches a wildcard pattern
    /// - Parameters:
    ///   - origin: The origin to check
    ///   - pattern: The pattern to match against (supports *.domain.com format)
    /// - Returns: Whether the origin matches the pattern
    private func matchesWildcardPattern(origin: String, pattern: String) -> Bool {
        // Only support subdomain wildcards (*.domain.com)
        guard pattern.hasPrefix("*.") else {
            return false
        }

        let patternDomain = String(pattern.dropFirst(2)).lowercased() // Remove "*." and normalize case
        
        // Extract domain from origin (remove protocol and port if present)
        let originDomain = extractDomain(from: origin)
        
        // For wildcard patterns, we need to check if there are any exact matches for the same domain
        // If there are exact matches with ports, wildcard should only match subdomains, not root domain
        if let authorizedOrigins = authorizedOrigins {
            let hasExactMatchForDomain = authorizedOrigins.contains { authorized in
                let authorizedDomain = extractDomain(from: authorized)
                return authorizedDomain == patternDomain && authorized.contains(":")
            }
            
            if hasExactMatchForDomain && originDomain == patternDomain {
                // If there's an exact match with port for this domain, don't allow wildcard to match root domain
                return false
            }
        }
        
        // Wildcard should match subdomains AND the root domain (unless there's an exact port match)
        return originDomain.hasSuffix("." + patternDomain) || originDomain == patternDomain
    }

    /// Extracts the domain from an origin URL
    /// - Parameter origin: The origin URL (e.g., "https://app.example.com:8080")
    /// - Returns: The domain part (e.g., "app.example.com")
    private func extractDomain(from origin: String) -> String {
        var domain = origin
        
        // Remove protocol
        if let protocolRange = domain.range(of: "://") {
            domain = String(domain[protocolRange.upperBound...])
        }
        
        // Remove port
        if let portRange = domain.range(of: ":") {
            domain = String(domain[..<portRange.lowerBound])
        }
        
        return domain.lowercased()
    }

}
