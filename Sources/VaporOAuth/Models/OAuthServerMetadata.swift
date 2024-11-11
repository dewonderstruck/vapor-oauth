import Vapor

/// OAuth 2.0 Authorization Server Metadata
///
/// A model representing the metadata for an OAuth 2.0 authorization server as defined in RFC 8414.
/// This metadata provides configuration details about the authorization server's endpoints,
/// supported features, and capabilities.
///
/// The metadata is typically served at the well-known URI `/.well-known/oauth-authorization-server`
/// and includes both required and optional fields as specified by the RFC.
///
/// Required fields include:
/// - ``issuer``: The authorization server's issuer identifier
/// - ``authorizationEndpoint``: The authorization endpoint URL
/// - ``tokenEndpoint``: The token endpoint URL
/// - ``jwksUri``: The JWKS (JSON Web Key Set) endpoint URL
/// - ``responseTypesSupported``: List of supported OAuth 2.0 response types
/// - ``subjectTypesSupported``: List of supported subject identifier types
/// - ``idTokenSigningAlgValuesSupported``: List of supported signing algorithms for ID tokens
///
/// For more details, see [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414#section-2)
public struct OAuthServerMetadata: Content, Sendable {
    /// The authorization server's issuer identifier URL
    ///
    /// A URL using the HTTPS scheme that uniquely identifies the authorization server.
    /// This URL MUST be identical to the issuer URL included in ID Tokens issued by
    /// the authorization server.
    let issuer: String
    
    /// The fully qualified URL of the authorization server's authorization endpoint
    ///
    /// The endpoint used to obtain authorization from the resource owner via
    /// user-agent redirection.
    let authorizationEndpoint: String
    
    /// The fully qualified URL of the authorization server's token endpoint
    ///
    /// The endpoint used to obtain an access token, refresh token, or ID token by
    /// presenting an authorization grant or refresh token.
    let tokenEndpoint: String
    
    /// The fully qualified URL of the authorization server's JWKS endpoint
    ///
    /// The endpoint that provides the set of JSON Web Key (JWK) that can be used to
    /// validate the signature of JWT tokens issued by the authorization server.
    let jwksUri: String
    
    /// List of OAuth 2.0 response_type values supported by the authorization server
    ///
    /// Common values include "code" for the authorization code flow and "token" for
    /// the implicit flow.
    let responseTypesSupported: [String]
    
    /// List of subject identifier types supported by the authorization server
    ///
    /// Typically includes "public" and/or "pairwise" subject types.
    let subjectTypesSupported: [String]
    
    /// List of JWS signing algorithms supported for ID Token signatures
    ///
    /// Common values include "RS256", "ES256", etc.
    let idTokenSigningAlgValuesSupported: [String]
    
    // MARK: - Recommended Fields
    
    /// List of OAuth 2.0 scope values supported by the authorization server
    ///
    /// If omitted, the authorization server supports all scopes requested by clients.
    let scopesSupported: [String]?
    
    /// List of client authentication methods supported by the token endpoint
    ///
    /// Common values include "client_secret_basic", "client_secret_post", "client_secret_jwt",
    /// and "private_key_jwt".
    let tokenEndpointAuthMethodsSupported: [String]?
    
    /// List of OAuth 2.0 grant type values supported by the authorization server
    ///
    /// Common values include "authorization_code", "client_credentials", "refresh_token",
    /// "password", etc.
    let grantTypesSupported: [String]?
    
    /// The fully qualified URL of the authorization server's UserInfo endpoint
    ///
    /// The endpoint that provides claims about the authenticated end-user.
    let userinfoEndpoint: String?
    
    /// The fully qualified URL of the authorization server's Client Registration endpoint
    ///
    /// The endpoint used to dynamically register OAuth 2.0 clients.
    let registrationEndpoint: String?
    
    /// List of claim names supported by the authorization server
    ///
    /// Claims that can be returned in ID Tokens and UserInfo responses.
    let claimsSupported: [String]?
    
    // MARK: - Optional Fields
    
    /// The fully qualified URL of the authorization server's Token Introspection endpoint
    ///
    /// The endpoint used to query the state and validity of an access token.
    let tokenIntrospectionEndpoint: String?
    
    /// The fully qualified URL of the authorization server's Token Revocation endpoint
    ///
    /// The endpoint used to revoke access tokens and refresh tokens.
    let tokenRevocationEndpoint: String?
    
    /// URL of the authorization server's service documentation
    let serviceDocumentation: String?
    
    /// Languages and scripts supported for the user interface
    let uiLocalesSupported: [String]?
    
    /// URL that the authorization server provides to the person registering the client
    /// to read about the authorization server's requirements on how the client can use
    /// the data provided by the authorization server
    let opPolicyUri: String?
    
    /// URL that the authorization server provides to the person registering the client
    /// to read about the authorization server's terms of service
    let opTosUri: String?
    
    /// List of client authentication methods supported by the revocation endpoint
    let revocationEndpointAuthMethodsSupported: [String]?
    
    /// List of JWS signing algorithms supported by the revocation endpoint for signed
    /// authentication methods
    let revocationEndpointAuthSigningAlgValuesSupported: [String]?
    
    /// List of client authentication methods supported by the introspection endpoint
    let introspectionEndpointAuthMethodsSupported: [String]?
    
    /// List of JWS signing algorithms supported by the introspection endpoint for
    /// signed authentication methods
    let introspectionEndpointAuthSigningAlgValuesSupported: [String]?
    
    /// List of PKCE code challenge methods supported by the authorization server
    ///
    /// Common values include "plain" and "S256".
    let codeChallengeMethodsSupported: [String]?
    
    /// The fully qualified URL of the authorization server's Device Authorization endpoint
    ///
    /// The endpoint used for the OAuth 2.0 Device Authorization Grant flow.
    let deviceAuthorizationEndpoint: String?
    
    public init(
        issuer: String,
        authorizationEndpoint: String,
        tokenEndpoint: String,
        jwksUri: String,
        responseTypesSupported: [String],
        subjectTypesSupported: [String],
        idTokenSigningAlgValuesSupported: [String],
        scopesSupported: [String]? = nil,
        tokenEndpointAuthMethodsSupported: [String]? = nil,
        grantTypesSupported: [String]? = nil,
        userinfoEndpoint: String? = nil,
        registrationEndpoint: String? = nil,
        claimsSupported: [String]? = nil,
        tokenIntrospectionEndpoint: String? = nil,
        tokenRevocationEndpoint: String? = nil,
        serviceDocumentation: String? = nil,
        uiLocalesSupported: [String]? = nil,
        opPolicyUri: String? = nil,
        opTosUri: String? = nil,
        revocationEndpointAuthMethodsSupported: [String]? = nil,
        revocationEndpointAuthSigningAlgValuesSupported: [String]? = nil,
        introspectionEndpointAuthMethodsSupported: [String]? = nil,
        introspectionEndpointAuthSigningAlgValuesSupported: [String]? = nil,
        codeChallengeMethodsSupported: [String]? = nil,
        deviceAuthorizationEndpoint: String? = nil
    ) {
        self.issuer = issuer
        self.authorizationEndpoint = authorizationEndpoint
        self.tokenEndpoint = tokenEndpoint
        self.jwksUri = jwksUri
        self.responseTypesSupported = responseTypesSupported
        self.subjectTypesSupported = subjectTypesSupported
        self.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported
        self.scopesSupported = scopesSupported
        self.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported
        self.grantTypesSupported = grantTypesSupported
        self.userinfoEndpoint = userinfoEndpoint
        self.registrationEndpoint = registrationEndpoint
        self.claimsSupported = claimsSupported
        self.tokenIntrospectionEndpoint = tokenIntrospectionEndpoint
        self.tokenRevocationEndpoint = tokenRevocationEndpoint
        self.serviceDocumentation = serviceDocumentation
        self.uiLocalesSupported = uiLocalesSupported
        self.opPolicyUri = opPolicyUri
        self.opTosUri = opTosUri
        self.revocationEndpointAuthMethodsSupported = revocationEndpointAuthMethodsSupported
        self.revocationEndpointAuthSigningAlgValuesSupported = revocationEndpointAuthSigningAlgValuesSupported
        self.introspectionEndpointAuthMethodsSupported = introspectionEndpointAuthMethodsSupported
        self.introspectionEndpointAuthSigningAlgValuesSupported = introspectionEndpointAuthSigningAlgValuesSupported
        self.codeChallengeMethodsSupported = codeChallengeMethodsSupported
        self.deviceAuthorizationEndpoint = deviceAuthorizationEndpoint
    }
    
    enum CodingKeys: String, CodingKey {
        case issuer
        case authorizationEndpoint = "authorization_endpoint"
        case tokenEndpoint = "token_endpoint"
        case jwksUri = "jwks_uri"
        case responseTypesSupported = "response_types_supported"
        case subjectTypesSupported = "subject_types_supported"
        case idTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported"
        case scopesSupported = "scopes_supported"
        case tokenEndpointAuthMethodsSupported = "token_endpoint_auth_methods_supported"
        case grantTypesSupported = "grant_types_supported"
        case userinfoEndpoint = "userinfo_endpoint"
        case registrationEndpoint = "registration_endpoint"
        case claimsSupported = "claims_supported"
        case tokenIntrospectionEndpoint = "introspection_endpoint"
        case tokenRevocationEndpoint = "revocation_endpoint"
        case serviceDocumentation = "service_documentation"
        case uiLocalesSupported = "ui_locales_supported"
        case opPolicyUri = "op_policy_uri"
        case opTosUri = "op_tos_uri"
        case revocationEndpointAuthMethodsSupported = "revocation_endpoint_auth_methods_supported"
        case revocationEndpointAuthSigningAlgValuesSupported = "revocation_endpoint_auth_signing_alg_values_supported"
        case introspectionEndpointAuthMethodsSupported = "introspection_endpoint_auth_methods_supported"
        case introspectionEndpointAuthSigningAlgValuesSupported = "introspection_endpoint_auth_signing_alg_values_supported"
        case codeChallengeMethodsSupported = "code_challenge_methods_supported"
        case deviceAuthorizationEndpoint = "device_authorization_endpoint"
    }
}