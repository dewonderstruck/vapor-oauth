public enum OAuthFlowType: String, Sendable {
    case authorization = "authorization_code"
    
    @available(*, deprecated, message: "The Implicit Grant flow is deprecated and not recommended for security reasons. It returns access tokens in HTTP redirects without confirmation of client receipt. Native and browser-based apps should use Authorization Code flow with PKCE instead, as recommended by OAuth 2.0 Security Best Practices.")
    case implicit = "implicit"
    
    @available(*, deprecated, message: "The Password Grant flow is deprecated and not recommended for security reasons. It is disallowed in OAuth 2.1 and exposes user credentials. Use Authorization Code flow with PKCE instead.")
    case password = "password"
    
    case clientCredentials = "client_credentials"
    case refresh = "refresh_token"
    case tokenIntrospection = "token_introspection"
}
