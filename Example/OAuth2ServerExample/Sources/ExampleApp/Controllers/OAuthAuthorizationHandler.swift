import Vapor
import VaporOAuth

struct OAuthAuthorizationHandler: AuthorizeHandler {
    func handleAuthorizationRequest(
        _ request: Request,
        authorizationRequestObject: AuthorizationRequestObject
    ) async throws -> Response {
        // Check if user is authenticated
        guard let sessionToken = request.cookies["session_token"]?.string,
              let userID = try await request.sessionService.validateSession(sessionToken),
              let user = try await User.find(userID, on: request.db) else {
            // User is not authenticated, store the current URL and CSRF token in session and redirect to login
            let currentURL = request.url.description
            request.session.data["oauth_redirect_url"] = currentURL
            request.session.data["oauth_csrf_token"] = authorizationRequestObject.csrfToken
            let loginURL = "/auth/login"
            request.logger.info("User not authenticated, storing redirect URL and CSRF token in session: \(currentURL)")
            return request.redirect(to: loginURL)
        }
        
        request.logger.info("User authenticated, rendering authorization page for client: \(authorizationRequestObject.clientID)")
        
        // Use stored CSRF token if available (for redirects from login), otherwise use the one from the request
        let csrfToken = request.session.data["oauth_csrf_token"] ?? authorizationRequestObject.csrfToken
        
        // Prepare context for the template - use String values for compatibility
        var context: [String: String] = [
            "title": "OAuth2 Authorization",
            "client_id": authorizationRequestObject.clientID,
            "redirect_uri": authorizationRequestObject.redirectURI.description,
            "response_type": authorizationRequestObject.responseType,
            "scope": authorizationRequestObject.scope.joined(separator: " "),
            "csrf_token": csrfToken
        ]
        
        if let state = authorizationRequestObject.state {
            context["state"] = state
        }
        
        if let codeChallenge = authorizationRequestObject.codeChallenge {
            context["code_challenge"] = codeChallenge
        }
        
        if let codeChallengeMethod = authorizationRequestObject.codeChallengeMethod {
            context["code_challenge_method"] = codeChallengeMethod
        }
        
        // Render the authorization template
        let view = try await request.view.render("oauth/authorize", context)
        return try await view.encodeResponse(for: request).get()
    }
    
    func handleAuthorizationError(_ errorType: AuthorizationError) async throws -> Response {
        let errorMessage: String
        
        switch errorType {
        case .invalidClientID:
            errorMessage = "Invalid client ID"
        case .invalidRedirectURI:
            errorMessage = "Invalid redirect URI"
        case .confidentialClientTokenGrant:
            errorMessage = "Token grant disabled for confidential clients"
        case .httpRedirectURI:
            errorMessage = "HTTP redirect URIs are not allowed in production"
        case .missingPKCE:
            errorMessage = "PKCE is required for this client"
        }
        
        // For now, return a simple error response
        return Response(status: .badRequest, body: .init(string: "OAuth Error: \(errorMessage)"))
    }
} 