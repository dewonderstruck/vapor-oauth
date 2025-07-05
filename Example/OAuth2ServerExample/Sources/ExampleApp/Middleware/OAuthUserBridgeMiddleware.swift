import Vapor
import VaporOAuth

struct OAuthUserBridgeMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        // Only apply this middleware to OAuth POST endpoints
        if request.url.path == "/oauth/authorize" && request.method == .POST {
            // Check if we have a session token and convert to OAuthUser
            if let sessionToken = request.cookies["session_token"]?.string,
               let userID = try await request.sessionService.validateSession(sessionToken),
               let user = try await User.find(userID, on: request.db) {
                
                // Convert User to OAuthUser and authenticate
                let oauthUser = user.toOAuthUser()
                request.auth.login(oauthUser)
                request.logger.info("Bridged User to OAuthUser for OAuth authorization")
                
                // Restore CSRF token to session if it was stored
                if let storedCSRFToken = request.session.data["oauth_csrf_token"] {
                    request.session.data["CSRFToken"] = storedCSRFToken
                    request.logger.info("Restored CSRF token to session: \(storedCSRFToken)")
                }
                
                // Debug: Log the parameters being received
                request.logger.info("OAuth POST parameters:")
                request.logger.info("  Query params: \(request.url.query ?? "none")")
                
                // Log specific expected parameters
                if let clientID = request.query[String.self, at: "client_id"] {
                    request.logger.info("  client_id: \(clientID)")
                } else {
                    request.logger.info("  client_id: MISSING")
                }
                
                if let redirectURI = request.query[String.self, at: "redirect_uri"] {
                    request.logger.info("  redirect_uri: \(redirectURI)")
                } else {
                    request.logger.info("  redirect_uri: MISSING")
                }
                
                if let responseType = request.query[String.self, at: "response_type"] {
                    request.logger.info("  response_type: \(responseType)")
                } else {
                    request.logger.info("  response_type: MISSING")
                }
                
                if let scope = request.query[String.self, at: "scope"] {
                    request.logger.info("  scope: \(scope)")
                } else {
                    request.logger.info("  scope: MISSING")
                }
                
                if let csrfToken = request.content[String.self, at: "csrfToken"] {
                    request.logger.info("  csrfToken: \(csrfToken)")
                } else {
                    request.logger.info("  csrfToken: MISSING")
                }
                
                if let applicationAuthorized = request.content[String.self, at: "applicationAuthorized"] {
                    request.logger.info("  applicationAuthorized: \(applicationAuthorized)")
                } else {
                    request.logger.info("  applicationAuthorized: MISSING")
                }
                
                // Debug CSRF token validation
                if let sessionCSRFToken = request.session.data["CSRFToken"] {
                    request.logger.info("  session csrf_token: \(sessionCSRFToken)")
                } else {
                    request.logger.info("  session csrf_token: MISSING")
                }
                
                // Debug: Log all session data
                request.logger.info("  All session data: \(request.session.data)")
                
                // Debug client validation
                request.logger.info("  userID: \(userID)")
                request.logger.info("  oauthUser.id: \(oauthUser.id ?? "nil")")
            }
        }
        
        return try await next.respond(to: request)
    }
} 