import Vapor

struct AuthMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        // Get session token from cookie
        guard let sessionToken = request.cookies["session_token"]?.string else {
            // Redirect to login if no session
            if request.url.path.hasPrefix("/auth") || request.url.path == "/" {
                return try await next.respond(to: request)
            }
            return request.redirect(to: "/auth/login")
        }
        
        // Validate session
        guard let userID = try await request.sessionService.validateSession(sessionToken) else {
            // Clear invalid session cookie
            request.cookies["session_token"] = nil
            if request.url.path.hasPrefix("/auth") || request.url.path == "/" {
                return try await next.respond(to: request)
            }
            return request.redirect(to: "/auth/login")
        }
        
        // Get user and attach to request
        if let user = try await request.authService.getUser(by: userID) {
            request.auth.login(user)
        }
        
        return try await next.respond(to: request)
    }
}

struct OptionalAuthMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        // Get session token from cookie
        if let sessionToken = request.cookies["session_token"]?.string,
           let userID = try await request.sessionService.validateSession(sessionToken),
           let user = try await request.authService.getUser(by: userID) {
            request.auth.login(user)
        }
        
        return try await next.respond(to: request)
    }
} 