import Vapor
import Leaf

struct AuthController: RouteCollection {
    func boot(routes: any RoutesBuilder) throws {
        let auth = routes.grouped("auth")
        
        // Public routes
        auth.get("login", use: loginPage)
        auth.post("login", use: login)
        auth.get("register", use: registerPage)
        auth.post("register", use: register)
        auth.get("logout", use: logout)
        
        // Protected routes
        let protected = auth.grouped(AuthMiddleware())
        protected.get("profile", use: profile)
        protected.post("profile", use: updateProfile)
        protected.get("change-password", use: changePasswordPage)
        protected.post("change-password", use: changePassword)
    }
    
    // MARK: - Login
    func loginPage(req: Request) async throws -> View {
        var context: [String: String] = [
            "title": "Login"
        ]
        
        if let error = req.query[String.self, at: "error"] {
            context["error"] = error
        }
        
        if let success = req.query[String.self, at: "success"] {
            context["success"] = success
        }
        
        return try await req.view.render("auth/login", context)
    }
    
    func login(req: Request) async throws -> Response {
        struct LoginData: Content {
            let username: String
            let password: String
        }
        
        let data = try req.content.decode(LoginData.self)
        
        // Debug: Log what we received
        req.logger.info("Login attempt for user: \(data.username)")
        
        do {
            let user = try await req.authService.login(username: data.username, password: data.password)
            let sessionToken = try await req.sessionService.createSession(for: user.id, req: req)
            
            // Check if there's a redirect URL stored in session
            let redirectURL: String
            if let oauthRedirectURL = req.session.data["oauth_redirect_url"] {
                redirectURL = oauthRedirectURL
                req.logger.info("Redirecting to OAuth URL from session: \(redirectURL)")
                // Clear the session data after use
                req.session.data["oauth_redirect_url"] = nil
            } else {
                redirectURL = "/dashboard"
                req.logger.info("No OAuth redirect URL in session, going to dashboard")
            }
            
            var response = req.redirect(to: redirectURL)
            
            // Set the custom session token cookie
            response.cookies["session_token"] = HTTPCookies.Value(
                string: sessionToken,
                expires: Date().addingTimeInterval(24 * 60 * 60),
                maxAge: 24 * 60 * 60,
                domain: nil,
                path: "/",
                isSecure: false,
                isHTTPOnly: true,
                sameSite: .lax
            )
            
            // Preserve the Vapor session cookie if it exists (for OAuth CSRF tokens)
            if let vaporSessionCookie = req.cookies["vapor-session"] {
                response.cookies["vapor-session"] = vaporSessionCookie
                req.logger.info("Preserved Vapor session cookie for OAuth CSRF token")
            }
            
            return response
        } catch {
            return req.redirect(to: "/auth/login?error=Invalid credentials")
        }
    }
    
    // MARK: - Registration
    func registerPage(req: Request) async throws -> View {
        return try await req.view.render("auth/register", [
            "title": "Register",
            "error": req.query[String.self, at: "error"]
        ])
    }
    
    func register(req: Request) async throws -> Response {
        let userData = try req.content.decode(User.Create.self)
        
        do {
            let user = try await req.authService.register(userData)
            let sessionToken = try await req.sessionService.createSession(for: user.id, req: req)
            
            var response = req.redirect(to: "/dashboard")
            response.cookies["session_token"] = HTTPCookies.Value(
                string: sessionToken,
                expires: Date().addingTimeInterval(24 * 60 * 60),
                maxAge: 24 * 60 * 60,
                domain: nil,
                path: "/",
                isSecure: false,
                isHTTPOnly: true,
                sameSite: .lax
            )
            return response
        } catch {
            return req.redirect(to: "/auth/register?error=Registration failed")
        }
    }
    
    // MARK: - Logout
    func logout(req: Request) async throws -> Response {
        if let sessionToken = req.cookies["session_token"]?.string {
            try await req.sessionService.invalidateSession(sessionToken)
        }
        
        var response = req.redirect(to: "/auth/login?success=Logged out successfully")
        response.cookies["session_token"] = nil
        return response
    }
    
    // MARK: - Profile
    func profile(req: Request) async throws -> View {
        guard let user = req.auth.get(User.Public.self) else {
            throw Abort(.unauthorized)
        }
        
        return try await req.view.render("auth/profile", [
            "title": "Profile",
            "error": req.query[String.self, at: "error"],
            "success": req.query[String.self, at: "success"]
        ])
    }
    
    func updateProfile(req: Request) async throws -> Response {
        guard let user = req.auth.get(User.Public.self) else {
            throw Abort(.unauthorized)
        }
        
        let updateData = try req.content.decode(User.Update.self)
        
        do {
            _ = try await req.authService.updateUser(user.id, with: updateData)
            return req.redirect(to: "/auth/profile?success=Profile updated successfully")
        } catch {
            return req.redirect(to: "/auth/profile?error=Failed to update profile")
        }
    }
    
    // MARK: - Change Password
    func changePasswordPage(req: Request) async throws -> View {
        return try await req.view.render("auth/change-password", [
            "title": "Change Password",
            "error": req.query[String.self, at: "error"],
            "success": req.query[String.self, at: "success"]
        ])
    }
    
    func changePassword(req: Request) async throws -> Response {
        guard let user = req.auth.get(User.Public.self) else {
            throw Abort(.unauthorized)
        }
        
        struct PasswordData: Content {
            let currentPassword: String
            let newPassword: String
            let confirmPassword: String
        }
        
        let data = try req.content.decode(PasswordData.self)
        
        guard data.newPassword == data.confirmPassword else {
            return req.redirect(to: "/auth/change-password?error=New passwords do not match")
        }
        
        do {
            try await req.authService.changePassword(
                for: user.id,
                oldPassword: data.currentPassword,
                newPassword: data.newPassword
            )
            return req.redirect(to: "/auth/change-password?success=Password changed successfully")
        } catch {
            return req.redirect(to: "/auth/change-password?error=Failed to change password")
        }
    }
} 