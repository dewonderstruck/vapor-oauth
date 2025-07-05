import Fluent
import Vapor
import Leaf
import VaporOAuth

func routes(_ app: Application) throws {
    app.get { req async throws -> View in
        var context: [String: String] = [
            "title": "Vapor OAuth2"
        ]
        if let user = req.auth.get(User.Public.self) {
            context["user"] = user.username
        }
        return try await req.view.render("home", context)
    }

    app.get("hello") { req async -> String in
        "Hello, world!"
    }
    
    app.get("demo") { req async throws -> View in
        return try await req.view.render("demo", [
            "title": "OAuth2 Demo"
        ])
    }
    
    app.get("docs") { req async throws -> View in
        return try await req.view.render("docs", [
            "title": "OAuth2 Documentation"
        ])
    }
    
    app.get("callback") { req async throws -> View in
        let code = req.query[String.self, at: "code"]
        let state = req.query[String.self, at: "state"]
        let error = req.query[String.self, at: "error"]
        let errorDescription = req.query[String.self, at: "error_description"]
        
        return try await req.view.render("callback", [
            "title": "OAuth Callback",
            "code": code,
            "state": state,
            "error": error,
            "errorDescription": errorDescription
        ])
    }
    
    // Debug route to check OAuth clients
    app.get("debug", "clients") { req async throws -> String in
        let clients = try await OAuthClientModel.query(on: req.db).all()
        return "Found \(clients.count) clients: \(clients.map { $0.clientID })"
    }
    
    // Test route to generate a device code for testing
    app.get("test", "device-code") { req async throws -> View in
        // Generate device code directly
        guard let deviceCode = try await req.application.oauthDeviceCodeManager.generateDeviceCode(
            clientID: "device-client",
            scopes: ["read", "write"],
            verificationURI: req.application.oauth.deviceVerificationURI,
            verificationURIComplete: nil
        ) else {
            throw Abort(.internalServerError)
        }
        
        return try await req.view.render("test/device-code", [
            "title": "Device Code Generated",
            "deviceCode": deviceCode.deviceCode,
            "userCode": deviceCode.userCode,
            "verificationURI": deviceCode.verificationURI,
            "expiresIn": String(Int(deviceCode.expiryDate.timeIntervalSinceNow)),
            "interval": String(deviceCode.interval),
            "scopes": deviceCode.scopes?.joined(separator: ", ") ?? "No scopes"
        ])
    }

    // Register controllers
    try app.register(collection: TodoController())
    try app.register(collection: OAuthController())
    try app.register(collection: AuthController())
    try app.register(collection: DashboardController())
    try app.register(collection: DeviceController())
}
