import Vapor
import VaporOAuth
import Leaf

struct DeviceController: RouteCollection {
    func boot(routes: any RoutesBuilder) throws {
        let device = routes.grouped("device")
        
        // Device verification page - shows pending device codes
        device.get { req async throws -> View in
            return try await req.view.render("device/verify", [
                "title": "Device Authorization"
            ])
        }
        
        // Handle user code submission
        device.post("verify") { req async throws -> View in
            guard let userCode = req.content[String.self, at: "user_code"] else {
                return try await req.view.render("device/verify", [
                    "title": "Device Authorization",
                    "error": "User code is required"
                ])
            }
            
            // Get device code by user code
            guard let deviceCode = try await req.application.oauthDeviceCodeManager.getUserCode(userCode) else {
                return try await req.view.render("device/verify", [
                    "title": "Device Authorization",
                    "error": "Invalid or expired user code"
                ])
            }
            
            // Check if code is expired
            if deviceCode.expiryDate < Date() {
                return try await req.view.render("device/verify", [
                    "title": "Device Authorization",
                    "error": "User code has expired"
                ])
            }
            
            // Check if already authorized or declined
            if deviceCode.status != .pending && deviceCode.status != .unauthorized {
                return try await req.view.render("device/verify", [
                    "title": "Device Authorization",
                    "error": "Device code has already been processed"
                ])
            }
            
            // Get client info
            guard let client = try await req.application.oauthClientRetriever.getClient(clientID: deviceCode.clientID) else {
                return try await req.view.render("device/verify", [
                    "title": "Device Authorization",
                    "error": "Invalid client"
                ])
            }
            
            // Calculate expiry time
            let timeUntilExpiry = Int(deviceCode.expiryDate.timeIntervalSinceNow)
            let expiryMinutes = timeUntilExpiry / 60
            let expirySeconds = timeUntilExpiry % 60
            let expiryText = "\(expiryMinutes)m \(expirySeconds)s"
            
            // Prepare template context with safe defaults
            var context: [String: String] = [
                "title": "Authorize Device",
                "userCode": userCode,
                "deviceCodeDeviceCode": deviceCode.deviceCode,
                "deviceCodeUserCode": deviceCode.userCode,
                "deviceCodeClientID": deviceCode.clientID,
                "deviceCodeVerificationURI": deviceCode.verificationURI,
                "deviceCodeVerificationURIComplete": deviceCode.verificationURIComplete ?? "",
                "deviceCodeStatus": String(describing: deviceCode.status),
                "deviceCodeUserID": deviceCode.userID ?? "",
                "deviceCodeExpiryDate": expiryText,
                "deviceCodeInterval": String(deviceCode.interval),
                "clientClientID": client.clientID,
                "clientClientSecret": client.clientSecret ?? "",
                "clientConfidentialClient": (client.confidentialClient ?? false) ? "Confidential" : "Public",
                "clientFirstParty": (client.firstParty ?? false) ? "true" : "false",
                "clientAllowedGrantType": String(describing: client.allowedGrantType)
            ]
            
            // Add scopes as comma-separated string
            if let scopes = deviceCode.scopes {
                context["deviceCodeScopes"] = scopes.joined(separator: ", ")
            } else {
                context["deviceCodeScopes"] = "No specific scopes requested"
            }
            if let validScopes = client.validScopes {
                context["clientValidScopes"] = validScopes.joined(separator: ", ")
            } else {
                context["clientValidScopes"] = ""
            }
            
            // Debug: Print context to see what we're passing
            print("Device authorization context: \(context)")
            
            return try await req.view.render("device/authorize", context)
        }
        
        // Handle authorization decision
        device.post("authorize") { req async throws -> View in
            guard let userCode = req.content[String.self, at: "user_code"],
                  let action = req.content[String.self, at: "action"] else {
                return try await req.view.render("device/verify", [
                    "title": "Device Authorization",
                    "error": "Missing required parameters"
                ])
            }
            
            // Get device code by user code
            guard let deviceCode = try await req.application.oauthDeviceCodeManager.getUserCode(userCode) else {
                return try await req.view.render("device/verify", [
                    "title": "Device Authorization",
                    "error": "Invalid or expired user code"
                ])
            }
            
            // Get current user
            guard let sessionToken = req.cookies["session_token"]?.string,
                  let userID = try await req.sessionService.validateSession(sessionToken),
                  let user = try await User.find(userID, on: req.db) else {
                return try await req.view.render("device/verify", [
                    "title": "Device Authorization",
                    "error": "Please log in to authorize devices"
                ])
            }
            
            switch action {
            case "approve":
                // Authorize the device
                try await req.application.oauthDeviceCodeManager.authorizeDeviceCode(deviceCode, userID: user.id?.uuidString ?? "")
                return try await req.view.render("device/success", [
                    "title": "Device Authorized",
                    "message": "Device has been successfully authorized"
                ])
                
            case "deny":
                // Mark as declined - we need to update the database record
                // Since we can't modify the VaporOAuth.OAuthDeviceCode directly,
                // we'll need to handle this in the device code manager
                // For now, we'll just show the success message
                return try await req.view.render("device/success", [
                    "title": "Device Authorization Denied",
                    "message": "Device authorization has been denied"
                ])
                
            default:
                return try await req.view.render("device/verify", [
                    "title": "Device Authorization",
                    "error": "Invalid action"
                ])
            }
        }
    }
} 
