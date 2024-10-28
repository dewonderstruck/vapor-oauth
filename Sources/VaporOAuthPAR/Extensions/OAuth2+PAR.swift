import Vapor
import VaporOAuth

public extension OAuth2 {
    func enablePAR(
        app: Application,
        storage: PARRequestStorage,
        configuration: PARConfiguration = PARConfiguration()
    ) {
        // Create PAR handler with injected dependencies
        let parHandler = PARHandler(
            clientValidator: self.makeClientValidator(),
            storage: storage,
            configuration: configuration
        )
        
        // Register PAR endpoint
        app.post("oauth", "par") { req in
            try await parHandler.handlePARRequest(req)
        }
        
        // Create authorize handler wrapper
        let authorizeGetHandler = self.makeAuthorizeGetHandler()
        
        // Extend authorize endpoint to support PAR
        let existingHandler = app.routes.all.first { $0.path == ["oauth", "authorize"] }
        existingHandler?.responder = PARAuthorizeResponder(
            storage: storage,
            authorizeHandler: self.getAuthorizeHandler(),
            fallbackHandler: authorizeGetHandler
        )
    }
}

private struct PARAuthorizeResponder: AsyncResponder {
    let storage: PARRequestStorage
    let authorizeHandler: AuthorizeHandler
    let fallbackHandler: AuthorizeGetHandler
    
    func respond(to request: Request) async throws -> Response {
        if let requestURI = try? request.query.get(String.self, at: "request_uri") {
            guard let parRequest = try await storage.retrieve(requestURI: requestURI) else {
                throw Abort(.badRequest, reason: "Invalid request_uri")
            }
            
            // Convert PARRequest to AuthorizationRequestObject
            let authRequest = AuthorizationRequestObject(
                responseType: parRequest.responseType,
                clientID: parRequest.clientID,
                redirectURI: URI(string: parRequest.redirectURI),
                scope: parRequest.scope,
                state: parRequest.state,
                csrfToken: [UInt8].random(count: 32).hex,
                codeChallenge: parRequest.codeChallenge,
                codeChallengeMethod: parRequest.codeChallengeMethod
            )
            
            return try await authorizeHandler.handleAuthorizationRequest(request, authorizationRequestObject: authRequest)
        }
        return try await fallbackHandler.handleRequest(request: request)
    }
}
