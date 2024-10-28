import Vapor

public struct OAuth2: LifecycleHandler {
    let codeManager: CodeManager
    let tokenManager: TokenManager
    let deviceCodeManager: DeviceCodeManager
    let clientRetriever: ClientRetriever
    let authorizeHandler: AuthorizeHandler
    let userManager: UserManager
    let validScopes: [String]?
    let resourceServerRetriever: ResourceServerRetriever
    let oAuthHelper: OAuthHelper

    public init(
        codeManager: CodeManager = EmptyCodeManager(),
        tokenManager: TokenManager,
        deviceCodeManager: DeviceCodeManager = EmptyDeviceCodeManager(),
        clientRetriever: ClientRetriever,
        authorizeHandler: AuthorizeHandler = EmptyAuthorizationHandler(),
        userManager: UserManager = EmptyUserManager(),
        validScopes: [String]? = nil,
        resourceServerRetriever: ResourceServerRetriever = EmptyResourceServerRetriever(),
        oAuthHelper: OAuthHelper
    ) {
        self.codeManager = codeManager
        self.clientRetriever = clientRetriever
        self.authorizeHandler = authorizeHandler
        self.tokenManager = tokenManager
        self.deviceCodeManager = deviceCodeManager
        self.userManager = userManager
        self.validScopes = validScopes
        self.resourceServerRetriever = resourceServerRetriever
        self.oAuthHelper = oAuthHelper
    }

    public func didBoot(_ application: Application) throws {
        addRoutes(to: application)
        application.oAuthHelper = oAuthHelper
    }

    private func addRoutes(to app: Application) {
        let scopeValidator = ScopeValidator(validScopes: validScopes, clientRetriever: clientRetriever)
        
        let clientValidator = ClientValidator(
            clientRetriever: clientRetriever,
            scopeValidator: scopeValidator,
            environment: app.environment
        )
        
        let tokenHandler = TokenHandler(
            clientValidator: clientValidator,
            tokenManager: tokenManager,
            scopeValidator: scopeValidator,
            codeManager: codeManager,
            deviceCodeManager: deviceCodeManager,
            userManager: userManager,
            logger: app.logger
        )
        
        let tokenIntrospectionHandler = TokenIntrospectionHandler(
            clientValidator: clientValidator,
            tokenManager: tokenManager,
            userManager: userManager
        )
        
        let authorizeGetHandler = AuthorizeGetHandler(
            authorizeHandler: authorizeHandler,
            clientValidator: clientValidator
        )
        let authorizePostHandler = AuthorizePostHandler(
            tokenManager: tokenManager,
            codeManager: codeManager,
            clientValidator: clientValidator
        )
        
        let deviceAuthorizationHandler = DeviceAuthorizationHandler(
            deviceCodeManager: deviceCodeManager,
            clientValidator: clientValidator,
            scopeValidator: scopeValidator
        )
        
        let resourceServerAuthenticator = ResourceServerAuthenticator(resourceServerRetriever: resourceServerRetriever)
        
        // returning something like "Authenticate with GitHub page"
        app.get("oauth", "authorize", use: authorizeGetHandler.handleRequest)
        // pressing something like "Allow/Deny Access" button on "Authenticate with GitHub page". Returns a code.
        app.grouped(OAuthUser.guardMiddleware()).post("oauth", "authorize", use: authorizePostHandler.handleRequest)
        
        app.post("oauth", "device_authorization", use: deviceAuthorizationHandler.handleRequest)
        
        // client requesting access/refresh token with code from POST /authorize endpoint
        app.post("oauth", "token", use: tokenHandler.handleRequest)
        
        let tokenIntrospectionAuthMiddleware = TokenIntrospectionAuthMiddleware(resourceServerAuthenticator: resourceServerAuthenticator)
        let resourceServerProtected = app.routes.grouped(tokenIntrospectionAuthMiddleware)
        resourceServerProtected.post("oauth", "token_info", use: tokenIntrospectionHandler.handleRequest)
    }
}

public extension OAuth2 {
    func makeClientValidator() -> ClientValidator {
        return ClientValidator(
            clientRetriever: self.clientRetriever,
            scopeValidator: ScopeValidator(validScopes: self.validScopes, clientRetriever: self.clientRetriever),
            environment: .development
        )
    }
    func makeAuthorizeGetHandler() -> AuthorizeGetHandler {
        return AuthorizeGetHandler(
            authorizeHandler: self.authorizeHandler,
            clientValidator: self.makeClientValidator()
        )
    }
    func getAuthorizeHandler() -> AuthorizeHandler {
        return self.authorizeHandler
    }
}
