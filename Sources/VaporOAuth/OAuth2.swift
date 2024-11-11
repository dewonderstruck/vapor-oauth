import Vapor

public struct OAuth2: LifecycleHandler {
    let codeManager: any CodeManager
    let tokenManager: any TokenManager
    let deviceCodeManager: any DeviceCodeManager
    let clientRetriever: any ClientRetriever
    let authorizeHandler: any AuthorizeHandler
    let userManager: any UserManager
    let validScopes: [String]?
    let resourceServerRetriever: any ResourceServerRetriever
    let oAuthHelper: OAuthHelper
    let metadataProvider: any ServerMetadataProvider

    public init(
        codeManager: CodeManager = EmptyCodeManager(),
        tokenManager: TokenManager,
        deviceCodeManager: DeviceCodeManager = EmptyDeviceCodeManager(),
        clientRetriever: ClientRetriever,
        authorizeHandler: AuthorizeHandler = EmptyAuthorizationHandler(),
        userManager: UserManager = EmptyUserManager(),
        validScopes: [String]? = nil,
        resourceServerRetriever: any ResourceServerRetriever = EmptyResourceServerRetriever(),
        oAuthHelper: OAuthHelper,
        metadataProvider: (any ServerMetadataProvider)? = nil
    ) {
        self.metadataProvider = metadataProvider ?? DefaultServerMetadataProvider(
            validScopes: validScopes,
            clientRetriever: clientRetriever,
            hasCodeManager: !(codeManager is EmptyCodeManager),
            hasDeviceCodeManager: !(deviceCodeManager is EmptyDeviceCodeManager),
            hasTokenIntrospection: !(resourceServerRetriever is EmptyResourceServerRetriever),
            hasUserManager: !(userManager is EmptyUserManager)
        )
        self.codeManager = codeManager
        self.tokenManager = tokenManager
        self.deviceCodeManager = deviceCodeManager
        self.clientRetriever = clientRetriever
        self.authorizeHandler = authorizeHandler
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

        let tokenRevocationHandler = TokenRevocationHandler(
            clientValidator: clientValidator,
            tokenManager: tokenManager
        )

        let metadataHandler = MetadataHandler(metadataProvider: metadataProvider)

        let resourceServerAuthenticator = ResourceServerAuthenticator(resourceServerRetriever: resourceServerRetriever)

        // returning something like "Authenticate with GitHub page"
        app.get("oauth", "authorize", use: authorizeGetHandler.handleRequest)
        // pressing something like "Allow/Deny Access" button on "Authenticate with GitHub page". Returns a code.
        app.grouped(OAuthUser.guardMiddleware()).post("oauth", "authorize", use: authorizePostHandler.handleRequest)
    
        app.post("oauth", "device_authorization", use: deviceAuthorizationHandler.handleRequest)
    
        // client requesting access/refresh token with code from POST /authorize endpoint
        app.post("oauth", "token", use: tokenHandler.handleRequest)

        // Revoke a token
        app.post("oauth", "revoke", use: tokenRevocationHandler.handleRequest)

        // RFC 8414 required endpoints
        app.get(".well-known", "oauth-authorization-server", use: metadataHandler.handleRequest)

        let tokenIntrospectionAuthMiddleware = TokenIntrospectionAuthMiddleware(resourceServerAuthenticator: resourceServerAuthenticator)
        let resourceServerProtected = app.routes.grouped(tokenIntrospectionAuthMiddleware)
        resourceServerProtected.post("oauth", "token_info", use: tokenIntrospectionHandler.handleRequest)
    }
}
