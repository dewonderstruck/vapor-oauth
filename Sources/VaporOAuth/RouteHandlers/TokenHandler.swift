import Vapor

struct TokenHandler: Sendable {

    let tokenAuthenticator = TokenAuthenticator()
    let refreshTokenHandler: RefreshTokenHandler
    let clientCredentialsTokenHandler: ClientCredentialsTokenHandler
    let tokenResponseGenerator: TokenResponseGenerator
    let authCodeTokenHandler: AuthCodeTokenHandler
    let passwordTokenHandler: PasswordTokenHandler
    var deviceCodeTokenHandler: DeviceCodeTokenHandler
    let extensionManager: OAuthExtensionManager

    init(
        clientValidator: ClientValidator, tokenManager: any TokenManager, scopeValidator: ScopeValidator,
        codeManager: any CodeManager, deviceCodeManager: any DeviceCodeManager, userManager: any UserManager, logger: Logger,
        extensionManager: OAuthExtensionManager
    ) {
        self.extensionManager = extensionManager
        tokenResponseGenerator = TokenResponseGenerator()
        refreshTokenHandler = RefreshTokenHandler(
            scopeValidator: scopeValidator, tokenManager: tokenManager,
            clientValidator: clientValidator, tokenAuthenticator: tokenAuthenticator,
            tokenResponseGenerator: tokenResponseGenerator)
        clientCredentialsTokenHandler = ClientCredentialsTokenHandler(
            clientValidator: clientValidator,
            scopeValidator: scopeValidator,
            tokenManager: tokenManager,
            tokenResponseGenerator: tokenResponseGenerator)
        authCodeTokenHandler = AuthCodeTokenHandler(
            clientValidator: clientValidator, tokenManager: tokenManager,
            codeManager: codeManager,
            tokenResponseGenerator: tokenResponseGenerator)
        passwordTokenHandler = PasswordTokenHandler(
            clientValidator: clientValidator, scopeValidator: scopeValidator,
            userManager: userManager, logger: logger, tokenManager: tokenManager,
            tokenResponseGenerator: tokenResponseGenerator)
        deviceCodeTokenHandler = DeviceCodeTokenHandler(
            clientValidator: clientValidator, scopeValidator: scopeValidator, deviceCodeManager: deviceCodeManager,
            tokenManager: tokenManager, tokenResponseGenerator: tokenResponseGenerator)
    }

    @Sendable
    func handleRequest(request: Request) async throws -> Response {
        // Process request through extensions
        let processedRequest = try await extensionManager.processTokenRequest(request)

        guard let grantType: String = processedRequest.content[OAuthRequestParameters.grantType] else {
            return try tokenResponseGenerator.createResponse(
                error: OAuthResponseParameters.ErrorType.invalidRequest,
                description: "Request was missing the 'grant_type' parameter")
        }

        switch grantType {
        case OAuthFlowType.authorization.rawValue:
            return try await authCodeTokenHandler.handleAuthCodeTokenRequest(processedRequest)
        case OAuthFlowType.password.rawValue:
            return try await passwordTokenHandler.handlePasswordTokenRequest(processedRequest)
        case OAuthFlowType.clientCredentials.rawValue:
            return try await clientCredentialsTokenHandler.handleClientCredentialsTokenRequest(processedRequest)
        case OAuthFlowType.refresh.rawValue:
            return try await refreshTokenHandler.handleRefreshTokenRequest(processedRequest)
        case OAuthFlowType.deviceCode.rawValue:
            return try await deviceCodeTokenHandler.handleDeviceCodeTokenRequest(processedRequest)
        default:
            return try tokenResponseGenerator.createResponse(
                error: OAuthResponseParameters.ErrorType.unsupportedGrant,
                description: "This server does not support the '\(grantType)' grant type")
        }

    }

}
