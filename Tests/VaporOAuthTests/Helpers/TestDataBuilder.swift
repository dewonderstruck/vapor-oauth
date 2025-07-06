import Vapor
import XCTVapor

@testable import VaporOAuth

class TestDataBuilder {
    static func getOAuth2Application(
        codeManager: CodeManager = EmptyCodeManager(),
        deviceCodeManager: DeviceCodeManager = EmptyDeviceCodeManager(),
        tokenManager: TokenManager = StubTokenManager(),
        clientRetriever: ClientRetriever = FakeClientGetter(),
        userManager: UserManager = EmptyUserManager(),
        authorizeHandler: AuthorizeHandler = EmptyAuthorizationHandler(),
        validScopes: [String]? = nil,
        resourceServerRetriever: ResourceServerRetriever = EmptyResourceServerRetriever(),
        environment: Environment = .testing,
        logger: CapturingLogger? = nil,
        sessions: FakeSessions? = nil,
        registeredUsers: [OAuthUser] = [],
        configuration: OAuthConfiguration? = nil,
        enableRARExtension: Bool = false,
        enablePARExtension: Bool = false,
        jwtConfiguration: JWTConfiguration = .disabled
    ) async throws -> Application {
        let app = try await Application.make(environment)

        if let sessions = sessions {
            app.sessions.use { _ in sessions }
        }

        app.middleware.use(FakeAuthenticationMiddleware(allowedUsers: registeredUsers))
        app.middleware.use(app.sessions.middleware)

        if let configuration = configuration {
            app.oauth = configuration
        } else {
            app.oauth = OAuthConfiguration(deviceVerificationURI: "")
        }

        let _ = "https://auth.example.com"

        // Register OAuth extensions (RAR, PAR, etc.)
        let extensionManager = OAuthExtensionManager()
        if enableRARExtension {
            extensionManager.register(RichAuthorizationRequestsExtension())
        }
        if enablePARExtension {
            extensionManager.register(PushedAuthorizationRequestsExtension())
        }

        let oauthProvider = OAuth2(
            codeManager: codeManager,
            tokenManager: tokenManager,
            deviceCodeManager: deviceCodeManager,
            clientRetriever: clientRetriever,
            authorizeHandler: authorizeHandler,
            userManager: userManager,
            validScopes: validScopes,
            resourceServerRetriever: resourceServerRetriever,
            oAuthHelper: .local(
                tokenAuthenticator: nil,
                userManager: nil,
                tokenManager: nil
            ),
            extensionManager: extensionManager,
            jwtConfiguration: jwtConfiguration
        )

        app.lifecycle.use(oauthProvider)

        // Manually trigger the lifecycle handler since testable() doesn't do it
        try await oauthProvider.didBoot(app)

        do {
            _ = try app.testable(method: .running)
        } catch {
            try await app.asyncShutdown()
            throw error
        }

        return app
    }

    static func getTokenRequestResponse(
        with app: Application,
        grantType: String?,
        clientID: String?,
        clientSecret: String?,
        redirectURI: String? = nil,
        code: String? = nil,
        scope: String? = nil,
        username: String? = nil,
        password: String? = nil,
        refreshToken: String? = nil,
        codeVerifier: String? = nil
    ) async throws -> XCTHTTPResponse {
        struct RequestData: Content {
            var grantType: String?
            var clientID: String?
            var clientSecret: String?
            var redirectURI: String?
            var code: String?
            var scope: String?
            var username: String?
            var password: String?
            var refreshToken: String?
            var codeVerifier: String?

            enum CodingKeys: String, CodingKey {
                case username, password, scope, code
                case grantType = "grant_type"
                case clientID = "client_id"
                case clientSecret = "client_secret"
                case redirectURI = "redirect_uri"
                case refreshToken = "refresh_token"
                case codeVerifier = "code_verifier"
            }
        }

        let requestData = RequestData(
            grantType: grantType,
            clientID: clientID,
            clientSecret: clientSecret,
            redirectURI: redirectURI,
            code: code,
            scope: scope,
            username: username,
            password: password,
            refreshToken: refreshToken,
            codeVerifier: codeVerifier
        )

        return try await withCheckedThrowingContinuation { continuation in
            do {
                try app.test(
                    .POST,
                    "/oauth/token",
                    beforeRequest: { request in
                        try request.content.encode(requestData, as: .urlEncodedForm)
                    },
                    afterResponse: { response in
                        continuation.resume(returning: response)
                    }
                )
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }

    static func getAuthRequestResponse(
        with app: Application,
        responseType: String?,
        clientID: String?,
        redirectURI: String?,
        scope: String?,
        state: String?,
        codeChallenge: String? = nil,
        codeChallengeMethod: String? = nil
    ) async throws -> XCTHTTPResponse {
        var queries: [String] = []

        if let responseType = responseType {
            queries.append("response_type=\(responseType)")
        }

        if let clientID = clientID {
            queries.append("client_id=\(clientID)")
        }

        if let redirectURI = redirectURI {
            queries.append("redirect_uri=\(redirectURI)")
        }

        if let scope = scope {
            queries.append("scope=\(scope)")
        }

        if let state = state {
            queries.append("state=\(state)")
        }

        // Add PKCE parameters to query string
        if let codeChallenge = codeChallenge {
            queries.append("code_challenge=\(codeChallenge)")
        }

        if let codeChallengeMethod = codeChallengeMethod {
            queries.append("code_challenge_method=\(codeChallengeMethod)")
        }

        let requestQuery = queries.joined(separator: "&")

        return try await withCheckedThrowingContinuation { continuation in
            do {
                try app.test(
                    .GET, "/oauth/authorize?\(requestQuery)",
                    afterResponse: { response in
                        continuation.resume(returning: response)
                    })
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }

    static func getAuthResponseResponse(
        with app: Application,
        approve: Bool?,
        clientID: String?,
        redirectURI: String?,
        responseType: String?,
        scope: String?,
        state: String?,
        csrfToken: String?,
        user: OAuthUser?,
        sessionCookie: HTTPCookies? = nil,
        sessionID: String? = nil
    ) async throws -> XCTHTTPResponse {
        var queries: [String] = []

        if let clientID = clientID {
            queries.append("client_id=\(clientID)")
        }

        if let redirectURI = redirectURI {
            queries.append("redirect_uri=\(redirectURI)")
        }

        if let state = state {
            queries.append("state=\(state)")
        }

        if let scope = scope {
            queries.append("scope=\(scope)")
        }

        if let responseType = responseType {
            queries.append("response_type=\(responseType)")
        }

        let requestQuery = queries.joined(separator: "&")

        struct RequestBody: Encodable {
            var applicationAuthorized: Bool?
            var csrfToken: String?
        }

        var requestBody = RequestBody()
        requestBody.applicationAuthorized = approve
        requestBody.csrfToken = csrfToken

        return try await withCheckedThrowingContinuation { continuation in
            do {
                try app.test(
                    .POST,
                    "/oauth/authorize?\(requestQuery)",
                    beforeRequest: { request in
                        if let sessionID = sessionID {
                            request.headers.cookie = ["vapor-session": .init(string: sessionID)]
                        }
                        if let sessionCookie = sessionCookie {
                            request.headers.cookie = sessionCookie
                        }
                        try request.content.encode(requestBody, as: .urlEncodedForm)

                        if let user = user {
                            request.headers.basicAuthorization = .init(
                                username: user.username,
                                password: user.password
                            )
                        }
                    },
                    afterResponse: { response in
                        continuation.resume(returning: response)
                    }
                )
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }

    static let anyUserID: String = "12345-asbdsadi"
    static func anyOAuthUser() -> OAuthUser {
        return OAuthUser(
            userID: TestDataBuilder.anyUserID,
            username: "hansolo",
            emailAddress: "han.solo@therebelalliance.com",
            password: "leia"
        )
    }

    static func getDeviceAuthorizationResponse(
        with app: Application,
        clientID: String?,
        clientSecret: String?,
        scope: String?
    ) async throws -> XCTHTTPResponse {
        return try await withCheckedThrowingContinuation { continuation in
            do {
                try app.test(.POST, "oauth/device_authorization") { req in
                    var content: [String: String] = [:]
                    if let clientID = clientID {
                        content["client_id"] = clientID
                    }
                    if let clientSecret = clientSecret {
                        content["client_secret"] = clientSecret
                    }
                    if let scope = scope {
                        content["scope"] = scope
                    }
                    try req.content.encode(content)
                } afterResponse: { response in
                    continuation.resume(returning: response)
                }
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }

    static func getDeviceTokenResponse(
        with app: Application,
        deviceCode: String,
        clientID: String,
        clientSecret: String
    ) async throws -> XCTHTTPResponse {
        return try await withCheckedThrowingContinuation { continuation in
            do {
                try app.test(.POST, "oauth/token") { req in
                    try req.content.encode([
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                        "device_code": deviceCode,
                        "client_id": clientID,
                        "client_secret": clientSecret,
                    ])
                } afterResponse: { response in
                    continuation.resume(returning: response)
                }
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }

    // MARK: - Test Keys for JWT Configuration

    /// Test RSA private key (2048-bit) for testing purposes only
    /// See: Tests/VaporOAuthTests/TestKeys/rsa-private.pem
    static let rsaPrivateKeyPEM = """
        -----BEGIN PRIVATE KEY-----
        MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDGS0RGWVQfHk2x
        wd6ZdA0Fe9NwlscqjBpDF74E+8XPTa7r7qJfDlJyWOefN/C6Npx4LSu+H0j9Wzvp
        MBK+P9z0Y4BttWHUGDO7JJouVWgsVEEEHxOlcKASMeeXoDYn+FaRaIHHAuowA2Zd
        tIx/kI35bsaGzjx1631ug0UuPDAJ9bpdkCEY8Wbr4B1+Jf3xzO5dWFVu7GxoJCSw
        IJNle1lus7ePENhsSdIIeKwF5lANe7E/o+oJTbs4oalkVqagwT5yk+xMYd1T/6Bg
        T353xSsjoN38ntMnSF76ophQ7A86m7Ng0TnxQDPSKb5R5a9mzLotxcU4Z9oUQcUT
        eo/qLTS7AgMBAAECggEAX57d/pqG8TaYurZFVHRc7x8GGA3tXvwOkfn5/Mc4XT4V
        stnxXKs4YMG0d9fu8qzxCRanOFg3x0zeeBVhhHKhZwwwWzcTRMai84S0ANHYmT/L
        1mPyAl5sIjoEdt6gHugnPplJs6EZMywAigFNmxonDHg5rbn399kmNEuC6cfGVpZZ
        X7KS5buRXv4v8faFh+638UpLPR7WBjeMffytveH9ZlcWiLs1hOyeAT5zwPo2NVU4
        gmsk0sIXmq0blQY6ozEouziZZIlKv6GQmBiNccb8r9nKta5StjJ3jKM5niglspfC
        EnLXaRGIg/m2lUXjVWbvSFQUH65I8AU/FgvuAG3f0QKBgQDzt3HMOCoqI8WTf3fM
        bzibsyJ1D1do3+gw9nUZVyPibGPgg+gQdOCqlAalZUGhVwGHGVW4PEoRV1Hqz/BE
        UrD/C+QDqr4XI+CuP2pgSccsnjYJKGyoYNNSGXlD4nej/cFzMdJuJW8NMT/z5cVx
        JPzWvntwTd8+HLWS4DofhjVbEwKBgQDQScHNiE8ZHmTL+vNPmYi/kWFpj13GfIQn
        dXREGBSkP2TOHDaCahzZF38h7DaOAbYNiqYsDN8Hu/6uQZDXaRBm9ft1Awz/UDRU
        TRkkm9j8xdQd+PjSC9g6DAwb98jNjjflKisItm6gv16H0fg87zFjeBOTqAyuzmda
        qvwq6vCMuQKBgEFXprANQujHbHqOS21JSJEeJxfhhBr/JT6zZVPk9B8J1oFkfDyl
        SXMSevGvQzhhnmw9U6kwqN8bXUAqfg2jagcHhhuhlJOZr+yn3fpw7XC9/ljYOMGw
        LBgv8j5MIq2aJFqhOf0EFlEgKjhXG2epdgyRR4Elr7v0cI4vhgXbssR3AoGACmb0
        l9gr4xxCenFw/1OyoaaYD9aKH2SOkQ3rnY76UO2dkjGUg1TbVfg3cDFE1Di/p9N5
        0w9dgBxibr91hVyI5it4wHJDjuiphGBJViu2XYFfw5NwkcTnqpZ5cFginilxHy/I
        8Gl0AvErvmq9FAX6GHahu6kT4RML1Fpft6D+HHkCgYBqV1XQ0vvn0Wzr/No5kMxb
        BZ2C1K09K/Gp5TFnhntPVjQQ3pUBFWAMkAbN/2dXB/i8QN6oeeci90BEGZMBdJK2
        emZJ6hmCHh9HWtN4/F5GeiPXnwxrVxXFLsiWSNw6WeWYMErnJxmpAhOYfB/z17k/
        iz92TNXoTZHtzUqOZT7+KA==
        -----END PRIVATE KEY-----
        """

    /// Test ECDSA private key (P-256) for testing purposes only
    /// See: Tests/VaporOAuthTests/TestKeys/ecdsa-private.pem
    static let ecdsaPrivateKeyPEM = """
        -----BEGIN EC PRIVATE KEY-----
        MHcCAQEEIINZC6wIVdoQIOiRx6TJGWClM3HHCaaSsJlhQvjzR6jyoAoGCCqGSM49
        AwEHoUQDQgAE9eGEiSGcPNcZofknuU8jQpvWFEODC3w3yUHPlGcka9VvmKfg7sTX
        qekjPODTmCMlaomB1abEn4UxM7671qYpAw==
        -----END EC PRIVATE KEY-----
        """
}
