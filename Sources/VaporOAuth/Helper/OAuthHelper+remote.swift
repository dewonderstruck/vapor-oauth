import Vapor

extension OAuthHelper {
    public static func remote(
        tokenIntrospectionEndpoint: String,
        client: Client,
        resourceServerUsername: String,
        resourceServerPassword: String
    ) -> Self {
        actor TokenResponseHolder {
            var remoteTokenResponse: RemoteTokenResponse?
            
            func getOrSetResponse(_ setter: () async throws -> RemoteTokenResponse) async throws -> RemoteTokenResponse {
                if let response = remoteTokenResponse {
                    return response
                }
                let newResponse = try await setter()
                remoteTokenResponse = newResponse
                return newResponse
            }
        }
        let tokenResponseHolder = TokenResponseHolder()
        
        return OAuthHelper(
            assertScopes: { scopes, request in
                let remoteTokenResponse = try await tokenResponseHolder.getOrSetResponse {
                    var response: RemoteTokenResponse?
                    try await setupRemoteTokenResponse(
                        request: request,
                        tokenIntrospectionEndpoint: tokenIntrospectionEndpoint,
                        client: client,
                        resourceServerUsername: resourceServerUsername,
                        resourceServerPassword: resourceServerPassword,
                        remoteTokenResponse: &response
                    )
                    guard let response = response else {
                        throw Abort(.internalServerError)
                    }
                    return response
                }

                if let requiredScopes = scopes {
                    guard let tokenScopes = remoteTokenResponse.scopes else {
                        throw Abort(.unauthorized)
                    }

                    for scope in requiredScopes {
                        if !tokenScopes.contains(scope) {
                            throw Abort(.unauthorized)
                        }
                    }
                }
            },
            user: { request in
                let remoteTokenResponse = try await tokenResponseHolder.getOrSetResponse {
                    var response: RemoteTokenResponse?
                    try await setupRemoteTokenResponse(
                        request: request,
                        tokenIntrospectionEndpoint: tokenIntrospectionEndpoint,
                        client: client,
                        resourceServerUsername: resourceServerUsername,
                        resourceServerPassword: resourceServerPassword,
                        remoteTokenResponse: &response
                    )
                    guard let response = response else {
                        throw Abort(.internalServerError)
                    }
                    return response
                }

                guard let user = remoteTokenResponse.user else {
                    throw Abort(.unauthorized)
                }

                return user
            }
        )
    }

    private static func setupRemoteTokenResponse(
        request: Request,
        tokenIntrospectionEndpoint: String,
        client: Client,
        resourceServerUsername: String,
        resourceServerPassword: String,
        remoteTokenResponse: inout RemoteTokenResponse?
    ) async throws {
        let token = try request.getOAuthToken()

        var headers = HTTPHeaders()
        headers.basicAuthorization = .init(
            username: resourceServerUsername,
            password: resourceServerPassword
        )

        struct Token: Content {
            let token: String
        }
        let tokenInfoResponse = try await client.post(
            URI(string: tokenIntrospectionEndpoint),
            headers: headers,
            content: Token(token: token)
        ).get()

        let tokenInfoJSON = tokenInfoResponse.content

        guard let tokenActive: Bool = tokenInfoJSON[OAuthResponseParameters.active], tokenActive else {
            throw Abort(.unauthorized)
        }

        var scopes: [String]?
        var oauthUser: OAuthUser?

        if let tokenScopes: String = tokenInfoJSON[OAuthResponseParameters.scope] {
            scopes = tokenScopes.components(separatedBy: " ")
        }

        if let userID: String = tokenInfoJSON[OAuthResponseParameters.userID] {
            guard let username: String = tokenInfoJSON[OAuthResponseParameters.username] else {
                throw Abort(.internalServerError)
            }
            oauthUser = OAuthUser(userID: userID, username: username,
                                  emailAddress: tokenInfoJSON[String.self, at: OAuthResponseParameters.email],
                                  password: "")
        }

        remoteTokenResponse = RemoteTokenResponse(scopes: scopes, user: oauthUser)

    }
}

struct RemoteTokenResponse: Sendable {
    let scopes: [String]?
    let user: OAuthUser?
}
