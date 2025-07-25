import Vapor

struct AuthorizePostRequest: Sendable {
    let user: OAuthUser
    let userID: String
    let redirectURIBaseString: String
    let approveApplication: Bool
    let clientID: String
    let responseType: String
    let csrfToken: String
    let scopes: [String]?
    let codeChallenge: String?
    let codeChallengeMethod: String?
}

struct AuthorizePostHandler: Sendable {

    let tokenManager: any TokenManager
    let codeManager: any CodeManager
    let clientValidator: ClientValidator

    @Sendable
    func handleRequest(request: Request) async throws -> Response {
        let requestObject = try validateAuthPostRequest(request)
        var redirectURI = requestObject.redirectURIBaseString

        do {
            try await clientValidator.validateClient(
                clientID: requestObject.clientID, responseType: requestObject.responseType,
                redirectURI: requestObject.redirectURIBaseString, scopes: requestObject.scopes)
        } catch is AbortError {
            throw Abort(.forbidden)
        } catch {
            throw Abort(.badRequest)
        }

        guard request.session.data[SessionData.csrfToken] == requestObject.csrfToken else {
            throw Abort(.badRequest)
        }

        if requestObject.approveApplication {
            if requestObject.responseType == ResponseType.token {
                let accessToken = try await tokenManager.generateAccessToken(
                    clientID: requestObject.clientID,
                    userID: requestObject.userID,
                    scopes: requestObject.scopes,
                    expiryTime: 3600
                )
                redirectURI += "#token_type=bearer&access_token=\(accessToken.tokenString)&expires_in=3600"
            } else if requestObject.responseType == ResponseType.code {
                let generatedCode = try await codeManager.generateCode(
                    userID: requestObject.userID,
                    clientID: requestObject.clientID,
                    redirectURI: requestObject.redirectURIBaseString,
                    scopes: requestObject.scopes,
                    codeChallenge: requestObject.codeChallenge,
                    codeChallengeMethod: requestObject.codeChallengeMethod
                )
                redirectURI += "?code=\(generatedCode)"
            } else {
                redirectURI += "?error=invalid_request&error_description=unknown+response+type"
            }
        } else {
            redirectURI += "?error=access_denied&error_description=user+denied+the+request"
        }

        if let requestedScopes = requestObject.scopes {
            if !requestedScopes.isEmpty {
                redirectURI += "&scope=\(requestedScopes.joined(separator: "+"))"
            }
        }

        if let state = try? request.query.get(String.self, at: OAuthRequestParameters.state) {
            redirectURI += "&state=\(state)"
        }

        return request.redirect(to: redirectURI)
    }

    private func validateAuthPostRequest(_ request: Request) throws -> AuthorizePostRequest {
        let user = try request.auth.require(OAuthUser.self)

        guard let userID = user.id else {
            throw Abort(.unauthorized)
        }

        guard let redirectURIBaseString: String = request.query[OAuthRequestParameters.redirectURI] else {
            throw Abort(.badRequest)
        }

        // If approveApplication is missing or nil, treat as denial (false)
        let approveApplication: Bool = {
            if let approve = request.content[OAuthRequestParameters.applicationAuthorized] as Bool? {
                return approve
            } else {
                return false
            }
        }()

        guard let clientID: String = request.query[OAuthRequestParameters.clientID] else {
            throw Abort(.badRequest)
        }

        guard let responseType: String = request.query[OAuthRequestParameters.responseType] else {
            throw Abort(.badRequest)
        }

        guard let csrfToken: String = request.content[OAuthRequestParameters.csrfToken] else {
            throw Abort(.badRequest)
        }

        let scopes: [String]?

        if let scopeQuery: String = request.query[OAuthRequestParameters.scope] {
            scopes = scopeQuery.components(separatedBy: " ")
        } else {
            scopes = nil
        }

        let codeChallenge: String? = request.query[String.self, at: OAuthRequestParameters.codeChallenge]

        let codeChallengeMethod: String? = request.query[String.self, at: OAuthRequestParameters.codeChallengeMethod]

        return AuthorizePostRequest(
            user: user, userID: userID, redirectURIBaseString: redirectURIBaseString,
            approveApplication: approveApplication, clientID: clientID,
            responseType: responseType, csrfToken: csrfToken, scopes: scopes,
            codeChallenge: codeChallenge, codeChallengeMethod: codeChallengeMethod)
    }

}
