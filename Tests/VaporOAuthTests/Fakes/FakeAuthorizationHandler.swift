import Vapor

@testable import VaporOAuth

final class FakeAuthorizationHandler: AuthorizeHandler, @unchecked Sendable {
    var capturedRequest: Request?
    var capturedAuthorizationRequestObject: AuthorizationRequestObject?
    var shouldAuthorize: Bool

    init(shouldAuthorize: Bool = true) {
        self.shouldAuthorize = shouldAuthorize
    }

    func handleAuthorizationRequest(
        _ request: Request,
        authorizationRequestObject: AuthorizationRequestObject
    ) async throws -> Response {
        capturedRequest = request
        capturedAuthorizationRequestObject = authorizationRequestObject

        let response = Response(status: shouldAuthorize ? .ok : .unauthorized)
        return response
    }

    func handleAuthorizationError(_ errorType: AuthorizationError) async throws -> Response {
        return Response(status: .badRequest)
    }
}
