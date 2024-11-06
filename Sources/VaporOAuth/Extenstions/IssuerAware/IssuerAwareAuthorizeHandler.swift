import Vapor
import VaporOAuth

public struct IssuerAwareAuthorizeHandler: AuthorizeHandler {
    private let wrapped: AuthorizeHandler
    private let issuer: String
    
    public init(wrapped: AuthorizeHandler, issuer: String) {
        // Ensure issuer is a valid URL and ASCII serializable
        guard let _ = URL(string: issuer),
              issuer.canBeConverted(to: .ascii) else {
            preconditionFailure("Issuer must be a valid URL and ASCII serializable")
        }
        self.wrapped = wrapped
        self.issuer = issuer
    }
    
    public func handleAuthorizationRequest(
        _ request: Request,
        authorizationRequestObject: AuthorizationRequestObject
    ) async throws -> Response {
        let response = try await wrapped.handleAuthorizationRequest(
            request,
            authorizationRequestObject: authorizationRequestObject
        )
        
        // RFC 9207: Add issuer to all authorization responses
        return try addIssuer(to: response)
    }
    
    public func handleAuthorizationError(_ error: AuthorizationError) async throws -> Response {
        let response = try await wrapped.handleAuthorizationError(error)
        
        // RFC 9207: Add issuer to all error responses
        return try addIssuer(to: response)
    }
    
    private func addIssuer(to response: Response) throws -> Response {
        let modifiedResponse = response
        
        // For redirect responses (successful authorization)
        if response.status == .seeOther,
           let location = response.headers.first(name: .location),
           var components = URLComponents(string: location) {
            var queryItems = components.queryItems ?? []
            
            // RFC 9207: Add iss parameter
            queryItems.append(URLQueryItem(name: "iss", value: issuer))
            components.queryItems = queryItems
            
            if let newLocation = components.string {
                modifiedResponse.headers.replaceOrAdd(name: .location, value: newLocation)
            }
        }
        
        // For error responses (JSON)
        if response.status.code >= 400 {
            if let body = response.body.string,
               let data = body.data(using: .utf8),
               var json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                // RFC 9207: Add iss parameter
                json["iss"] = issuer
                if let newData = try? JSONSerialization.data(withJSONObject: json),
                   let newBody = String(data: newData, encoding: .utf8) {
                    modifiedResponse.body = Response.Body(string: newBody)
                }
            }
        }
        
        return modifiedResponse
    }
}
