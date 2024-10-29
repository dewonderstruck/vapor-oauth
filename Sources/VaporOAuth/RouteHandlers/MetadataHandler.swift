import Vapor
import NIOHTTP1

struct MetadataHandler: Sendable {
    let metadataProvider: ServerMetadataProvider

    @Sendable
    func handleRequest(request: Request) async throws -> Response {
        let metadata = try await metadataProvider.getMetadata()
        return try createMetadataResponse(metadata: metadata)
    }

    private func createMetadataResponse(metadata: OAuthServerMetadata) throws -> Response {
        let response = Response(status: .ok)
        try response.content.encode(metadata)
        
         // Set required headers per RFC 8414 Section 3
        response.headers.contentType = .json
        // Set all cache control directives explicitly
        response.headers.replaceOrAdd(
            name: .cacheControl,
            value: "no-store, no-cache, max-age=0, must-revalidate"
        )
        response.headers.replaceOrAdd(name: .pragma, value: "no-cache")
        
        return response
    }   

    private func createErrorResponse(
        status: HTTPStatus,
        errorMessage: String,
        errorDescription: String
    ) throws -> Response {
        let response = Response(status: status)
        try response.content.encode(ErrorResponse(
            error: errorMessage,
            errorDescription: errorDescription
        ))
        return response
    }
}

extension MetadataHandler {
    struct ErrorResponse: Content {
        let error: String
        let errorDescription: String

        enum CodingKeys: String, CodingKey {
            case error
            case errorDescription = "error_description"
        }
    }   
}
