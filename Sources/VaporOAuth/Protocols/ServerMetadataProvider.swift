import Vapor

public protocol ServerMetadataProvider: Sendable {
    func getMetadata() async throws -> OAuthServerMetadata
}
