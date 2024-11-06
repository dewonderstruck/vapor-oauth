import XCTVapor
@testable import VaporOAuth

class IssuerIdentificationTests: XCTestCase {
    var app: Application!
    
    override func setUp() async throws {
        app = try await Application.make(.testing)
    }
    
    override func tearDown() async throws {
        try await app.asyncShutdown()
        try await super.tearDown()
    }
    
    func testEmptyIssuerError() async throws {
        let oauth = OAuth2(
            issuer: "",  // Empty issuer
            jwksEndpoint: "https://auth.example.com/.well-known/jwks.json",
            tokenManager: FakeTokenManager(),
            clientRetriever: StaticClientRetriever(clients: []), oAuthHelper: .local(
                tokenAuthenticator: nil,
                userManager: nil,
                tokenManager: nil
            )
        )
        
        do {
            _ = try await oauth.withIssuerIdentification()
            XCTFail("Should throw error for empty issuer")
        } catch let error as IssuerIdentificationError {
            XCTAssertEqual(error.description, IssuerIdentificationError.missingIssuer.description)
        }
    }
    
    func testMetadataUnavailableError() async throws {
        struct FailingMetadataProvider: ServerMetadataProvider {
            func getMetadata() async throws -> OAuthServerMetadata {
                throw IssuerIdentificationError.metadataUnavailable(underlying: NSError(domain: "Test", code: 1, userInfo: nil))
            }
        }
        
        let oauth = OAuth2(
            issuer: "https://auth.example.com",
            jwksEndpoint: "https://auth.example.com/.well-known/jwks.json",
            tokenManager: FakeTokenManager(),
            clientRetriever: StaticClientRetriever(clients: []),
            oAuthHelper: .local(
                tokenAuthenticator: nil,
                userManager: nil,
                tokenManager: nil
            ), metadataProvider: FailingMetadataProvider()
        )
        
        do {
            _ = try await oauth.withIssuerIdentification()
            XCTFail("Should throw error for unavailable metadata")
        } catch let error as IssuerIdentificationError {
            if case .metadataUnavailable = error {
                // Success
            } else {
                XCTFail("Wrong error type")
            }
        }
    }
}
