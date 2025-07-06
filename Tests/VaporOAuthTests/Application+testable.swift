import XCTVapor

@testable import VaporOAuth

extension Application {
    static func testableWithTester() async throws -> (Application, XCTApplicationTester) {
        let app = try await Application.make(.testing)
        do {
            let tester = try app.testable()
            return (app, tester)
        } catch {
            try await app.asyncShutdown()
            throw error
        }
    }

    static func testable() async throws -> Application {
        let (app, _) = try await self.testableWithTester()
        return app
    }
}
