import Vapor
import Leaf

struct DashboardController: RouteCollection {
    func boot(routes: any RoutesBuilder) throws {
        let dashboard = routes.grouped(AuthMiddleware())
        dashboard.get(use: index)
    }
    
    func index(req: Request) async throws -> View {
        guard let user = req.auth.get(User.Public.self) else {
            throw Abort(.unauthorized)
        }
        
        let dateFormatter = DateFormatter()
        dateFormatter.dateStyle = .medium
        let createdAtString = user.createdAt.map { dateFormatter.string(from: $0) } ?? "Unknown"
        
        return try await req.view.render("dashboard", [
            "title": "Dashboard",
            "username": user.username,
            "email": user.email,
            "createdAt": createdAtString
        ])
    }
}