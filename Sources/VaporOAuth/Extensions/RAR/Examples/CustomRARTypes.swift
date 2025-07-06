import Foundation

/// Example of custom RAR types for a specific domain
public enum CustomRARType: String, RARTypeProtocol {
    case documentAccess = "document_access"
    case userProfile = "user_profile"
    case notificationSettings = "notification_settings"
    case apiAccess = "api_access"

    public var description: String {
        switch self {
        case .documentAccess:
            return "Document Access"
        case .userProfile:
            return "User Profile"
        case .notificationSettings:
            return "Notification Settings"
        case .apiAccess:
            return "API Access"
        }
    }

    public var requiresValidation: Bool {
        switch self {
        case .documentAccess, .apiAccess:
            return true  // Sensitive operations
        default:
            return false
        }
    }

    public var defaultActions: [String] {
        switch self {
        case .documentAccess:
            return [CustomRARAction.read.rawValue, CustomRARAction.download.rawValue]
        case .userProfile:
            return [CustomRARAction.read.rawValue, CustomRARAction.update.rawValue]
        case .notificationSettings:
            return [CustomRARAction.read.rawValue, CustomRARAction.update.rawValue]
        case .apiAccess:
            return [CustomRARAction.execute.rawValue]
        }
    }
}

/// Example of custom RAR actions for a specific domain
public enum CustomRARAction: String, RARActionProtocol {
    case read = "read"
    case write = "write"
    case delete = "delete"
    case download = "download"
    case upload = "upload"
    case update = "update"
    case execute = "execute"
    case subscribe = "subscribe"
    case unsubscribe = "unsubscribe"

    public var description: String {
        switch self {
        case .read:
            return "Read access"
        case .write:
            return "Write access"
        case .delete:
            return "Delete access"
        case .download:
            return "Download files"
        case .upload:
            return "Upload files"
        case .update:
            return "Update records"
        case .execute:
            return "Execute operations"
        case .subscribe:
            return "Subscribe to notifications"
        case .unsubscribe:
            return "Unsubscribe from notifications"
        }
    }

    public var requiresSpecialPermission: Bool {
        switch self {
        case .delete, .execute:
            return true  // Destructive or administrative actions
        default:
            return false
        }
    }
}

/// Custom RAR type registry for the domain
public struct CustomRARTypeRegistry: RARTypeRegistry {
    public typealias RegistryType = CustomRARType
    public typealias RegistryAction = CustomRARAction

    private var customTypes: Set<String> = []

    public init() {}

    public func registerCustomType(_ type: String) -> CustomRARType? {
        // For predefined types, return the enum case
        if let rarType = CustomRARType(rawValue: type) {
            return rarType
        }

        // For custom types, add to registry and return nil (handled separately)
        // Note: In a real implementation, you might want to use a class or actor for mutable state
        return nil
    }

    public func isTypeRegistered(_ type: String) -> Bool {
        return CustomRARType(rawValue: type) != nil || customTypes.contains(type)
    }

    public func getAllTypes() -> [CustomRARType] {
        return Array(CustomRARType.allCases)
    }

    public func getAllActions() -> [CustomRARAction] {
        return Array(CustomRARAction.allCases)
    }
}

/// Example usage of the custom RAR types
public struct CustomRARExample {

    /// Example of creating authorization details with custom types
    public static func createCustomAuthorizationDetails() -> [AuthorizationDetail] {
        // Create authorization details directly without the builder
        let documentAccess = AuthorizationDetail(
            type: CustomRARType.documentAccess.rawValue,
            actions: [CustomRARAction.read.rawValue, CustomRARAction.download.rawValue],
            locations: ["https://api.example.com/documents"],
            data: ["documentId": AnyCodable("12345"), "maxSize": AnyCodable("10MB")],
            custom: nil
        )

        let userProfile = AuthorizationDetail(
            type: CustomRARType.userProfile.rawValue,
            actions: CustomRARType.userProfile.defaultActions,
            locations: ["https://api.example.com/profile"],
            data: ["scope": AnyCodable("basic")],
            custom: nil
        )

        let customType = AuthorizationDetail(
            type: "custom_analytics",
            actions: ["aggregate", "export"],
            locations: ["https://api.example.com/analytics"],
            data: ["timeRange": AnyCodable("30d")],
            custom: nil
        )

        return [documentAccess, userProfile, customType]
    }

    /// Example of creating a custom RAR configuration
    public static func createCustomConfiguration() -> GenericRARConfiguration<CustomRARTypeRegistry> {
        let registry = CustomRARTypeRegistry()

        return GenericRARConfiguration(
            allowCustomTypes: true,
            maxAuthorizationDetails: 5,
            validateURIs: true,
            allowedTypes: Set(CustomRARType.allCases),
            allowedActions: Set(CustomRARAction.allCases),
            typeRegistry: registry
        )
    }

    /// Example of using the protocol-based type system
    public static func demonstrateTypeSystem() {
        // Show how the protocol-based system works
        let customType: CustomRARType = .documentAccess
        print("Type: \(customType.rawValue)")
        print("Description: \(customType.description)")
        print("Requires validation: \(customType.requiresValidation)")
        print("Default actions: \(customType.defaultActions)")

        let customAction: CustomRARAction = .download
        print("Action: \(customAction.rawValue)")
        print("Description: \(customAction.description)")
        print("Requires special permission: \(customAction.requiresSpecialPermission)")

        // Show how the registry works
        let registry = CustomRARTypeRegistry()
        print("All types: \(registry.getAllTypes().map { $0.rawValue })")
        print("All actions: \(registry.getAllActions().map { $0.rawValue })")
    }
}

// MARK: - Swift Type System Features Demonstration

/// Example showing how to use Swift's associated types and protocols
public struct SwiftTypeSystemExample {

    /// Generic function that works with any RAR type registry
    public static func processWithAnyRegistry<Registry: RARTypeRegistry>(
        registry: Registry,
        type: String
    ) -> String {
        if registry.isTypeRegistered(type) {
            return "Type '\(type)' is registered in the registry"
        } else {
            return "Type '\(type)' is not registered in the registry"
        }
    }

    /// Example of using the generic configuration
    public static func createStrictConfiguration() -> GenericRARConfiguration<CustomRARTypeRegistry> {
        let registry = CustomRARTypeRegistry()

        return GenericRARConfiguration.strict(
            allowedTypes: [.documentAccess, .userProfile],
            allowedActions: [.read, .download],
            registry: registry
        )
    }

    /// Example of type-safe authorization detail creation
    public static func createTypeSafeAuthorizationDetail() -> AuthorizationDetail {
        // Using the protocol-based types ensures type safety
        let type = CustomRARType.documentAccess
        let actions = [CustomRARAction.read, CustomRARAction.download]

        return AuthorizationDetail(
            type: type.rawValue,
            actions: actions.map { $0.rawValue },
            locations: ["https://api.example.com/documents"],
            data: ["documentId": AnyCodable("12345")],
            custom: nil
        )
    }
}
