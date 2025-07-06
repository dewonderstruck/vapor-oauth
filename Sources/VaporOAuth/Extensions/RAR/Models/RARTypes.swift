import Foundation

/// Default RAR type registry implementation
public struct DefaultRARTypeRegistry: RARTypeRegistry {
    public typealias RegistryType = RARType
    public typealias RegistryAction = RARAction

    private var customTypes: Set<String> = []

    public init() {}

    public func registerCustomType(_ type: String) -> RARType? {
        // For predefined types, return the enum case
        if let rarType = RARType(rawValue: type) {
            return rarType
        }
        // For custom types, add to registry and return nil (handled separately)
        // Note: In a real implementation, you might want to use a class or actor for mutable state
        return nil
    }

    public func isTypeRegistered(_ type: String) -> Bool {
        return RARType(rawValue: type) != nil || customTypes.contains(type)
    }

    public func getAllTypes() -> [RARType] {
        return Array(RARType.allCases)
    }

    public func getAllActions() -> [RARAction] {
        return Array(RARAction.allCases)
    }

    // Internal method to add custom types for testing
    internal mutating func addCustomType(_ type: String) {
        customTypes.insert(type)
    }
}

/// Predefined RAR types for common use cases as defined in RFC 9396
public enum RARType: String, RARTypeProtocol {
    case paymentInitiation = "payment_initiation"
    case accountAccess = "account_access"
    case fundConfirmation = "funds_confirmation"
    case domesticPayment = "domestic_payment"
    case internationalPayment = "international_payment"
    case accountInformation = "account_information"
    case cardPayment = "card_payment"
    case fileAccess = "file_access"
    case dataAccess = "data_access"

    public var description: String {
        switch self {
        case .paymentInitiation:
            return "Payment Initiation"
        case .accountAccess:
            return "Account Access"
        case .fundConfirmation:
            return "Funds Confirmation"
        case .domesticPayment:
            return "Domestic Payment"
        case .internationalPayment:
            return "International Payment"
        case .accountInformation:
            return "Account Information"
        case .cardPayment:
            return "Card Payment"
        case .fileAccess:
            return "File Access"
        case .dataAccess:
            return "Data Access"
        }
    }

    public var requiresValidation: Bool {
        switch self {
        case .paymentInitiation, .domesticPayment, .internationalPayment:
            return true  // Financial operations require extra validation
        default:
            return false
        }
    }

    public var defaultActions: [String] {
        switch self {
        case .paymentInitiation:
            return [RARAction.initiate.rawValue, RARAction.status.rawValue, RARAction.cancel.rawValue]
        case .accountAccess, .accountInformation:
            return [RARAction.read.rawValue]
        case .fileAccess, .dataAccess:
            return [RARAction.read.rawValue, RARAction.write.rawValue]
        default:
            return []
        }
    }
}

/// Common actions for RAR as defined in RFC 9396
public enum RARAction: String, RARActionProtocol {
    case read = "read"
    case write = "write"
    case delete = "delete"
    case create = "create"
    case initiate = "initiate"
    case status = "status"
    case cancel = "cancel"
    case approve = "approve"
    case reject = "reject"

    public var description: String {
        switch self {
        case .read:
            return "Read access"
        case .write:
            return "Write access"
        case .delete:
            return "Delete access"
        case .create:
            return "Create access"
        case .initiate:
            return "Initiate action"
        case .status:
            return "Check status"
        case .cancel:
            return "Cancel action"
        case .approve:
            return "Approve action"
        case .reject:
            return "Reject action"
        }
    }

    public var requiresSpecialPermission: Bool {
        switch self {
        case .delete, .approve, .reject:
            return true  // Destructive or administrative actions
        default:
            return false
        }
    }
}

/// Generic RAR configuration that works with any type registry
public struct GenericRARConfiguration<Registry: RARTypeRegistry>: Sendable {
    /// Whether to allow custom RAR types beyond predefined ones
    public let allowCustomTypes: Bool
    /// Maximum number of authorization details allowed per request
    public let maxAuthorizationDetails: Int
    /// Whether to validate URIs in locations field
    public let validateURIs: Bool
    /// Allowed RAR types (if nil, all predefined types are allowed)
    public let allowedTypes: Set<Registry.RegistryType>?
    /// Allowed actions (if nil, all predefined actions are allowed)
    public let allowedActions: Set<Registry.RegistryAction>?
    /// Type registry for dynamic type management
    public let typeRegistry: Registry
    public init(
        allowCustomTypes: Bool = true,
        maxAuthorizationDetails: Int = 10,
        validateURIs: Bool = true,
        allowedTypes: Set<Registry.RegistryType>? = nil,
        allowedActions: Set<Registry.RegistryAction>? = nil,
        typeRegistry: Registry
    ) {
        self.allowCustomTypes = allowCustomTypes
        self.maxAuthorizationDetails = maxAuthorizationDetails
        self.validateURIs = validateURIs
        self.allowedTypes = allowedTypes
        self.allowedActions = allowedActions
        self.typeRegistry = typeRegistry
    }
    /// Default configuration that allows all predefined types and actions
    public static func `default`(with registry: Registry) -> GenericRARConfiguration<Registry> {
        return GenericRARConfiguration(typeRegistry: registry)
    }
    /// Strict configuration that only allows specific types and actions
    public static func strict(
        allowedTypes: Set<Registry.RegistryType>,
        allowedActions: Set<Registry.RegistryAction>,
        registry: Registry
    ) -> GenericRARConfiguration<Registry> {
        return GenericRARConfiguration(
            allowCustomTypes: false,
            maxAuthorizationDetails: 5,
            validateURIs: true,
            allowedTypes: allowedTypes,
            allowedActions: allowedActions,
            typeRegistry: registry
        )
    }
}

/// Type alias for backward compatibility
public typealias RARConfiguration = GenericRARConfiguration<DefaultRARTypeRegistry>

/// Extension to provide default RARConfiguration
extension RARConfiguration {
    public static let `default` = RARConfiguration(typeRegistry: DefaultRARTypeRegistry())
}
