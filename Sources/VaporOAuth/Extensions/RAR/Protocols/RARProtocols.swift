import Foundation

/// Protocol for RAR types that can be used in authorization details
public protocol RARTypeProtocol: RawRepresentable, CaseIterable, Sendable, Hashable where RawValue == String {
    /// Human-readable description of the RAR type
    var description: String { get }
    /// Whether this type requires specific validation
    var requiresValidation: Bool { get }
    /// Default actions for this type
    var defaultActions: [String] { get }
}

/// Protocol for RAR actions that can be used in authorization details
public protocol RARActionProtocol: RawRepresentable, CaseIterable, Sendable, Hashable where RawValue == String {
    /// Human-readable description of the RAR action
    var description: String { get }
    /// Whether this action requires special permissions
    var requiresSpecialPermission: Bool { get }
}

/// Protocol for RAR type registry that allows dynamic registration of types
public protocol RARTypeRegistry: Sendable {
    associatedtype RegistryType: RARTypeProtocol
    associatedtype RegistryAction: RARActionProtocol
    /// Register a custom RAR type
    func registerCustomType(_ type: String) -> RegistryType?
    /// Check if a type is registered
    func isTypeRegistered(_ type: String) -> Bool
    /// Get all registered types
    func getAllTypes() -> [RegistryType]
    /// Get all registered actions
    func getAllActions() -> [RegistryAction]
}
