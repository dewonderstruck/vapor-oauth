import Foundation

/// Generic builder for creating authorization details with any type registry
public struct GenericAuthorizationDetailBuilder<Registry: RARTypeRegistry> {
    private var type: String
    private var actions: [String] = []
    private var locations: [String] = []
    private var data: [String: AnyCodable] = [:]
    private var custom: [String: AnyCodable] = [:]
    private var registry: Registry

    public init(type: String, registry: Registry) {
        self.type = type
        self.registry = registry
    }

    public init<T: RARTypeProtocol>(type: T, registry: Registry) {
        self.type = type.rawValue
        self.registry = registry
    }

    @discardableResult
    public mutating func action(_ action: String) -> GenericAuthorizationDetailBuilder<Registry> {
        actions.append(action)
        return self
    }

    @discardableResult
    public mutating func action<T: RARActionProtocol>(_ action: T) -> GenericAuthorizationDetailBuilder<Registry> {
        actions.append(action.rawValue)
        return self
    }

    @discardableResult
    public mutating func actions(_ actions: [String]) -> GenericAuthorizationDetailBuilder<Registry> {
        self.actions.append(contentsOf: actions)
        return self
    }

    @discardableResult
    public mutating func actions<T: RARActionProtocol>(_ actions: [T]) -> GenericAuthorizationDetailBuilder<Registry> {
        self.actions.append(contentsOf: actions.map { $0.rawValue })
        return self
    }

    @discardableResult
    public mutating func location(_ location: String) -> GenericAuthorizationDetailBuilder<Registry> {
        locations.append(location)
        return self
    }

    @discardableResult
    public mutating func locations(_ locations: [String]) -> GenericAuthorizationDetailBuilder<Registry> {
        self.locations.append(contentsOf: locations)
        return self
    }

    @discardableResult
    public mutating func data(_ key: String, _ value: Any) -> GenericAuthorizationDetailBuilder<Registry> {
        data[key] = AnyCodable(value)
        return self
    }

    @discardableResult
    public mutating func custom(_ key: String, _ value: Any) -> GenericAuthorizationDetailBuilder<Registry> {
        custom[key] = AnyCodable(value)
        return self
    }

    /// Use default actions for the type if no actions are specified
    @discardableResult
    public mutating func useDefaultActions() -> GenericAuthorizationDetailBuilder<Registry> {
        if actions.isEmpty {
            // Try to find the type in the registry and use its default actions
            if let rarType = Registry.RegistryType(rawValue: type) {
                actions = rarType.defaultActions
            }
        }
        return self
    }

    public func build() -> AuthorizationDetail {
        return AuthorizationDetail(
            type: type,
            actions: actions.isEmpty ? nil : actions,
            locations: locations.isEmpty ? nil : locations,
            data: data.isEmpty ? nil : data,
            custom: custom.isEmpty ? nil : custom
        )
    }
}

/// Type alias for backward compatibility
public typealias AuthorizationDetailBuilder = GenericAuthorizationDetailBuilder<DefaultRARTypeRegistry>

// MARK: - Convenience Methods

extension AuthorizationDetailBuilder {
    /// Create a payment initiation authorization detail
    public static func paymentInitiation(
        actions: [RARAction] = [.initiate, .status, .cancel],
        locations: [String] = [],
        data: [String: Any] = [:]
    ) -> AuthorizationDetailBuilder {
        var builder = AuthorizationDetailBuilder(type: RARType.paymentInitiation.rawValue, registry: DefaultRARTypeRegistry())
        builder = builder.actions(actions)

        if !locations.isEmpty {
            builder = builder.locations(locations)
        }

        for (key, value) in data {
            builder = builder.data(key, value)
        }

        return builder
    }

    /// Create an account access authorization detail
    public static func accountAccess(
        actions: [RARAction] = [.read],
        locations: [String] = [],
        data: [String: Any] = [:]
    ) -> AuthorizationDetailBuilder {
        var builder = AuthorizationDetailBuilder(type: RARType.accountAccess.rawValue, registry: DefaultRARTypeRegistry())
        builder = builder.actions(actions)

        if !locations.isEmpty {
            builder = builder.locations(locations)
        }

        for (key, value) in data {
            builder = builder.data(key, value)
        }

        return builder
    }

    /// Create a data access authorization detail
    public static func dataAccess(
        actions: [RARAction] = [.read],
        locations: [String] = [],
        data: [String: Any] = [:]
    ) -> AuthorizationDetailBuilder {
        var builder = AuthorizationDetailBuilder(type: RARType.dataAccess.rawValue, registry: DefaultRARTypeRegistry())
        builder = builder.actions(actions)

        if !locations.isEmpty {
            builder = builder.locations(locations)
        }

        for (key, value) in data {
            builder = builder.data(key, value)
        }

        return builder
    }

    /// Create a custom authorization detail with default actions
    public static func custom(
        type: String,
        locations: [String] = [],
        data: [String: Any] = [:]
    ) -> AuthorizationDetailBuilder {
        var builder = AuthorizationDetailBuilder(type: type, registry: DefaultRARTypeRegistry())
        builder = builder.useDefaultActions()  // This will be empty for custom types

        if !locations.isEmpty {
            builder = builder.locations(locations)
        }

        for (key, value) in data {
            builder = builder.data(key, value)
        }

        return builder
    }
}
