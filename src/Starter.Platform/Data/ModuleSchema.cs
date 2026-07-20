namespace Starter.Platform.Data;

/// <summary>
/// One schema's persistence descriptor, contributed to DI by a module's
/// public Add&lt;Module&gt;Module bootstrap extension: the
/// schema name and the DbContext type that owns it.
/// The context type stays internal to its module; consumers resolve it
/// from a scope by type - readiness walks these descriptors to prove
/// migrations-at-head, and the integration fixture walks them to migrate
/// from zero, so the app and the suite can never disagree about what a
/// module registers.
/// </summary>
public sealed record ModuleSchema(string Name, Type ContextType);
