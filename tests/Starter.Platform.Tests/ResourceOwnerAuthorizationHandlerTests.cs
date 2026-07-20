using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Shouldly;
using Starter.Platform.Auth;
using Xunit;

namespace Starter.Platform.Tests;

/// <summary>
/// The resource-owner rule: a caller may act on an owned resource only when
/// the operation is one of the ResourceOperations singletons AND the caller's
/// sub is the resource's owner. The handler never calls Fail(), so a
/// not-granted decision is the absence of success, not an explicit veto.
/// </summary>
public class ResourceOwnerAuthorizationHandlerTests
{
    private static readonly ResourceOwnerAuthorizationHandler Handler = new();

    public static TheoryData<OperationAuthorizationRequirement> KnownOperations => new()
    {
        ResourceOperations.Read,
        ResourceOperations.Update,
        ResourceOperations.Delete,
    };

    [Theory]
    [MemberData(nameof(KnownOperations))]
    public async Task Owner_OnAKnownOperation_Succeeds(OperationAuthorizationRequirement operation)
    {
        var ownerId = Guid.CreateVersion7();
        var context = ContextFor(operation, PrincipalWithSub(ownerId.ToString()), new OwnedResource(ownerId));

        await Handler.HandleAsync(context);

        context.HasSucceeded.ShouldBeTrue();
        context.HasFailed.ShouldBeFalse();
    }

    [Fact]
    public async Task DifferentUser_DoesNotSucceed()
    {
        var resource = new OwnedResource(Guid.CreateVersion7());
        var otherUser = PrincipalWithSub(Guid.CreateVersion7().ToString());
        var context = ContextFor(ResourceOperations.Read, otherUser, resource);

        await Handler.HandleAsync(context);

        context.HasSucceeded.ShouldBeFalse();
        // Absence of success is the failure - never an explicit Fail().
        context.HasFailed.ShouldBeFalse();
    }

    [Fact]
    public async Task ForeignRequirement_EvenNamedTheSame_DoesNotSucceed()
    {
        // A requirement that merely shares the "read" name is not one of the
        // ResourceOperations singletons; reference identity is what matches.
        var foreign = new OperationAuthorizationRequirement { Name = "read" };
        var ownerId = Guid.CreateVersion7();
        var context = ContextFor(foreign, PrincipalWithSub(ownerId.ToString()), new OwnedResource(ownerId));

        await Handler.HandleAsync(context);

        context.HasSucceeded.ShouldBeFalse();
        context.HasFailed.ShouldBeFalse();
    }

    [Fact]
    public async Task MissingSubClaim_DoesNotSucceed()
    {
        var resource = new OwnedResource(Guid.CreateVersion7());
        var context = ContextFor(ResourceOperations.Read, PrincipalWithSub(null), resource);

        await Handler.HandleAsync(context);

        context.HasSucceeded.ShouldBeFalse();
        context.HasFailed.ShouldBeFalse();
    }

    [Fact]
    public async Task UnparseableSubClaim_DoesNotSucceed()
    {
        var resource = new OwnedResource(Guid.CreateVersion7());
        var context = ContextFor(ResourceOperations.Read, PrincipalWithSub("not-a-guid"), resource);

        await Handler.HandleAsync(context);

        context.HasSucceeded.ShouldBeFalse();
        context.HasFailed.ShouldBeFalse();
    }

    private static AuthorizationHandlerContext ContextFor(
        OperationAuthorizationRequirement operation,
        ClaimsPrincipal user,
        IOwnedResource resource) =>
        new([operation], user, resource);

    private static ClaimsPrincipal PrincipalWithSub(string? sub)
    {
        var claims = sub is null ? [] : new[] { new Claim(StarterClaims.Sub, sub) };
        // A named authentication type makes the identity report authenticated,
        // matching a real bearer-authenticated principal.
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"));
    }
}
