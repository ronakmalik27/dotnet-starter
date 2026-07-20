using System.Reflection;
using Shouldly;
using Xunit;

namespace Starter.Architecture.Tests;

/// <summary>
/// A tripwire: no float or double anywhere in the kernel's public surface.
/// The banned-API scan extends to every module; guarding the kernel first
/// catches numeric-precision mistakes at the foundation, before they can
/// spread.
/// </summary>
public class SharedKernelSurfaceTests
{
    private static readonly Type[] BannedNumericTypes = [typeof(float), typeof(double)];

    [Fact]
    public void SharedKernel_PublicSurface_UsesNoFloatOrDouble()
    {
        var offenders = typeof(Starter.SharedKernel.Ids).Assembly.GetExportedTypes()
            .SelectMany(PublicSignatureTypes)
            .Where(BansViolated)
            .ToList();

        offenders.ShouldBeEmpty();
    }

    private static IEnumerable<Type> PublicSignatureTypes(Type type)
    {
        const BindingFlags visible =
            BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static;

        foreach (var field in type.GetFields(visible))
        {
            yield return field.FieldType;
        }

        foreach (var property in type.GetProperties(visible))
        {
            yield return property.PropertyType;
        }

        foreach (var method in type.GetMethods(visible))
        {
            yield return method.ReturnType;
            foreach (var parameter in method.GetParameters())
            {
                yield return parameter.ParameterType;
            }
        }

        foreach (var constructor in type.GetConstructors(visible))
        {
            foreach (var parameter in constructor.GetParameters())
            {
                yield return parameter.ParameterType;
            }
        }
    }

    private static bool BansViolated(Type signatureType)
    {
        var unwrapped = signatureType.IsByRef || signatureType.IsArray
            ? signatureType.GetElementType()!
            : signatureType;

        return BannedNumericTypes.Contains(unwrapped)
            || (unwrapped.IsGenericType
                && unwrapped.GetGenericArguments().Any(BansViolated));
    }
}
