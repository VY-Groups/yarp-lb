using System.Text.Json;

namespace GatewayCore.Gslb.Contracts;

/// <summary>
/// Reject JSON objects with duplicate property names before typed
/// deserialization. Matching is ordinal case-insensitive to agree with the
/// web-default JSON options used by the HTTP report endpoint.
/// </summary>
public static class StrictJsonPropertyNames
{
    public static bool HasNoDuplicates(ReadOnlyMemory<byte> utf8Json)
    {
        try
        {
            using var document = JsonDocument.Parse(utf8Json,
                new JsonDocumentOptions { MaxDepth = 32 });
            return Visit(document.RootElement);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>
    /// For signed versioned wire messages, reject absent/extra fields and
    /// case-insensitive aliases before JSON deserialization. A canonical
    /// signature over known fields must not authorize unknown envelope data.
    /// </summary>
    public static bool HasExactTopLevelProperties(
        ReadOnlyMemory<byte> utf8Json, IReadOnlySet<string> requiredProperties)
    {
        ArgumentNullException.ThrowIfNull(requiredProperties);
        if (requiredProperties.Count == 0) return false;
        try
        {
            using var document = JsonDocument.Parse(utf8Json,
                new JsonDocumentOptions { MaxDepth = 32 });
            if (document.RootElement.ValueKind != JsonValueKind.Object) return false;
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (!requiredProperties.Contains(property.Name) ||
                    !names.Add(property.Name) || !Visit(property.Value))
                    return false;
            }
            return names.Count == requiredProperties.Count;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool Visit(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
            {
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var property in element.EnumerateObject())
                    if (!names.Add(property.Name) || !Visit(property.Value))
                        return false;
                return true;
            }
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                    if (!Visit(item)) return false;
                return true;
            default:
                return true;
        }
    }
}
