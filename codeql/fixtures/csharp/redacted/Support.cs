// Minimal stand-ins for the framework and domain types the query keys off.
// Fixtures are analysed with --build-mode=none and are never compiled or
// executed, so these only have to be shaped correctly.
namespace Fixture.Support;

public sealed class Customer
{
    public string CustomerNumber { get; set; } = string.Empty;
    public string FirstName { get; set; } = string.Empty;
    public string? AhvNumber { get; set; }
    public DateOnly DateOfBirth { get; set; }
    public string Email { get; set; } = string.Empty;
    public string? Iban { get; set; }
}

public interface ILogger
{
    void LogInformation(string message, params object?[] args);
    void LogWarning(string message, params object?[] args);
    void LogError(string message, params object?[] args);
}

public static class PiiRedaction
{
    public static string Mask(string? value) => "[redacted]";
    public static string MaskAhv(string? value) => "756.****.****.00";
    public static string MaskDateOfBirth(DateOnly? value) => "0000-**-**";
    public static string MaskExceptSuffix(string? value, int visible = 2) => "[redacted]";
}
