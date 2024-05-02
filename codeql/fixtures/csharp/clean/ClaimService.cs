// Expected findings: 0.
//
// Everything here is what we want teams to write. If this fixture ever reports a
// finding, the query has become noisy and teams will start ignoring it - which is
// worse than not having the query at all.
namespace Fixture.Clean;

using Fixture.Support;

public sealed class ClaimService
{
    private readonly ILogger _logger;

    public ClaimService(ILogger logger) => _logger = logger;

    public void RegisterClaim(Customer customer, string claimNumber)
    {
        // The safe identifier, structured logging, no interpolation.
        _logger.LogInformation(
            "Claim {ClaimNumber} registered for customer {CustomerNumber}",
            claimNumber,
            customer.CustomerNumber);
    }

    public void LogCount(int count)
    {
        _logger.LogInformation("Processed {Count} claims", count);
    }

    public void LogDerivedValue(Customer customer)
    {
        // A boolean derived from personal data is not personal data.
        var isAdult = DateTime.UtcNow.Year - customer.DateOfBirth.Year >= 18;
        _logger.LogInformation("Policyholder adult: {IsAdult}", isAdult);
    }

    public void ReturnsButDoesNotLog(Customer customer)
    {
        // Reading a restricted field is fine. Only reaching a log sink is not.
        var ahv = customer.AhvNumber;
        _ = ahv?.Length;
    }
}
