// Expected findings: several.
//
// Each method is a mistake we have actually seen in review, from a human or from
// a coding agent. They are separate methods so that a regression in one flow
// shape does not hide behind another still working.
namespace Fixture.Violating;

using Fixture.Support;

public sealed class ClaimService
{
    private readonly ILogger _logger;

    public ClaimService(ILogger logger) => _logger = logger;

    // 1. The obvious one: a restricted property as a structured-logging argument.
    public void StructuredArgument(Customer customer, string claimNumber)
    {
        _logger.LogInformation(
            "Claim {ClaimNumber} for policyholder {Ahv}",
            claimNumber,
            customer.AhvNumber);
    }

    // 2. String interpolation, which is how it usually actually appears.
    public void Interpolated(Customer customer)
    {
        _logger.LogInformation($"Resolving policyholder {customer.AhvNumber}");
    }

    // 3. Date of birth, which people forget is restricted at all.
    public void DateOfBirth(Customer customer)
    {
        _logger.LogWarning("Age check failed for {Dob}", customer.DateOfBirth);
    }

    // 4. Laundered through a local. The taint has to survive the assignment.
    public void ViaLocal(Customer customer)
    {
        var ahvNumber = customer.AhvNumber;
        _logger.LogError("Lookup failed for {Ahv}", ahvNumber);
    }

    // 5. Bank details, on the error path, where logging feels most justified.
    public void PaymentFailure(Customer customer, string claimNumber)
    {
        _logger.LogError(
            "Payout for {ClaimNumber} failed to account {Iban}",
            claimNumber,
            customer.Iban);
    }

    // 6. ToString() does not launder it either.
    public void ViaToString(Customer customer)
    {
        _logger.LogInformation("DOB {Dob}", customer.DateOfBirth.ToString());
    }
}
