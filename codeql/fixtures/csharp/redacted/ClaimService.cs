// Expected findings: 0.
//
// The same six flows as the violating fixture, each routed through the sanctioned
// redaction helper. This is the fixture that protects teams who did the right
// thing: if the barrier ever stops being recognised, this fails loudly here
// rather than quietly in fifty pull requests.
namespace Fixture.Redacted;

using Fixture.Support;

public sealed class ClaimService
{
    private readonly ILogger _logger;

    public ClaimService(ILogger logger) => _logger = logger;

    public void StructuredArgument(Customer customer, string claimNumber)
    {
        _logger.LogInformation(
            "Claim {ClaimNumber} for policyholder {Ahv}",
            claimNumber,
            PiiRedaction.MaskAhv(customer.AhvNumber));
    }

    public void Interpolated(Customer customer)
    {
        _logger.LogInformation($"Resolving policyholder {PiiRedaction.MaskAhv(customer.AhvNumber)}");
    }

    public void DateOfBirth(Customer customer)
    {
        _logger.LogWarning("Age check failed for {Dob}", PiiRedaction.MaskDateOfBirth(customer.DateOfBirth));
    }

    public void ViaLocal(Customer customer)
    {
        var ahvNumber = PiiRedaction.MaskAhv(customer.AhvNumber);
        _logger.LogError("Lookup failed for {Ahv}", ahvNumber);
    }

    public void PaymentFailure(Customer customer, string claimNumber)
    {
        _logger.LogError(
            "Payout for {ClaimNumber} failed to account {Iban}",
            claimNumber,
            PiiRedaction.MaskExceptSuffix(customer.Iban, 4));
    }

    public void ViaToString(Customer customer)
    {
        _logger.LogInformation("DOB {Dob}", PiiRedaction.MaskDateOfBirth(customer.DateOfBirth));
    }
}
