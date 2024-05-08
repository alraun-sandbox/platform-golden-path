// Expected findings: 0.
//
// The same operational moments as the violating fixture, with only safe values in
// the log line. If this reports, teams doing the right thing get noisy feedback.
import java.time.LocalDate;
import java.util.logging.Logger;

final class ClaimService {
    private final org.slf4j.Logger log;
    private final Logger auditLog = Logger.getLogger(ClaimService.class.getName());

    ClaimService(org.slf4j.Logger log) {
        this.log = log;
    }

    void registerClaim(Customer customer) {
        log.info(
                "Claim {} registered for customer {}",
                customer.getClaimNumber(),
                customer.getCustomerNumber());
    }

    void concatenateSafeValue(Customer customer) {
        log.info("Resolving policyholder reference " + customer.getPolicyholderReference());
    }

    void viaLocal(Customer customer) {
        String stableReference = customer.getPolicyholderReference();
        log.error("Lookup failed for {}", stableReference);
    }

    void paymentFailure(Customer customer) {
        log.error("Payout failed for claim {}", customer.getClaimNumber());
    }

    void derivedFromDateOfBirth(Customer customer) {
        boolean adult = LocalDate.now().getYear() - customer.getDateOfBirth().getYear() >= 18;
        log.info("Policyholder adult: {}", adult);
    }

    void javaUtilLogging(Customer customer) {
        auditLog.info("No claim features available for " + customer.getClaimNumber());
    }

    void consoleFallback(Customer customer) {
        System.out.printf("Scored claim %s%n", customer.getClaimNumber());
    }

    void readsButDoesNotLog(Customer customer) {
        String restrictedValue = customer.getDateOfBirth().toString();
        restrictedValue.length();
    }
}