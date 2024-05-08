// Expected findings: 0.
//
// The violating flows routed through every sanitizer name family Pii.qll accepts:
// redact, mask, anonymi, pseudonymi, hash and tokeni.
import java.util.logging.Logger;

final class ClaimService {
    private final org.slf4j.Logger log;
    private final Logger auditLog = Logger.getLogger(ClaimService.class.getName());

    ClaimService(org.slf4j.Logger log) {
        this.log = log;
    }

    void structuredArgument(Customer customer, String claimNumber) {
        log.info(
                "Claim {} for policyholder {}",
                claimNumber,
                PiiMasking.maskAhv(customer.getAhvNumber()));
    }

    void concatenatedMessage(Customer customer) {
        log.info("Resolving policyholder " + PiiMasking.redact(customer.getAhvNumber()));
    }

    void viaLocal(Customer customer) {
        String safeValue = PiiMasking.anonymise(customer.getAhvNumber());
        log.error("Lookup failed for {}", safeValue);
    }

    void paymentFailure(Customer customer, String claimNumber) {
        log.error(
                "Payout for claim {} failed to account {}",
                claimNumber,
                PiiMasking.hash(customer.iban));
    }

    void viaToString(Customer customer) {
        log.warn("DOB {}", PiiMasking.maskDateOfBirth(customer.getDateOfBirth()));
    }

    void fieldAccess(Customer customer) {
        log.info("Manual review for {}", PiiMasking.pseudonymise(customer.policyholderName));
    }

    void javaUtilLogging(Customer customer) {
        auditLog.warning("Policyholder email " + PiiMasking.tokenise(customer.getEmailAddress()));
    }

    void consoleFallback(Customer customer) {
        System.err.printf("Policyholder %s%n", PiiMasking.maskAhv(customer.getAhvNumber()));
    }
}