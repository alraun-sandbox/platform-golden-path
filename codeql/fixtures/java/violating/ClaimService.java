// Expected findings: several.
//
// These methods mirror mistakes that look plausible in the Spring Boot risk
// engine: controller audit lines, repository failures and exception paths. Each
// flow is separate so one working source/sink shape cannot hide another regressing.
import java.util.logging.Logger;

final class ClaimService {
    private final org.slf4j.Logger log;
    private final Logger auditLog = Logger.getLogger(ClaimService.class.getName());

    ClaimService(org.slf4j.Logger log) {
        this.log = log;
    }

    // 1. The obvious one: a restricted getter as a structured-logging argument.
    void structuredArgument(Customer customer, String claimNumber) {
        log.info(
                "Claim {} for policyholder {}",
                claimNumber,
                customer.getAhvNumber());
    }

    // 2. Java's interpolation-shaped mistake: concatenating PII into the message.
    void concatenatedMessage(Customer customer) {
        log.info("Resolving policyholder " + customer.getAhvNumber());
    }

    // 3. Laundered through a local. The taint has to survive the assignment.
    void viaLocal(Customer customer) {
        String ahvNumber = customer.getAhvNumber();
        log.error("Lookup failed for {}", ahvNumber);
    }

    // 4. Bank details, on the error path, where logging feels most justified.
    void paymentFailure(Customer customer, String claimNumber) {
        log.error(
                "Payout for claim {} failed to account {}",
                claimNumber,
                customer.iban);
    }

    // 5. toString() does not launder it either.
    void viaToString(Customer customer) {
        log.warn("DOB {}", customer.getDateOfBirth().toString());
    }

    // 6. Direct field access is as sensitive as a getter.
    void fieldAccess(Customer customer) {
        log.info("Manual review for {}", customer.policyholderName);
    }

    // 7. A JDK logger sink, included to prove non-SLF4J sinks resolve too.
    void javaUtilLogging(Customer customer) {
        auditLog.warning("Policyholder email " + customer.getEmailAddress());
    }

    // 8. PrintStream is also a configured sink and resolves from the JDK.
    void consoleFallback(Customer customer) {
        System.err.printf("Policyholder %s%n", customer.getAhvNumber());
    }
}