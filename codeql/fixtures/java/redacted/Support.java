import java.time.LocalDate;

final class Customer {
    private final String customerNumber;
    private final String ahvNumber;
    private final LocalDate dateOfBirth;
    private final String emailAddress;
    public final String iban;
    public final String policyholderName;

    Customer(
            String customerNumber,
            String ahvNumber,
            LocalDate dateOfBirth,
            String emailAddress,
            String iban,
            String policyholderName) {
        this.customerNumber = customerNumber;
        this.ahvNumber = ahvNumber;
        this.dateOfBirth = dateOfBirth;
        this.emailAddress = emailAddress;
        this.iban = iban;
        this.policyholderName = policyholderName;
    }

    String getCustomerNumber() {
        return customerNumber;
    }

    String getAhvNumber() {
        return ahvNumber;
    }

    LocalDate getDateOfBirth() {
        return dateOfBirth;
    }

    String getEmailAddress() {
        return emailAddress;
    }
}

final class PiiMasking {
    private PiiMasking() {
    }

    static String redact(String value) {
        return "[redacted]";
    }

    static String maskAhv(String value) {
        return "756.****.****.00";
    }

    static String maskDateOfBirth(LocalDate value) {
        return "0000-**-**";
    }

    static String anonymise(String value) {
        return "anonymous";
    }

    static String pseudonymise(String value) {
        return "subject-7f83b1";
    }

    static String hash(String value) {
        return "hash:2cf24dba";
    }

    static String tokenise(String value) {
        return "token:policyholder";
    }
}