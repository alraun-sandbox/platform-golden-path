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