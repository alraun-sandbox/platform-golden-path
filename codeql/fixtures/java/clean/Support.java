import java.time.LocalDate;

final class Customer {
    private final String customerNumber;
    private final String policyholderReference;
    private final LocalDate dateOfBirth;
    private final String claimNumber;

    Customer(String customerNumber, String policyholderReference, LocalDate dateOfBirth, String claimNumber) {
        this.customerNumber = customerNumber;
        this.policyholderReference = policyholderReference;
        this.dateOfBirth = dateOfBirth;
        this.claimNumber = claimNumber;
    }

    String getCustomerNumber() {
        return customerNumber;
    }

    String getPolicyholderReference() {
        return policyholderReference;
    }

    LocalDate getDateOfBirth() {
        return dateOfBirth;
    }

    String getClaimNumber() {
        return claimNumber;
    }
}