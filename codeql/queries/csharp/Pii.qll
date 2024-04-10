/**
 * Shared definitions of what Zurich considers policyholder personal data, and what counts
 * as writing it somewhere durable.
 *
 * Kept in one library because the same definition has to hold for C# and, mirrored, for Java.
 * A compliance rule that means something different in two services is not a rule.
 */

import csharp

/**
 * Naming patterns for personal data as it appears in the claims domain model.
 *
 * Name-based detection is a deliberate compromise. A perfect classifier would need a data
 * catalogue; this catches the realistic mistake - an engineer, or a coding agent, logging a
 * domain object field for debugging - with very few false positives.
 */
bindingset[name]
predicate isPiiName(string name) {
  name
      .toLowerCase()
      .regexpMatch(".*(" +
          // Swiss social insurance number (AHV / AVS) - the canonical Swiss identifier.
          "ahv|ahvnumber|avs|socialsecurity|ssn|nationalid|" +
          // Direct identifiers.
          "dateofbirth|dob|birthdate|passport|idcardnumber|" +
          // Contact details.
          "email|emailaddress|phone|phonenumber|mobile|streetaddress|postaladdress|" +
          // Financial.
          "iban|bankaccount|accountnumber|creditcard|cardnumber|" +
          // Domain-specific.
          "policyholdername|insuredname|beneficiary|medicalrecord|healthdata" +
          ").*")
}

/** A property whose name identifies it as personal data. */
class PiiProperty extends Property {
  PiiProperty() { isPiiName(this.getName()) }
}

/** A field whose name identifies it as personal data. */
class PiiField extends Field {
  PiiField() { isPiiName(this.getName()) }
}

/**
 * Holds if `v` is named after personal data but every value it ever receives comes out
 * of a redaction helper.
 *
 * Without this, `var ahvNumber = PiiRedaction.MaskAhv(customer.AhvNumber)` is reported,
 * because the name-based source re-introduces taint at the read even though the barrier
 * cleared it at the call. That is precisely the developer who did the right thing, and
 * they are the last person a compliance rule can afford to be wrong about.
 */
predicate isRedactedVariable(Variable v) {
  exists(v.getAnAssignedValue()) and
  forall(Expr assigned | assigned = v.getAnAssignedValue() |
    exists(MethodCall call | call = assigned and isRedactionCall(call))
  )
}

/** A parameter or local carrying personal data. */
class PiiVariable extends Variable {
  PiiVariable() {
    isPiiName(this.getName()) and
    not this instanceof Field and
    not isRedactedVariable(this)
  }
}

/**
 * A logging call: any `Microsoft.Extensions.Logging` sink, plus the console and
 * `System.Diagnostics` writers people reach for when a logger is inconvenient.
 */
class LoggingCall extends MethodCall {
  LoggingCall() {
    exists(Method m | m = this.getTarget() |
      // ILogger / LoggerExtensions - LogInformation, LogDebug, LogError, BeginScope, Log...
      m.getDeclaringType().getName().matches("%Logger%") and
      (m.getName().matches("Log%") or m.getName() = "BeginScope")
      or
      m.getDeclaringType().hasFullyQualifiedName("System", "Console") and
      m.getName().matches("Write%")
      or
      m.getDeclaringType().hasFullyQualifiedName("System.Diagnostics", "Trace") and
      m.getName().matches("Write%")
      or
      m.getDeclaringType().hasFullyQualifiedName("System.Diagnostics", "Debug") and
      m.getName().matches("Write%")
      or
      // Serilog fluent API.
      m.getDeclaringType().getName().matches("%ILogger%") and
      m.getName() in ["Information", "Debug", "Warning", "Error", "Fatal", "Verbose"]
    )
  }

  /** The arguments that end up in the rendered log line. */
  Expr getALoggedArgument() { result = this.getAnArgument() }
}

/**
 * Sanitisers. Redaction has to be recognisable, otherwise the rule punishes teams that did
 * the right thing and they stop trusting it.
 */
predicate isRedactionCall(MethodCall call) {
  call.getTarget().getName().toLowerCase().matches(["%redact%", "%mask%", "%anonymi%", "%pseudonymi%", "%hash%", "%tokeni%"])
}
