/**
 * The Java mirror of the C# definition. Same words, same rule.
 *
 * This file existing at all is the point of Act 4: the risk engine is a different language,
 * owned by a different team, with a different build tool - and it is held to an identical
 * compliance standard, because the standard lives in the platform rather than in either team.
 */

import java

bindingset[name]
predicate isPiiName(string name) {
  name
      .toLowerCase()
      .regexpMatch(".*(" +
          "ahv|ahvnumber|avs|socialsecurity|ssn|nationalid|" +
          "dateofbirth|dob|birthdate|passport|idcardnumber|" +
          "email|emailaddress|phone|phonenumber|mobile|streetaddress|postaladdress|" +
          "iban|bankaccount|accountnumber|creditcard|cardnumber|" +
          "policyholdername|insuredname|beneficiary|medicalrecord|healthdata" +
          ").*")
}

/** A getter returning personal data, e.g. `claim.getPolicyholderName()`. */
class PiiGetter extends Method {
  PiiGetter() {
    isPiiName(this.getName()) and
    this.getNumberOfParameters() = 0
  }
}

class PiiField extends Field {
  PiiField() { isPiiName(this.getName()) }
}

/**
 * A local variable or parameter whose name says it holds personal data.
 *
 * Extends `Variable` rather than `LocalScopeVariable` because the latter is
 * abstract and would require implementing `getCallable()`; restricting to
 * `LocalVariableDecl` and `Parameter` gives the same set.
 */
class PiiVariable extends Variable {
  PiiVariable() {
    isPiiName(this.getName()) and
    (this instanceof LocalVariableDecl or this instanceof Parameter)
  }
}

/** SLF4J, Log4j, java.util.logging and the console. */
class LoggingCall extends MethodCall {
  LoggingCall() {
    exists(Method m | m = this.getMethod() |
      m.getDeclaringType().getASupertype*().hasQualifiedName("org.slf4j", "Logger") and
      m.hasName(["trace", "debug", "info", "warn", "error"])
      or
      m.getDeclaringType()
          .getASupertype*()
          .hasQualifiedName("org.apache.logging.log4j", "Logger") and
      m.hasName(["trace", "debug", "info", "warn", "error", "fatal"])
      or
      m.getDeclaringType().hasQualifiedName("java.util.logging", "Logger") and
      m.hasName(["log", "info", "fine", "finer", "finest", "warning", "severe"])
      or
      m.getDeclaringType().hasQualifiedName("java.io", "PrintStream") and
      m.hasName(["println", "print", "printf"])
    )
  }
}

predicate isRedactionCall(MethodCall call) {
  call.getMethod()
      .getName()
      .toLowerCase()
      .matches(["%redact%", "%mask%", "%anonymi%", "%pseudonymi%", "%hash%", "%tokeni%"])
}
