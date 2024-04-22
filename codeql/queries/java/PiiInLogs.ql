/**
 * @name Policyholder personal data written to application logs
 * @description Personal data reaching a log sink is disclosed to every operator, the SIEM and
 *              the retention archive. Under GDPR Art. 5(1)(c) and FINMA circular 2023/1 this
 *              is a reportable data protection incident, and log retention normally outlives
 *              the lawful basis for holding the data.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id zurich/pii-in-logs
 * @tags security
 *       privacy
 *       compliance
 *       external/cwe/cwe-532
 */

import java
import semmle.code.java.dataflow.TaintTracking
import Pii
import PiiToLog::PathGraph

module PiiToLogConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(MethodCall call | call.getMethod() instanceof PiiGetter and source.asExpr() = call)
    or
    exists(FieldAccess access |
      access.getField() instanceof PiiField and source.asExpr() = access
    )
    or
    exists(VarAccess access |
      access.getVariable() instanceof PiiVariable and source.asExpr() = access
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(LoggingCall call | sink.asExpr() = call.getAnArgument())
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(MethodCall call | isRedactionCall(call) and node.asExpr() = call)
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    // Taint does not cross toString() on its own, so `log.info(customer.toString())`
    // produced no finding at all until this step was added. That is the same failure
    // family as the integration test that could never fail: a control that reports
    // "clean" because it never looked is more dangerous than no control, because it
    // is believed. The redacted fixture is what keeps this honest - it must stay at
    // zero findings for the right reason, not because the query is blind.
    exists(MethodCall call |
      call.getMethod().hasName("toString") and
      call.getNumArgument() = 0 and
      node1.asExpr() = call.getQualifier() and
      node2.asExpr() = call
    )
  }
}

module PiiToLog = TaintTracking::Global<PiiToLogConfig>;

from PiiToLog::PathNode source, PiiToLog::PathNode sink
where PiiToLog::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Policyholder personal data from $@ is written to the application log. Redact or omit it.",
  source.getNode(), source.getNode().toString()
