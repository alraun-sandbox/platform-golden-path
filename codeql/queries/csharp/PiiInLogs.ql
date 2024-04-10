/**
 * @name Policyholder personal data written to application logs
 * @description Personal data reaching a log sink is disclosed to everyone with log access -
 *              operators, the SIEM, the log retention archive and any downstream analytics
 *              pipeline. Under GDPR Art. 5(1)(c) and FINMA circular 2023/1 this is a
 *              reportable data protection incident even when no external party sees it, and
 *              log retention usually far outlives the lawful basis for holding the data.
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

import csharp
import semmle.code.csharp.dataflow.internal.DataFlowImplCommon
import semmle.code.csharp.dataflow.TaintTracking
import Pii
import PiiToLog::PathGraph

module PiiToLogConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Reading a personal-data property or field off a domain object.
    exists(PropertyAccess access |
      access.getTarget() instanceof PiiProperty and
      source.asExpr() = access
    )
    or
    exists(FieldAccess access |
      access.getTarget() instanceof PiiField and
      source.asExpr() = access
    )
    or
    // A parameter or local whose name says what it holds.
    exists(VariableAccess access |
      access.getTarget() instanceof PiiVariable and
      source.asExpr() = access
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(LoggingCall call | sink.asExpr() = call.getALoggedArgument())
  }

  predicate isBarrier(DataFlow::Node node) {
    // Explicit redaction clears the taint - that is the fix we want people to make.
    exists(MethodCall call | isRedactionCall(call) and node.asExpr() = call)
    or
    // A hashed or tokenised identifier is no longer personal data for logging purposes.
    exists(MethodCall call |
      call.getTarget().getDeclaringType().getName().matches("%Hash%") and
      node.asExpr() = call
    )
  }

  /**
   * String interpolation is how this defect virtually always appears in practice -
   * `_logger.LogInformation($"Processing claim for {claim.PolicyholderName}")` - so make
   * sure taint survives it even where the standard model is conservative.
   */
  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    exists(InterpolatedStringExpr interpolated |
      nodeFrom.asExpr() = interpolated.getAChild() and
      nodeTo.asExpr() = interpolated
    )
    or
    exists(MethodCall call |
      call.getTarget().hasName("ToString") and
      nodeFrom.asExpr() = call.getQualifier() and
      nodeTo.asExpr() = call
    )
    or
    exists(MethodCall call |
      call.getTarget().getDeclaringType().getName() = "JsonSerializer" and
      call.getTarget().hasName("Serialize") and
      nodeFrom.asExpr() = call.getAnArgument() and
      nodeTo.asExpr() = call
    )
  }
}

module PiiToLog = TaintTracking::Global<PiiToLogConfig>;

from PiiToLog::PathNode source, PiiToLog::PathNode sink
where PiiToLog::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Policyholder personal data from $@ is written to the application log. Redact or omit it.",
  source.getNode(), source.getNode().toString()
