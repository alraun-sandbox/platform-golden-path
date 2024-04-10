/**
 * @name Claims API action without an authorization decision
 * @description Every endpoint that touches claims data must make an explicit authorization
 *              decision. An action with neither `[Authorize]` (inherited or direct) nor a
 *              deliberate `[AllowAnonymous]` is not "secure by default" - it is undecided,
 *              and undecided endpoints are how broken access control reaches production.
 *              Zurich requires the decision to be visible in the code, so that a reviewer and
 *              an auditor can both see it.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.1
 * @precision high
 * @id zurich/missing-authorization
 * @tags security
 *       compliance
 *       external/cwe/cwe-862
 */

import csharp

class ControllerClass extends Class {
  ControllerClass() {
    this.getABaseType*().hasName(["ControllerBase", "Controller"])
    or
    this.getName().matches("%Controller")
  }
}

predicate hasAuthorizeAttribute(Attributable element) {
  element.getAnAttribute().getType().hasName(["AuthorizeAttribute", "Authorize"])
}

predicate hasAllowAnonymous(Attributable element) {
  element.getAnAttribute().getType().hasName(["AllowAnonymousAttribute", "AllowAnonymous"])
}

predicate isHttpAction(Method m) {
  m.getAnAttribute()
      .getType()
      .hasName([
          "HttpGetAttribute", "HttpPostAttribute", "HttpPutAttribute", "HttpPatchAttribute",
          "HttpDeleteAttribute", "HttpGet", "HttpPost", "HttpPut", "HttpPatch", "HttpDelete",
          "RouteAttribute"
        ])
}

from Method action, ControllerClass controller
where
  action.getDeclaringType() = controller and
  action.isPublic() and
  isHttpAction(action) and
  not hasAuthorizeAttribute(action) and
  not hasAuthorizeAttribute(controller) and
  // An explicit AllowAnonymous is a decision, and decisions are allowed. Health and metrics
  // endpoints legitimately live here.
  not hasAllowAnonymous(action) and
  not hasAllowAnonymous(controller)
select action,
  "Action '" + action.getName() + "' on " + controller.getName() +
    " makes no authorization decision. Add [Authorize] with the required policy, or [AllowAnonymous] if it is genuinely public."
