# Author: Victor Fang
# Website: https://VictorFang.com
# X: https://X.com/vicfcs
# LinkedIn: https://www.linkedin.com/in/drvictorfang

package ztagent_core.authz

import rego.v1

default allow := false

allow if {
    input.action == "model.generate"
    input.subject != ""
}

allow if {
    input.action == "tool.execute"
    input.subject != ""
    input.resource.risk in {"low", "medium"}
}

allow if {
    input.action == "tool.execute"
    input.resource.risk == "high"
    not input.resource.tool in {"issue_refund", "read_web_resource", "publish_web_message"}
    "ztagent-tool-admin" in input.roles
}

# Customer-service identities may only refund to the original payment method
# within a bounded service limit. A stolen role alone cannot redirect funds.
allow if {
    input.action == "tool.execute"
    input.resource.tool == "issue_refund"
    "customer-service-agent" in input.roles
    input.resource.authorization_context.destination_type == "original_payment_method"
    input.resource.authorization_context.amount_cents <= 50000
}

# Larger refunds require a finance supervisor and a trusted, request-bound approval.
allow if {
    input.action == "tool.execute"
    input.resource.tool == "issue_refund"
    "finance-supervisor" in input.roles
    input.resource.authorization_context.destination_type == "original_payment_method"
    input.resource.authorization_context.approval_verified == true
    input.resource.authorization_context.amount_cents <= 500000
}

# Only a dedicated read capability may access classified business services.
# There is intentionally no allow rule for publish_web_message.
allow if {
    input.action == "tool.execute"
    input.resource.tool == "read_web_resource"
    input.resource.authorization_context.destination_class == "approved_business_service"
}
