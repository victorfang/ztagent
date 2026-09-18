# ZTAgent.ai : Zero Trust Security for AI Agents
# Author: VictorFang.com

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
    "ztagent-tool-admin" in input.roles
}
