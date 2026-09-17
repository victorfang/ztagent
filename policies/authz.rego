# Author: Victor Fang
# Website: https://VictorFang.com
# X: https://X.com/vicfcs
# LinkedIn: https://www.linkedin.com/in/drvictorfang

package mini_secure_agent.authz

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
    "msa-tool-admin" in input.roles
}
