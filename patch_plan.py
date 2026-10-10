import sys

with open("crates/mcpg-app/src/capsule_plan.rs", "r") as f:
    content = f.read()

bad = """fn expand_string(raw: &str, vars: &VarTable) -> Result<String, PlanError> {
    if raw.contains("${") {
        let path = expand(raw, vars).map_err(|e| PlanError::VarExpansion(e.to_string()))?;
        Ok(path.to_string_lossy().into_owned())
    } else {
        Ok(raw.to_string())
    }
}"""

good = """fn expand_string(raw: &str, vars: &VarTable) -> Result<String, PlanError> {
    if raw.contains("${") {
        let path = expand(raw, vars).map_err(|e| PlanError::VarExpansion(e.to_string()))?;
        let s = path.to_string_lossy().into_owned();
        if s.contains("..") {
            if let Ok(canon) = std::fs::canonicalize(&path) {
                return Ok(canon.to_string_lossy().into_owned());
            }
        }
        Ok(s)
    } else {
        Ok(raw.to_string())
    }
}"""

content = content.replace(bad, good)
with open("crates/mcpg-app/src/capsule_plan.rs", "w") as f:
    f.write(content)

