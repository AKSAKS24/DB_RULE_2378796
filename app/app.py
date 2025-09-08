from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import re

app = FastAPI(
    title="ABAP Sensitive SQL Field Scanner (SAP Note 2378796)",
    version="1.0"
)

# ====== Models ======
class Finding(BaseModel):
    pgm_name: Optional[str] = None
    inc_name: Optional[str] = None
    type: Optional[str] = None
    name: Optional[str] = None
    class_implementation: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    issue_type: Optional[str] = None
    severity: Optional[str] = None
    line: Optional[int] = None
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None

class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    class_implementation: Optional[str] = ""
    start_line: int = 0
    end_line: int = 0
    code: str
    findings: Optional[List[Finding]] = None


# ====== Core SAP Note List ======
SENSITIVE_TABLES = {"MARC"}
SENSITIVE_FIELDS = {
    "STAWN": "Create instance of /SAPSLL/CL_MM_CLS_SERVICE and call ->GET_COMMODITY_CODE_CLS",
    "EXPME": "Create instance of /SAPSLL/CL_MM_CLS_SERVICE and call ->GET_COMMODITY_CODE_DETAILS",
}


# ====== Regex Knowledge ======
SQL_SELECT_BLOCK_RE = re.compile(
    r"\bSELECT\b(?P<select>.+?)\bFROM\b\s+(?P<table>\w+)(?P<rest>.*?)(?=(\bSELECT\b|$))",
    re.IGNORECASE | re.DOTALL,
)
JOIN_RE = re.compile(r"\bJOIN\s+(?P<table>\w+)", re.IGNORECASE)

# ====== Helpers / Snippet Extract ======
def line_of_offset(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1

def snippet_at(text: str, start: int, end: int) -> str:
    s = max(0, start - 60); e = min(len(text), end + 60)
    return text[s:e].replace("\n", "\\n")

def comment_field(field: str) -> str:
    f = field.upper()
    if f in SENSITIVE_FIELDS:
        return (
            f"Field {f} must NOT be read directly from MARC (SAP Note 2378796). {SENSITIVE_FIELDS[f]}"
        )
    return ""


# ====== SQL Scanner ======
def scan_unit_for_sensitive_sql(unit: Unit) -> Dict[str, Any]:
    src = unit.code or ""
    findings: List[Dict[str, Any]] = []
    seen = set()
    for stmt in SQL_SELECT_BLOCK_RE.finditer(src):
        table = stmt.group("table").upper()
        stmt_text = stmt.group(0)
        span = stmt.span()
        # Only check MARC table
        if table in SENSITIVE_TABLES:
            for field in SENSITIVE_FIELDS:
                if re.search(rf"\b{field}\b", stmt_text, re.IGNORECASE):
                    key = (table, field, span)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append({
                        "pgm_name": unit.pgm_name,
                        "inc_name": unit.inc_name,
                        "type": unit.type,
                        "name": unit.name,
                        "class_implementation": getattr(unit, 'class_implementation', ""),
                        "start_line": unit.start_line,
                        "end_line": unit.end_line,
                        "issue_type": "SensitiveFieldDirectAccess",
                        "severity": "error",
                        "message": comment_field(field),
                        "suggestion": SENSITIVE_FIELDS[field],
                        "snippet": snippet_at(src, span[0], span[1]),
                    })
        # Check JOIN parts for MARC+field usage
        for jm in JOIN_RE.finditer(stmt.group("rest")):
            jtable = jm.group("table").upper()
            if jtable in SENSITIVE_TABLES:
                j_text = stmt.group("rest")
                for field in SENSITIVE_FIELDS:
                    if re.search(rf"\b{field}\b", j_text, re.IGNORECASE):
                        key = (jtable, field, jm.span())
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append({
                            "pgm_name": unit.pgm_name,
                            "inc_name": unit.inc_name,
                            "type": unit.type,
                            "name": unit.name,
                            "class_implementation": getattr(unit, 'class_implementation', ""),
                            "start_line": unit.start_line,
                            "end_line": unit.end_line,
                            "issue_type": "SensitiveFieldJoinAccess",
                            "severity": "error",
                            "message": comment_field(field),
                            "suggestion": SENSITIVE_FIELDS[field],
                            "snippet": snippet_at(src, jm.span()[0], jm.span()[1]),                            
                        })
    result_obj = unit.model_dump()
    if findings:
        result_obj["findings"] = findings
    return result_obj

# ====== API ======
@app.post("/assess-2378796")
async def scan_2378796(units: List[Unit]):
    # System code style: only include findings units (positive); negatives omit findings key
    results = []
    for u in units:
        obj = scan_unit_for_sensitive_sql(u)
        if obj.get("findings"):
            results.append(obj)
    return results

@app.get("/health")
async def health():
    return {"ok": True, "note": "2378796"}