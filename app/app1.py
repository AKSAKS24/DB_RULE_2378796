from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional
import re, json

app = FastAPI(title="ABAP Scanner - SAP Note 2378796")

# --- Definitions ---
# Sensitive table and fields as per SAP Note 2378796
SENSITIVE_TABLES = {"MARC"}   

# Sensitive fields and correct replacement usage (instance methods!)
SENSITIVE_FIELDS = {
    "STAWN": "Create instance of /SAPSLL/CL_MM_CLS_SERVICE and call ->GET_COMMODITY_CODE_CLS",
    "EXPME": "Create instance of /SAPSLL/CL_MM_CLS_SERVICE and call ->GET_COMMODITY_CODE_DETAILS",
}

# Regex for SQL SELECT extraction and JOINs
SQL_SELECT_BLOCK_RE = re.compile(
    r"\bSELECT\b(?P<select>.+?)\bFROM\b\s+(?P<table>\w+)(?P<rest>.*?)(?=(\bSELECT\b|$))",
    re.IGNORECASE | re.DOTALL,
)
JOIN_RE = re.compile(r"\bJOIN\s+(?P<table>\w+)", re.IGNORECASE)


class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = None
    code: Optional[str] = ""


# --- Comment helper for fields ---
def comment_field(field: str) -> str:
    f = field.upper()
    if f in SENSITIVE_FIELDS:
        return (
            f"* TODO: Field {f} must NOT be read directly from MARC "
            f"(Note 2378796). {SENSITIVE_FIELDS[f]} instead."
        )
    return ""


# --- SQL scanner ---
def scan_sql(code: str):
    results = []

    for stmt in SQL_SELECT_BLOCK_RE.finditer(code):
        table = stmt.group("table").upper()
        stmt_text = stmt.group(0)
        span = stmt.span()

        # Only check MARC table
        if table in SENSITIVE_TABLES:
            field_found = False
            for field in SENSITIVE_FIELDS.keys():
                if re.search(rf"\b{field}\b", stmt_text, re.IGNORECASE):
                    field_found = True
                    results.append({
                        "target_type": "SQL_FIELD",
                        "target_name": field,
                        "field": field,
                        "span": span,
                        "used_fields": [field],
                        "suggested_fields": None,
                        "suggested_statement": comment_field(field)
                    })

            # 🚫 If no STAWN/EXPME present → no findings at all
            if not field_found:
                pass  

        # Check JOINS with MARC (but again only warn if STAWN/EXPME used)
        for jm in JOIN_RE.finditer(stmt.group("rest")):
            jtable = jm.group("table").upper()
            if jtable in SENSITIVE_TABLES:
                # check if fields present in join part
                j_text = stmt.group("rest")
                for field in SENSITIVE_FIELDS.keys():
                    if re.search(rf"\b{field}\b", j_text, re.IGNORECASE):
                        results.append({
                            "target_type": "SQL_FIELD",
                            "target_name": field,
                            "field": field,
                            "span": jm.span(),
                            "used_fields": [field],
                            "suggested_fields": None,
                            "suggested_statement": comment_field(field)
                        })

    return results


# --- API endpoint ---
@app.post("/assess-2378796")
def assess(units: List[Unit]):
    results = []
    for u in units:
        src = u.code or ""
        findings = []
        seen = set()

        for hit in scan_sql(src):
            key = (hit["target_type"], hit["target_name"], hit["span"])
            if key in seen:
                continue
            seen.add(key)

            findings.append({
                "table": None,  # only flagging fields, so no table entry
                "field": hit.get("field"),
                "target_type": hit["target_type"],
                "target_name": hit["target_name"],
                "start_char_in_unit": hit["span"][0],
                "end_char_in_unit": hit["span"][1],
                "used_fields": hit["used_fields"],
                "ambiguous": False,
                "suggested_fields": hit["suggested_fields"],
                "suggested_statement": hit["suggested_statement"]
            })
        obj = json.loads(u.model_dump_json())
        obj["selects"] = findings
        results.append(obj)
    return results


@app.get("/health")
def health():
    return {"ok": True, "note": "2378796"}