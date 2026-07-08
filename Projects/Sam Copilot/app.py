import glob
import json
import logging
import mimetypes
import os
import re
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
import subprocess
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config.json"
AUDIT_LOG = ROOT / "audit.log"
POLICY_DIR = ROOT / "policies"
ARIBA_KB_PATH = POLICY_DIR / "sap_ariba_knowledge.json"
SAP_DOCS_PATH = POLICY_DIR / "sap_official_docs.json"
SESSIONS_DIR = ROOT / "sessions"
ASSETS_DIR = ROOT / "assets"

# in-memory session store (also persisted)
SESSIONS_DIR.mkdir(exist_ok=True)
SESSIONS = {}
MODEL_EXECUTOR = ThreadPoolExecutor(max_workers=1)


def load_config():
    with CONFIG_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def apply_runtime_config_overrides(config, payload):
    runtime_config = dict(config)
    requested_model = str(payload.get("ollama_model") or payload.get("model") or "").strip()
    allowed_models = config.get("ollama_model_options") or [config.get("ollama_model")]
    if requested_model and requested_model in allowed_models:
        runtime_config["ollama_model"] = requested_model
    return runtime_config


def ensure_audit_log():
    if not AUDIT_LOG.exists():
        AUDIT_LOG.write_text("", encoding="utf-8")


def append_audit(entry):
    ensure_audit_log()
    with AUDIT_LOG.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


def load_policies(config):
    policy_folder = ROOT / config.get("policy_folder", "policies")
    policies = {}
    if policy_folder.exists() and policy_folder.is_dir():
        for pattern in ["*.txt", "*.md"]:
            for path in sorted(policy_folder.glob(pattern)):
                try:
                    policies[path.name] = path.read_text(encoding="utf-8")
                except Exception:
                    continue
    return policies


def load_ariba_knowledge():
    return load_knowledge_base()


def source_type_for_path(path):
    name = path.name.lower()
    if name in {"hr_kb.json", "it_helpdesk_kb.json"}:
        return "enterprise_helpdesk"
    if name == "sap_ariba_knowledge.json":
        return "local_ariba"
    if name == "sap_official_docs.json":
        return "official_sap_doc"
    if name == "sap_tcodes.json":
        return "downloaded_tcode"
    if name == "sap_ariba_master_knowledge.json":
        return "downloaded_ariba_kb"
    if name == "sap_ariba_abbreviations.json":
        return "local_ariba"
    if name == "sap_ariba_knowledge_base.json":
        return "downloaded_ariba_kb"
    return "downloaded_knowledge"


def stringify_kb_value(value):
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(stringify_kb_value(item) for item in value)
    if isinstance(value, dict):
        parts = []
        for key, nested in value.items():
            label = str(key).replace("_", " ")
            text = stringify_kb_value(nested)
            if text:
                parts.append(f"{label}: {text}")
        return " ".join(parts)
    if value is None:
        return ""
    return str(value)


def title_from_key(key):
    return str(key).replace("_", " ").replace("-", " ").title()


def tags_from_text(*parts):
    text = normalize_text(" ".join(str(part) for part in parts if part))
    stopwords = {
        "and", "the", "for", "with", "from", "that", "this", "into", "about",
        "ariba", "sap", "process", "module", "data", "user", "users",
    }
    tags = []
    for token in text.split():
        if len(token) >= 4 and token not in stopwords and token not in tags:
            tags.append(token)
        if len(tags) >= 12:
            break
    return tags


def flatten_downloaded_ariba_kb(data, path):
    if not isinstance(data, dict):
        return []

    records = []
    base_title = data.get("title", "SAP Ariba Comprehensive Knowledge Base")

    def add_record(item_id, title, summary, content="", tags=None, next_step="", risks=None):
        item = {
            "id": item_id,
            "title": title,
            "summary": summary,
            "content": content,
            "tags": tags or tags_from_text(title, summary, content),
            "key_risks": risks or [],
            "recommended_next_step": next_step,
            "confidence": "Reference",
            "policy_references": [base_title],
        }
        normalized = normalize_knowledge_item(item, path)
        if normalized:
            records.append(normalized)

    overview = data.get("platform_overview")
    if isinstance(overview, dict):
        add_record(
            "ariba_platform_overview",
            "SAP Ariba Platform Overview",
            stringify_kb_value(overview.get("what_it_is") or overview),
            stringify_kb_value(overview),
            ["ariba", "platform", "overview", "upstream", "downstream", "network", "realm"],
        )

    navigation = data.get("navigation")
    if isinstance(navigation, dict):
        for key, value in navigation.items():
            add_record(
                f"ariba_navigation_{normalize_text(key).replace(' ', '_')}",
                f"SAP Ariba Navigation - {title_from_key(key)}",
                stringify_kb_value(value),
                stringify_kb_value(value),
                ["ariba", "navigation", key.replace("_", " ")],
            )

    modules = data.get("modules")
    if isinstance(modules, dict):
        for key, module in modules.items():
            if not isinstance(module, dict):
                continue
            purpose = stringify_kb_value(module.get("purpose"))
            key_objects = stringify_kb_value(module.get("key_objects"))
            hard_notes = stringify_kb_value(module.get("hard_to_find_knowledge"))
            add_record(
                f"ariba_module_{normalize_text(key).replace(' ', '_')}",
                f"SAP Ariba Module - {title_from_key(key)}",
                purpose,
                f"Key objects: {key_objects} Hard-to-find knowledge: {hard_notes}",
                ["ariba", "module", key.replace("_", " ")] + tags_from_text(key, purpose, key_objects),
                "Use the module-specific workspace and verify tenant licensing/configuration before assuming a feature is available.",
            )

    implementation = data.get("implementation")
    if isinstance(implementation, dict):
        for key, value in implementation.items():
            add_record(
                f"ariba_implementation_{normalize_text(key).replace(' ', '_')}",
                f"SAP Ariba Implementation - {title_from_key(key)}",
                stringify_kb_value(value),
                stringify_kb_value(value),
                ["ariba", "implementation", key.replace("_", " ")],
            )

    troubleshooting = data.get("troubleshooting_playbook")
    if isinstance(troubleshooting, list):
        for index, item in enumerate(troubleshooting, start=1):
            if not isinstance(item, dict):
                continue
            symptom = stringify_kb_value(item.get("symptom"))
            content = stringify_kb_value(item)
            add_record(
                f"ariba_troubleshooting_{index}",
                f"SAP Ariba Troubleshooting - {symptom[:80] or index}",
                symptom,
                content,
                ["ariba", "troubleshooting", "support"] + tags_from_text(symptom, content),
                stringify_kb_value(item.get("where_to_look")),
                item.get("likely_causes") if isinstance(item.get("likely_causes"), list) else [],
            )

    best_practices = data.get("best_practices")
    if isinstance(best_practices, list):
        for index, practice in enumerate(best_practices, start=1):
            add_record(
                f"ariba_best_practice_{index}",
                f"SAP Ariba Best Practice {index}",
                stringify_kb_value(practice),
                stringify_kb_value(practice),
                ["ariba", "best practice"] + tags_from_text(practice),
            )

    glossary = data.get("glossary")
    if isinstance(glossary, dict):
        for term, definition in glossary.items():
            add_record(
                f"ariba_glossary_{normalize_text(term).replace(' ', '_')}",
                f"SAP Ariba Glossary - {term}",
                stringify_kb_value(definition),
                stringify_kb_value(definition),
                ["ariba", "glossary", str(term)],
            )

    deep_dives = data.get("complex_processes_deep_dive")
    if isinstance(deep_dives, dict):
        for key, value in deep_dives.items():
            content = stringify_kb_value(value)
            recommendations = []
            if isinstance(value, dict) and isinstance(value.get("practical_recommendations"), list):
                recommendations = value.get("practical_recommendations")
            add_record(
                f"ariba_deep_dive_{normalize_text(key).replace(' ', '_')}",
                f"SAP Ariba Deep Dive - {title_from_key(key)}",
                content.split(". ")[0][:350] if content else title_from_key(key),
                content,
                ["ariba", "deep dive", key.replace("_", " ")] + tags_from_text(key, content),
                stringify_kb_value(recommendations[:2]) if recommendations else "",
                recommendations[:3],
            )

    return records


def flatten_sharepoint_chatbot_kb(data, path):
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        return []

    records = []
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    dataset_name = metadata.get("dataset_name") or "Enterprise SharePoint chatbot knowledge base"

    for entry in data.get("entries", []):
        if not isinstance(entry, dict):
            continue
        title = str(entry.get("title") or entry.get("id") or "").strip()
        answer = str(entry.get("answer") or "").strip()
        if not title or not answer:
            continue

        steps = entry.get("resolution_steps") if isinstance(entry.get("resolution_steps"), list) else []
        tags = []
        for value in [
            entry.get("domain"),
            entry.get("category"),
            title,
            *(entry.get("question_variants") if isinstance(entry.get("question_variants"), list) else []),
        ]:
            if value and str(value) not in tags:
                tags.append(str(value))

        risks = []
        if entry.get("requires_authentication"):
            risks.append("This request may require employee identity verification or authenticated access.")
        if str(entry.get("priority", "")).lower() in {"high", "critical"}:
            risks.append(f"Priority is {entry.get('priority')}; escalate promptly if business impact is active.")

        next_step = " ".join(str(step) for step in steps[:3])
        escalation_team = entry.get("escalation_team")
        estimated_resolution = entry.get("estimated_resolution")
        if escalation_team:
            next_step = f"{next_step} Escalate to {escalation_team} if unresolved.".strip()
        if estimated_resolution:
            next_step = f"{next_step} Estimated resolution: {estimated_resolution}.".strip()

        content_parts = [
            f"Domain: {entry.get('domain', '')}",
            f"Category: {entry.get('category', '')}",
            f"Question variants: {stringify_kb_value(entry.get('question_variants', []))}",
            f"Keywords: {stringify_kb_value(entry.get('keywords', []))}",
            f"Resolution steps: {stringify_kb_value(steps)}",
            f"Escalation team: {escalation_team or ''}",
            f"Estimated resolution: {estimated_resolution or ''}",
        ]
        item = {
            "id": normalize_text(entry.get("id") or title).replace(" ", "_"),
            "title": f"{entry.get('domain', 'Enterprise Helpdesk')} - {title}",
            "summary": answer,
            "content": " ".join(part for part in content_parts if part),
            "tags": tags + tags_from_text(answer, next_step),
            "key_risks": risks,
            "recommended_next_step": next_step,
            "confidence": "High",
            "policy_references": [dataset_name, str(entry.get("domain") or "Enterprise Helpdesk")],
        }
        normalized = normalize_knowledge_item(item, path)
        if normalized:
            records.append(normalized)

    return records


def normalize_knowledge_item(item, path):
    if not isinstance(item, dict):
        return None
    if "codes" in item and path.name.lower() == "sap_functionality_map.json":
        return None
    item_id = str(item.get("id") or item.get("title") or "").strip()
    summary = str(item.get("summary") or item.get("content") or "").strip()
    if not item_id or not summary:
        return None

    normalized = dict(item)
    source_type = source_type_for_path(path)
    normalized["source_type"] = source_type
    normalized["source_file"] = path.name
    normalized.setdefault("title", item_id.replace("_", " ").title())
    normalized.setdefault("tags", [])
    normalized.setdefault("confidence", "Reference" if source_type == "official_sap_doc" else "High")
    if not normalized.get("policy_references"):
        if source_type == "official_sap_doc":
            normalized["policy_references"] = ["SAP official documentation"]
        elif source_type == "downloaded_tcode":
            normalized["policy_references"] = ["Downloaded SAP T-code knowledge base"]
        elif source_type == "local_ariba":
            normalized["policy_references"] = ["SAP Ariba local knowledge base"]
        elif source_type == "downloaded_ariba_kb":
            normalized["policy_references"] = ["SAP Ariba comprehensive knowledge base"]
        else:
            normalized["policy_references"] = [path.name]
    return normalized


def load_knowledge_base():
    knowledge = []
    paths = {
        path
        for pattern in ("sap_*.json", "hr_kb.json", "it_helpdesk_kb.json")
        for path in POLICY_DIR.glob(pattern)
    }
    for path in sorted(paths):
        if path.name.lower() == "sap_functionality_map.json":
            continue
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                for item in data:
                    normalized = normalize_knowledge_item(item, path)
                    if normalized:
                        knowledge.append(normalized)
            elif isinstance(data, dict):
                if isinstance(data.get("entries"), list):
                    knowledge.extend(flatten_sharepoint_chatbot_kb(data, path))
                else:
                    knowledge.extend(flatten_downloaded_ariba_kb(data, path))
        except Exception:
            continue
    return knowledge


ABBREVIATION_ALIASES = {
    "po": ["purchase order"],
    "pr": ["purchase requisition", "purchase request"],
    "req": ["requisition"],
    "rfq": ["request for quotation", "quote request"],
    "rfx": ["sourcing event", "request for x", "rfp", "rfi", "rfq"],
    "rfp": ["request for proposal", "sourcing event"],
    "rfi": ["request for information", "sourcing event"],
    "gr": ["goods receipt"],
    "gi": ["goods issue"],
    "ir": ["invoice receipt"],
    "ses": ["service entry sheet"],
    "asn": ["advanced shipping notice", "advance ship notice"],
    "cig": ["cloud integration gateway", "managed gateway", "integration"],
    "cxml": ["commerce xml", "punchout", "integration"],
    "slp": ["supplier lifecycle performance", "supplier lifecycle and performance", "supplier management"],
    "scc": ["supply chain collaboration"],
    "sbn": ["sap business network"],
    "cro": ["tenant specific procurement acronym", "contract request", "change request"],
    "gb": ["guided buying"],
    "gbp": ["guided buying parameter"],
    "sso": ["single sign on", "login authentication"],
    "ias": ["identity authentication service", "sap cloud identity services"],
    "cis": ["cloud identity services"],
    "idp": ["identity provider"],
    "erp": ["enterprise resource planning"],
    "ecc": ["sap ecc"],
    "s4": ["sap s 4hana"],
    "s4hana": ["sap s 4hana"],
    "api": ["application programming interface", "integration"],
    "edi": ["electronic data interchange", "integration"],
    "gl": ["general ledger"],
    "wbs": ["work breakdown structure"],
    "capex": ["capital expenditure"],
    "opex": ["operating expenditure"],
    "kba": ["knowledge base article"],
    "mfa": ["multi factor authentication"],
    "2fa": ["two factor authentication"],
    "uom": ["unit of measure"],
    "sku": ["stock keeping unit", "catalog item"],
    "p2p": ["procure to pay"],
    "s2p": ["source to pay"],
}


def normalize_text(text):
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def expand_abbreviations(text):
    normalized = normalize_text(text)
    if not normalized:
        return ""
    tokens = normalized.split()
    expanded = list(tokens)
    for token in tokens:
        expanded.extend(ABBREVIATION_ALIASES.get(token, []))
    return normalize_text(" ".join(expanded))


def payload_text(payload):
    return (payload.get("message") or payload.get("request") or "").strip()


def is_greeting_or_empty(text):
    text = (text or "").strip()
    if not text:
        return True
    return len(text.split()) <= 4 and re.search(r"\b(hi|hello|hey|thanks|thank you|salam|مرحبا)\b", text, re.I)


def greeting_answer(response_style="human"):
    item = {
        "title": "SAP Ariba Assistant",
        "summary": "Hi. I can help with SAP Ariba workflows, SAP procurement T-codes, requisitions, approvals, suppliers, catalogs, purchase orders, and safe automation steps.",
        "key_risks": [],
        "recommended_next_step": "Ask me the exact SAP or Ariba task, transaction code, requisition number, supplier scenario, or approval issue you want to handle.",
        "policy_references": [],
    }
    if response_style in {"structured", "json"}:
        return json.dumps({
            "Summary": item["summary"],
            "KeyRisks": [],
            "RecommendedNextStep": item["recommended_next_step"],
            "ConfidenceLevel": "High",
            "PolicyReferences": [],
        }, ensure_ascii=False)
    return format_human_answer(item, style="human")


def token_overlap_score(text, candidate):
    text_tokens = set(expand_abbreviations(text).split())
    cand_tokens = set(expand_abbreviations(candidate).split())
    if not text_tokens or not cand_tokens:
        return 0
    return len(text_tokens & cand_tokens) / max(len(text_tokens), len(cand_tokens))


ACTION_ALIASES = {
    "create": {"create", "creating", "make", "new", "raise", "start", "initiate", "generate", "build", "enter", "add", "post", "set up", "open new"},
    "change": {"change", "changing", "edit", "update", "modify", "adjust", "revise", "amend", "correct", "maintain", "fix"},
    "display": {"display", "displaying", "show", "showing", "view", "viewing", "see", "open", "check", "look", "look at", "lookup", "pull up", "get", "retrieve", "review", "inspect", "read"},
    "list": {"list", "listing", "search", "find", "report", "track", "lookup", "monitor", "overview"},
    "compare": {"compare", "evaluate", "contrast", "rank", "analyze"},
    "confirm": {"confirm", "complete", "close", "acknowledge", "verify"},
    "monitor": {"monitor", "track", "watch", "check", "review"},
    "process": {"process", "handle", "work", "execute", "run"},
    "forecast": {"forecast", "plan", "predict"},
}


OBJECT_ALIASES = {
    "purchase requisition": {"purchase requisition", "requisition", "pr", "req", "req number", "requisition number", "request", "purchase request"},
    "purchase order": {"purchase order", "po", "po number", "po no", "po doc", "order number", "purchase order number", "purchase document"},
    "request for quotation": {"request for quotation", "rfq", "quotation request", "quote request"},
    "sourcing event": {"sourcing event", "rfx", "rfp", "rfi", "bid event", "auction", "event"},
    "quotation": {"quotation", "quote", "supplier quote", "bid"},
    "info record": {"info record", "purchasing info record", "vendor material record"},
    "source list": {"source list", "approved source", "source"},
    "condition records": {"condition records", "condition record", "pricing record", "price condition"},
    "vendor": {"vendor", "supplier", "vendor master", "supplier master"},
    "transfer order": {"transfer order", "to", "warehouse transfer"},
    "warehouse task": {"warehouse task", "ewm task", "task"},
    "warehouse order": {"warehouse order", "ewm order"},
    "inventory": {"inventory", "stock", "stock level", "stock overview"},
    "inventory difference": {"inventory difference", "stock difference", "variance"},
    "goods movement": {"goods movement", "goods receipt", "goods issue", "gr", "gi", "migo", "movement"},
    "material document": {"material document", "material document list", "document list"},
    "delivery": {"delivery", "outbound delivery", "inbound delivery", "shipment delivery"},
    "advanced shipping notice": {"advanced shipping notice", "advance ship notice", "asn"},
    "shipment": {"shipment", "transport", "shipping"},
    "mrp": {"mrp", "mrp run", "material requirements planning"},
    "stock requirement": {"stock requirement", "stock requirement list", "md04", "requirements"},
    "forecasting": {"forecasting", "forecast", "demand planning"},
    "purchasing documents": {"purchasing documents", "purchasing report", "po report", "purchase order report"},
    "vendor performance": {"vendor performance", "supplier performance", "supplier evaluation"},
    "table": {"table", "database table", "se16n"},
    "authorization": {"authorization", "role", "permission", "access", "user authorization"},
    "single sign on": {"single sign on", "sso", "login", "authentication", "identity provider", "idp"},
    "guided buying": {"guided buying", "gb"},
    "supplier lifecycle performance": {"supplier lifecycle performance", "supplier lifecycle and performance", "slp", "supplier management"},
    "cloud integration gateway": {"cloud integration gateway", "managed gateway", "cig", "integration"},
    "service entry sheet": {"service entry sheet", "ses"},
    "dump": {"dump", "runtime error", "abap dump", "st22"},
    "job": {"job", "background job", "scheduled job"},
}


def token_variants(token):
    variants = {token}
    if token.endswith("ing") and len(token) > 5:
        variants.add(token[:-3])
    if token.endswith("ed") and len(token) > 4:
        variants.add(token[:-2])
    if token.endswith("es") and len(token) > 4:
        variants.add(token[:-2])
    if token.endswith("s") and len(token) > 3:
        variants.add(token[:-1])
    return variants


def canonical_actions(text):
    normalized = normalize_text(text)
    base_tokens = set(normalized.split())
    tokens = set(base_tokens)
    for token in base_tokens:
        tokens.update(token_variants(token))
    actions = set()
    for canonical, aliases in ACTION_ALIASES.items():
        for alias in aliases:
            normalized_alias = normalize_text(alias)
            alias_tokens = set(normalized_alias.split())
            if normalized_alias and (normalized_alias in normalized or alias_tokens <= tokens):
                actions.add(canonical)
                break
            if len(alias_tokens) == 1 and alias_tokens & tokens:
                actions.add(canonical)
                break
    if "change" in actions and "display" in actions and not re.search(r"\b(display|show|view|see|open|check|look|lookup|pull up|get|retrieve|review|inspect|read)\b", normalized):
        actions.discard("display")
    return actions


def action_match_score(request_actions, code_actions):
    if not request_actions:
        return 0.0
    if request_actions & code_actions:
        return 3.0
    if "display" in request_actions and code_actions & {"list", "monitor"}:
        return 1.0
    if "list" in request_actions and code_actions & {"display", "monitor"}:
        return 1.0
    if "change" in request_actions and "maintain" in code_actions:
        return 2.0
    return -1.5


def object_match_score(request_objects, code_objects):
    if not request_objects:
        return 0.0
    exact_matches = request_objects & code_objects
    if exact_matches:
        return 4.0 + len(exact_matches)
    related_pairs = {
        ("purchase order", "purchasing documents"),
        ("goods movement", "material document"),
        ("inventory", "material document"),
        ("inventory", "goods movement"),
        ("vendor", "vendor performance"),
        ("quotation", "request for quotation"),
    }
    for left, right in related_pairs:
        if (left in request_objects and right in code_objects) or (right in request_objects and left in code_objects):
            return 1.5
    return -2.0


def match_sap_code_by_task(message, context):
    catalog = load_sap_shortcuts()
    if not catalog:
        return None

    text = f"{message} {context}"
    normalized_text = normalize_text(text)
    request_actions = canonical_actions(text)
    request_objects = canonical_objects(text)
    if not request_actions and not request_objects:
        return None

    best_item = None
    best_score = 0.0
    for group in catalog:
        group_text = " ".join([
            str(group.get("title", "")),
            str(group.get("summary", "")),
            " ".join(str(tag) for tag in group.get("tags", [])),
        ])
        group_objects = canonical_objects(group_text)
        for code in group.get("codes", []):
            code_text = f"{code.get('summary', '')} {' '.join(str(tag) for tag in code.get('tags', []))}"
            code_actions, code_objects = code_action_and_object(code_text)
            if not code_objects:
                code_objects = canonical_objects(f"{code_text} {group_text}")
            score = 0.0
            score += action_match_score(request_actions, code_actions)
            score += object_match_score(request_objects, code_objects)
            score += token_overlap_score(text, code_text) * 2.0
            if request_objects & group_objects:
                score += 0.5
            normalized_code = normalize_text(code.get("code", ""))
            if normalized_code and normalized_code in normalized_text:
                score += 6.0
            if "number" in normalized_text and code_objects & {"purchase order", "purchase requisition"}:
                score += 0.25
            if "by number" in normalized_text and "list" in code_actions:
                score += 1.5
            if score > best_score:
                best_score = score
                best_item = code_to_item(group, code)

    return best_item if best_score >= 4.0 else None


def canonical_objects(text):
    normalized = expand_abbreviations(text)
    tokens = set(normalized.split())
    objects = set()
    for canonical, aliases in OBJECT_ALIASES.items():
        for alias in aliases:
            normalized_alias = normalize_text(alias)
            alias_tokens = set(normalized_alias.split())
            if not normalized_alias:
                continue
            if len(normalized_alias) <= 2:
                matched = normalized_alias in tokens
            else:
                matched = normalized_alias in normalized or alias_tokens <= tokens
            if matched:
                objects.add(canonical)
                break
    return objects


def code_action_and_object(summary):
    normalized = normalize_text(summary)
    actions = canonical_actions(normalized)
    if not actions:
        first = normalized.split()[0] if normalized.split() else ""
        actions = {first} if first else set()
    objects = canonical_objects(normalized)
    return actions, objects


def code_to_item(group, code):
    code_value = str(code.get("code", "")).strip()
    summary = code.get("summary", "")
    return {
        "id": normalize_text(code_value),
        "title": f"{code_value} - {summary}",
        "summary": summary,
        "functionality": group.get("title", "SAP functionality"),
        "functionality_id": group.get("id", "sap_functionality"),
        "key_risks": [
            "This is an SAP GUI or SAP S/4HANA transaction code, not an SAP Ariba shortcut",
            "Access depends on SAP role authorization and the organization's release workflow",
        ],
        "recommended_next_step": group.get("recommended_next_step", ""),
        "policy_references": group.get("policy_references", []),
        "confidence": "High",
        "codes": [f"{code_value}: {summary}"],
    }


def score_knowledge_item(message, context, item, intent=None):
    text = f"{message} {context}"
    normalized_text = expand_abbreviations(text)
    query_tokens = set(normalized_text.split())
    source_type = item.get("source_type", "")
    item_id = normalize_text(item.get("id", ""))
    exact_id_match = item_id and item_id in set(normalized_text.split())
    if source_type == "downloaded_tcode" and intent != "sap_shortcuts" and not exact_id_match:
        return 0.0

    tags = [str(tag) for tag in item.get("tags", []) if tag]
    raw_query_tokens = set(normalize_text(text).split())
    raw_tag_tokens = {
        token
        for tag in tags
        for token in normalize_text(tag).split()
        if token
    }
    snippet = " ".join(
        str(item.get(key, ""))
        for key in ("title", "summary", "content", "recommended_next_step")
    )
    raw_snippet_tokens = set(normalize_text(snippet).split())
    query_abbrev_tokens = raw_query_tokens & set(ABBREVIATION_ALIASES)
    score = token_overlap_score(text, snippet)
    if query_abbrev_tokens & raw_tag_tokens:
        score += 5.0
    if query_abbrev_tokens & raw_snippet_tokens:
        score += min(4.0, len(query_abbrev_tokens & raw_snippet_tokens) * 1.4)
    if query_abbrev_tokens and not (query_abbrev_tokens & raw_tag_tokens or query_abbrev_tokens & raw_snippet_tokens):
        score -= 3.0
    title_raw = normalize_text(item.get("title", ""))
    if any(title_raw.startswith(f"{token} ") for token in query_abbrev_tokens):
        score += 2.0
    if item.get("source_file") == "sap_ariba_abbreviations.json" and re.search(
        r"\b(error|failed|fails|failure|exception|http|status|stuck|cannot|can't|unable|fix|troubleshoot)\b",
        text,
        re.I,
    ):
        score -= 7.0
    elif item.get("source_file") != "sap_ariba_abbreviations.json" and re.search(
        r"\b(error|failed|fails|failure|exception|http|status|stuck|cannot|can't|unable|fix|troubleshoot)\b",
        text,
        re.I,
    ):
        score += 2.0
    if item_id.startswith("master_meta_") and not re.search(r"\b(source|reddit|linkedin|blog|confidence|citation|non sap)\b", text, re.I):
        score -= 4.0
    if item_id.startswith("legacy_module_") and not re.search(r"\b(module|overview|what is|define|definition)\b", text, re.I):
        score -= 1.5
    if item_id.startswith("legacy_implementation_") and not re.search(r"\b(implementation|integrat|architecture|role|setup|configure)\b", text, re.I):
        score -= 1.0
    snippet_tokens = set(expand_abbreviations(snippet).split())
    matched_domain_tokens = query_tokens & snippet_tokens & {
        "purchase", "order", "requisition", "quotation", "sourcing", "event",
        "goods", "receipt", "invoice", "service", "entry", "sheet", "shipping",
        "notice", "integration", "gateway", "supplier", "lifecycle", "performance",
        "guided", "buying", "punchout", "catalog", "cxml", "authentication",
        "identity", "network",
    }
    score += min(3.0, len(matched_domain_tokens) * 0.45)

    for tag in tags:
        normalized_tag = expand_abbreviations(tag)
        if not normalized_tag:
            continue
        if normalized_tag in normalized_text:
            score += 2.0 + min(2.0, len(normalized_tag.split()) * 0.4)
        elif tag.lower() in text.lower():
            score += 1.25

    title = expand_abbreviations(item.get("title", ""))
    if item_id and item_id in normalized_text:
        score += 4.0
    if title and title in normalized_text:
        score += 2.0

    if source_type == "local_ariba" and is_ariba_related(text):
        score += 0.35
    if source_type == "downloaded_ariba_kb" and is_ariba_related(text):
        score += 0.45
    if source_type == "official_sap_doc" and ("sap" in normalized_text or "ariba" in normalized_text):
        score += 0.25
    if source_type == "downloaded_tcode" and infer_intent(text) == "sap_shortcuts":
        score += 0.3

    intent_targets = {
        "buyer_registration": {"buyer_registration", "ariba_glossary"},
        "requisition_number": {"requisition_number", "s4hana_procurement_requisition"},
        "approval": {"requisition_approval", "s4hana_procurement_requisition"},
        "supplier_onboarding": {"supplier_onboarding", "ariba_glossary"},
        "catalog_po": {"catalogs_and_po", "s4hana_procurement_requisition"},
        "sap_shortcuts": {"sap_tcodes"},
    }
    if intent and item.get("id") in intent_targets.get(intent, set()):
        score += 2.5 if item.get("source_type") == "local_ariba" else 1.0
    if intent in {"buyer_registration", "approval", "supplier_onboarding", "catalog_po"} and source_type == "downloaded_ariba_kb":
        score += 0.5
    if intent in {"sourcing", "integration"} and source_type in {"downloaded_ariba_kb", "local_ariba"}:
        score += 0.7

    return score


def find_local_doc_match(message, context):
    knowledge = load_ariba_knowledge()
    intent = infer_intent(f"{message} {context}")
    best_item = None
    best_score = 0.0
    for item in knowledge:
        score = score_knowledge_item(message, context, item, intent)
        if score > best_score:
            best_score = score
            best_item = item

    return best_item if best_score >= 1.1 else None


def find_relevant_sources(message, context, max_items=3):
    knowledge = load_ariba_knowledge()
    if not knowledge:
        return []

    intent = infer_intent(f"{message} {context}")
    normalized_text = expand_abbreviations(f"{message} {context}")
    exact_code_query = bool(re.search(r"\b[A-Z]{1,4}\d{1,3}[A-Z]?\b|/SCWM/|/SAPAPO/", f"{message} {context}", re.I))
    ranked = []
    for item in knowledge:
        source_type = item.get("source_type", "")
        if intent == "sap_shortcuts" and source_type not in {"downloaded_tcode", "official_sap_doc"}:
            continue
        if exact_code_query and source_type not in {"downloaded_tcode", "official_sap_doc"}:
            continue
        if intent != "sap_shortcuts" and not exact_code_query and source_type == "downloaded_tcode":
            continue
        ranked.append((score_knowledge_item(message, context, item, intent), item))

    ranked.sort(key=lambda pair: pair[0], reverse=True)
    selected = []
    seen_ids = set()
    for score, item in ranked:
        item_id = item.get("id") or item.get("title")
        if score < 1.1 or item_id in seen_ids:
            continue
        seen_ids.add(item_id)
        selected.append(item)
        if len(selected) >= max_items:
            break
    return selected


def enrich_with_related_sources(item, message, context, max_related=2):
    if not item:
        return item
    item_id = item.get("id") or item.get("title")
    related = []
    for candidate in find_relevant_sources(message, context, max_items=max_related + 3):
        candidate_id = candidate.get("id") or candidate.get("title")
        if candidate_id == item_id:
            continue
        related.append(candidate)
        if len(related) >= max_related:
            break
    if not related:
        return item
    enriched = dict(item)
    enriched["related_sources"] = related
    return enriched


def match_sap_functionality(message, context):
    catalog = load_sap_shortcuts()
    if not catalog:
        return None

    text = expand_abbreviations(f"{message} {context}")
    best_item = None
    best_score = 0.0
    for group in catalog:
        score = 0.0
        title = expand_abbreviations(group.get("title", ""))
        summary = expand_abbreviations(group.get("summary", ""))
        tags = [expand_abbreviations(tag) for tag in group.get("tags", []) if tag]
        if title and title in text:
            score += 2.5
        if summary:
            score += token_overlap_score(text, summary) * 2.0
        for tag in tags:
            if tag and tag in text:
                score += 1.5
        for code in group.get("codes", []):
            code_value = normalize_text(code.get("code", ""))
            code_summary = expand_abbreviations(code.get("summary", ""))
            if code_value and code_value in text:
                score += 4.0
            if code_summary:
                score += token_overlap_score(text, code_summary)
        if score > best_score:
            best_score = score
            best_item = group

    return best_item if best_score >= 1.0 else None


def match_exact_sap_code(message, context):
    text = normalize_text(f"{message} {context}")
    tokens = set(text.split())
    for group in load_sap_shortcuts():
        for code in group.get("codes", []):
            code_value = str(code.get("code", "")).strip()
            normalized_code = normalize_text(code_value)
            if normalized_code and (normalized_code in tokens or normalized_code in text):
                return code_to_item(group, code)
    return None


def format_policy_hit(name, text):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    excerpt = " ".join(lines[:3])
    return {
        "Summary": excerpt,
        "KeyRisks": ["Refer to local procurement policy for exact approval and supplier rules."],
        "RecommendedNextStep": "Review the local procurement policy and apply the relevant approval or supplier controls.",
        "ConfidenceLevel": "Medium",
        "PolicyReferences": [name],
        "MatchedSource": name,
    }


def infer_intent(text):
    lowered = expand_abbreviations(text)
    tokens = set(lowered.split())
    if "buyer" in tokens and any(word in tokens for word in ["register", "registration", "create", "setup", "provision", "provisioning"]):
        return "buyer_registration"
    if any(word in lowered for word in ["tcode", "tcodes", "t code", "t codes", "transaction code", "shortcut", "shortcuts", "sap shortcut", "sap shortcuts"]):
        return "sap_shortcuts"
    if any(word in lowered for word in ["register buyer", "buyer registration", "buyer role", "registering a buyer", "buyer setup"]):
        return "buyer_registration"
    if any(word in lowered for word in ["requisition number", "req number", "request number"]):
        return "requisition_number"
    if any(word in lowered for word in ["approve", "approval", "approver"]):
        return "approval"
    if any(word in lowered for word in ["rfq", "request for quotation", "rfx", "rfp", "rfi", "sourcing event", "auction"]):
        return "sourcing"
    if any(word in lowered for word in ["cig", "cloud integration gateway", "managed gateway", "cxml", "integration"]):
        return "integration"
    if any(word in lowered for word in ["slp", "supplier lifecycle", "supplier management"]):
        return "supplier_onboarding"
    if any(word in lowered for word in ["supplier", "vendor", "onboarding"]):
        return "supplier_onboarding"
    if "catalog" in tokens or "purchase order" in lowered or "po" in tokens or "purchase" in tokens and "order" in tokens:
        return "catalog_po"
    return "general_procurement"


def format_human_answer(item, intent=None, style="human"):
    summary = item.get("summary", "")
    risks = item.get("key_risks", [])
    next_step = item.get("recommended_next_step", "")
    refs = item.get("policy_references", []) or [item.get("title", item.get("id", "Local knowledge base"))]
    title = item.get("title", item.get("id", "SAP Ariba reference"))
    codes = item.get("codes") or []
    if style == "action":
        lines = [
            f"Action: {title}",
            f"Answer: {summary}",
            f"Next step: {next_step}",
            "Risks: " + ("; ".join(risks) if risks else "None"),
            "References: " + ", ".join(refs),
        ]
        if codes:
            lines.append("Shortcuts: " + ", ".join(codes))
        return "\n".join(lines)
    lines = [
        f"{title}",
        f"Summary: {summary}",
        f"Risks: " + ("; ".join(risks) if risks else "None"),
        f"Next step: {next_step}",
        f"References: {', '.join(refs)}",
    ]
    if codes:
        lines.append("Shortcuts: " + ", ".join(codes))
    return "\n".join(lines)


def is_ariba_related(text):
    lowered = expand_abbreviations(text)
    tokens = set(lowered.split())
    if "sap" in tokens:
        return True
    return any(
        token in lowered
        for token in [
            "sap ariba",
            "ariba",
            "tcode",
            "tcodes",
            "transaction code",
            "shortcut",
            "shortcuts",
            "requisition",
            "buyer",
            "supplier",
            "vendor",
            "catalog",
            "purchase order",
            "approval",
            "procurement",
            "purchasing",
            "material",
            "inventory",
            "warehouse",
            "sourcing",
            "rfq",
            "rfx",
            "rfp",
            "rfi",
            "cig",
            "cxml",
            "guided buying",
            "supplier lifecycle",
            "service entry sheet",
            "advanced shipping notice",
        ]
    )


def has_explicit_sap_context(text):
    search_text = f"{text} {expand_abbreviations(text)}"
    return bool(re.search(
        r"\b(sap|ariba|procurement|purchasing|purchase order|purchase requisition|requisition|supplier|vendor|catalog|po|pr|rfq|rfx|rfp|rfi|sourcing|guided buying|cxml)\b",
        search_text,
        re.I,
    ))


def playbook_answer(intent, payload, relevant_policies, style="human", source_item=None):
    source = source_item or {}
    title_map = {
        "buyer_registration": "SAP Ariba Buyer Registration",
        "requisition_number": "SAP Ariba Requisition Number",
        "approval": "SAP Ariba Approval Flow",
        "supplier_onboarding": "SAP Ariba Supplier Onboarding",
        "catalog_po": "SAP Ariba Catalog / Purchase Order",
    }
    default_title = source.get("title") or title_map.get(intent, "SAP Ariba Guidance")
    policy_refs = source.get("policy_references") or [name for name, _ in relevant_policies] or ["SAP Ariba local knowledge base"]
    summary = source.get("summary") or {
        "buyer_registration": "Buyer setup is normally an admin or user-provisioning workflow, not a keyboard shortcut.",
        "requisition_number": "A requisition number is the right trigger for downstream automation and tracking.",
        "approval": "Approvals should follow the tenant workflow, threshold rules, and delegated authority.",
        "supplier_onboarding": "Supplier onboarding should be validated before the supplier is used in buying workflows.",
        "catalog_po": "Catalog and PO actions should follow the approved supplier, catalog, and contract controls.",
    }.get(intent, "I can help with SAP Ariba workflows if you share the task details.")
    risks = source.get("key_risks") or {
        "buyer_registration": [
            "Buyer setup can vary by tenant and role permissions",
            "There is no universal keyboard shortcut for buyer registration",
        ],
        "requisition_number": [
            "The exact automation event depends on your Ariba integration",
            "Workflow actions still need approval and compliance checks",
        ],
        "approval": [
            "Approval thresholds vary by business unit and policy",
            "Skipping approval creates audit risk",
        ],
        "supplier_onboarding": [
            "Using an unapproved supplier can violate policy",
            "Regional compliance checks may differ",
        ],
        "catalog_po": [
            "Non-catalog items may need extra approvals",
            "Contract terms and legal checks can apply",
        ],
    }.get(intent, [])
    next_step = source.get("recommended_next_step") or {
        "buyer_registration": "Use the tenant's user-provisioning or admin workflow to assign the buyer role and verify the permissions.",
        "requisition_number": "Use the requisition-number webhook to record the event and trigger the local automation step.",
        "approval": "Confirm the approver chain and threshold, then release the requisition if policy allows.",
        "supplier_onboarding": "Verify the supplier master record and approval status before using it in procurement.",
        "catalog_po": "Check whether the request maps to an approved catalog item or contract before issuing the order.",
    }.get(intent, "Tell me the exact Ariba task and I'll map it to the right workflow.")
    item = {
        "title": default_title,
        "summary": summary,
        "key_risks": risks,
        "recommended_next_step": next_step,
        "policy_references": policy_refs,
    }
    if style in {"structured", "json"}:
        return json.dumps(format_knowledge_hit({
            "summary": summary,
            "key_risks": risks,
            "recommended_next_step": next_step,
            "confidence": source.get("confidence", "High"),
            "policy_references": policy_refs,
            "title": default_title,
            "url": source.get("url"),
            "id": source.get("id", intent),
            "codes": source.get("codes", []),
        }), ensure_ascii=False)
    return format_human_answer(item, intent=intent, style=style)


def load_sap_shortcuts():
    path = POLICY_DIR / "sap_functionality_map.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def shortcut_catalog_item(message="", context="", max_groups=2, max_codes_per_group=6):
    catalog = load_sap_shortcuts()
    text = f"{message} {context}"
    ranking_text = re.sub(
        r"\b(t\s*-?\s*codes?|tcodes?|transaction\s+codes?|sap\s+shortcuts?|shortcuts?|list\s+all|show\s+me)\b",
        " ",
        text,
        flags=re.I,
    )
    normalized_text = normalize_text(text)
    request_objects = canonical_objects(ranking_text)
    request_actions = canonical_actions(ranking_text) if request_objects else set()

    ranked = []
    for group in catalog:
        group_text = " ".join([
            str(group.get("title", "")),
            str(group.get("summary", "")),
            " ".join(str(tag) for tag in group.get("tags", [])),
        ])
        group_objects = canonical_objects(group_text)
        group_score = token_overlap_score(ranking_text, group_text)
        if request_objects & group_objects:
            group_score += 2.0
        if group.get("id") and normalize_text(group.get("id", "")) in normalized_text:
            group_score += 1.0

        matched_codes = []
        for code in group.get("codes", []):
            code_text = f"{code.get('code', '')} {code.get('summary', '')} {' '.join(str(tag) for tag in code.get('tags', []))}"
            code_actions, code_objects = code_action_and_object(code_text)
            code_score = token_overlap_score(ranking_text, code_text)
            code_score += action_match_score(request_actions, code_actions)
            code_score += object_match_score(request_objects, code_objects)
            if normalize_text(code.get("code", "")) in normalized_text:
                code_score += 6.0
            if code_score > 0:
                matched_codes.append((code_score, code))

        matched_codes.sort(key=lambda item: item[0], reverse=True)
        if matched_codes:
            group_score += matched_codes[0][0]
        ranked.append((group_score, group, [code for _, code in matched_codes[:max_codes_per_group]]))

    ranked.sort(key=lambda item: item[0], reverse=True)
    selected = [item for item in ranked if item[0] > 0][:max_groups]
    if not selected:
        selected = ranked[:max_groups]

    codes = []
    summaries = []
    refs = set()
    for _, group, matched_codes in selected:
        group_codes = matched_codes or group.get("codes", [])[:max_codes_per_group]
        summaries.append(f"{group.get('title', 'SAP functionality')}: {group.get('summary', '')}")
        refs.update(group.get("policy_references", []))
        for code in group_codes:
            codes.append(f"{code.get('code')}: {code.get('summary', '')}")

    return {
        "id": "sap_shortcut_catalog",
        "title": "SAP T-code guidance",
        "summary": (
            "SAP T-codes are SAP GUI or SAP S/4HANA transaction codes, not SAP Ariba tenant shortcuts. "
            + " ".join(summaries[:max_groups])
        ).strip(),
        "key_risks": [
            "A T-code may not exist in SAP Ariba because Ariba uses tenant workflows and screens",
            "Access depends on SAP role authorization and your organization's configuration",
        ],
        "recommended_next_step": "Tell me the exact task, module, or code and I will narrow this to the right transaction.",
        "policy_references": sorted(refs) or ["SAP local shortcut catalog"],
        "confidence": "High",
        "codes": codes[: max_groups * max_codes_per_group],
    }


def format_shortcut_catalog(style="human", message="", context=""):
    item = shortcut_catalog_item(message, context)
    if style in {"structured", "json"}:
        return json.dumps(format_knowledge_hit(item), ensure_ascii=False)

    return format_human_answer(item, style=style)


def score_policy(request_text, context_text, policy_text):
    words = set(re.findall(r"\w{4,}", f"{request_text} {context_text}".lower()))
    score = sum(policy_text.lower().count(word) for word in words)
    return score


def find_relevant_policies(payload, policies, max_items=3):
    if not policies:
        return []

    request_text = payload.get("request") or payload.get("message") or ""
    context_text = payload.get("context", "")
    ranked = []
    for name, text in policies.items():
        score = score_policy(request_text, context_text, text)
        ranked.append((score, name, text))

    ranked.sort(reverse=True, key=lambda item: item[0])
    relevant = [
        (name, text)
        for score, name, text in ranked
        if score > 0
    ]

    if not relevant:
        relevant = [(name, text) for _, name, text in ranked[:max_items]]

    return relevant[:max_items]


def build_prompt(payload, config, relevant_policies=None):
    role = payload.get("role", "buyer")
    request_text = payload.get("request", "")
    context_text = payload.get("context", "")
    response_style = payload.get("response_style", "human")
    intent = payload.get("intent") or infer_intent(request_text + " " + context_text)

    if len(request_text) > config.get("max_input_chars", 12000):
        raise ValueError("Request exceeds maximum input size")

    policy_section = ""
    if relevant_policies:
        policy_section = "Relevant procurement policies and excerpts:\n"
        for name, text in relevant_policies:
            excerpt = "\n".join([line.strip() for line in text.splitlines() if line.strip()][:4])
            policy_section += f"Policy: {name}\n{excerpt}\n\n"

    doc_section = ""
    relevant_sources = payload.get("relevant_sources") or []
    if relevant_sources:
        doc_section = "Relevant SAP and Ariba references:\n"
        for item in relevant_sources:
            doc_section += f"Title: {item.get('title', item.get('id', 'SAP reference'))}\n"
            if item.get("url"):
                doc_section += f"URL: {item['url']}\n"
            if item.get("summary"):
                doc_section += f"Summary: {item['summary']}\n"
            if item.get("content"):
                content_excerpt = " ".join(str(item.get("content", "")).split()[:80])
                doc_section += f"Excerpt: {content_excerpt}\n"
            doc_section += "\n"

    if response_style in {"structured", "json"}:
        answer_contract = """Return ONLY a valid JSON object with keys: Summary, KeyRisks, RecommendedNextStep, ConfidenceLevel, PolicyReferences, and optionally SourceUrls and MatchedSource."""
    elif response_style == "action":
        answer_contract = """Return a practical action-oriented answer in natural language. Explain what this means, what to do next, the main risks, and the reference basis. Use plain text or light markdown, not JSON."""
    else:
        answer_contract = """Return a natural chatbot answer in plain text. Be specific, helpful, and conversational. If details are missing, state the assumption or ask one concise clarifying question. Do not use JSON unless the user explicitly asked for structured JSON."""

    return f"""{config.get('system_prompt', '')}

Role: {role}
Task: {request_text}
Intent: {intent}
Response style: {response_style}
Context:
{context_text}

{policy_section}{doc_section}If the request is about SAP Ariba or SAP procurement, prefer the references above and answer from those references before using general reasoning. Never invent transaction codes, tenant-specific Ariba menu paths, approval thresholds, integration names, or policy rules.

{answer_contract}
"""


def call_ollama_chat(prompt, config, response_format="text"):
    base_url = str(config.get("ollama_base_url", "http://localhost:11434")).rstrip("/")
    model = str(config.get("ollama_model", "llama3.1:8b"))
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": config.get("system_prompt", "")},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "keep_alive": config.get("ollama_keep_alive", "30m"),
        "options": {
            "temperature": float(config.get("temperature", 0.2)),
            "top_p": float(config.get("top_p", 0.9)),
            "top_k": int(config.get("top_k", 50)),
            "num_predict": int(config.get("max_new_tokens", 512)),
            "repeat_penalty": float(config.get("repeat_penalty", 1.05)),
        },
    }
    if response_format in {"json", "structured"}:
        payload["format"] = "json"
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url}/api/chat",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    timeout = float(config.get("ollama_request_timeout", 30))
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = json.loads(response.read().decode("utf-8"))
    message = body.get("message", {}).get("content", "").strip()
    if not message:
        raise RuntimeError("Ollama returned an empty response")
    return message


def call_local_model(prompt, config, response_format="text"):
    backend = str(config.get("model_backend", "ollama")).lower()
    if backend == "ollama":
        try:
            return call_ollama_chat(prompt, config, response_format=response_format)
        except Exception as exc:
            if config.get("allow_local_transformer_fallback", True):
                append_audit({
                    "ts": datetime.utcnow().isoformat(),
                    "event": "ollama_fallback",
                    "detail": str(exc),
                })
                from ml_pipeline.local_model import generate_text as fallback_generate_text
                return fallback_generate_text(prompt, config, response_format=response_format)
            raise
    from ml_pipeline.local_model import generate_text as fallback_generate_text
    return fallback_generate_text(prompt, config, response_format=response_format)


def persist_session(session_id):
    path = SESSIONS_DIR / f"{session_id}.json"
    with path.open("w", encoding="utf-8") as f:
        json.dump(SESSIONS.get(session_id, {}), f, ensure_ascii=False, indent=2)


def clear_session(session_id):
    SESSIONS.pop(session_id, None)
    path = SESSIONS_DIR / f"{session_id}.json"
    if path.exists():
        path.unlink()


def start_background_job(cmd, job_id):
    # Start a background job and log to a file
    log_path = ROOT / f"jobs_{job_id}.log"
    with open(log_path, "w", encoding="utf-8") as out:
        subprocess.Popen(cmd, stdout=out, stderr=out, shell=False, cwd=str(ROOT))
    return str(log_path)


def render_homepage(config):
    template_path = ROOT / "ui.html"
    html = template_path.read_text(encoding="utf-8")
    html = html.replace("__MODEL_BACKEND__", config.get("model_backend", "ollama"))
    html = html.replace("__OLLAMA_MODEL__", config.get("ollama_model", "llama3.1:8b"))
    html = html.replace("__DEMO_PROFILE__", config.get("demo_profile", "1B-compatible prototype"))
    html = html.replace("__DEMO_RUNTIME_NOTE__", config.get("demo_runtime_note", "Runtime model shown in settings"))
    html = html.replace("__EMBEDDING_PATH__", config.get("embedding_model_path", "models/embedding_model"))
    return html


def serve_asset(handler, request_path):
    relative_path = request_path.lstrip("/").replace("/", os.sep)
    asset_path = (ROOT / relative_path).resolve()
    if not str(asset_path).startswith(str(ASSETS_DIR.resolve())) or not asset_path.is_file():
        handler.send_response(404)
        handler.end_headers()
        return

    content_type = mimetypes.guess_type(str(asset_path))[0] or "application/octet-stream"
    body = asset_path.read_bytes()
    handler.send_response(200)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    cors_headers(handler)
    handler.end_headers()
    handler.wfile.write(body)


def cors_headers(handler):
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type")


def derive_implementation(payload):
    text = f"{payload.get('message', '')} {payload.get('context', '')}".lower()
    if "register buyer" in text or "buyer registration" in text:
        action = "register_buyer"
    elif "create requisition" in text or "requisition" in text:
        action = "create_requisition"
    elif "req number" in text or "requisition number" in text:
        action = "requisition_number_generated"
    elif "approve" in text:
        action = "approve_request"
    elif "supplier" in text:
        action = "create_supplier"
    elif "contract" in text:
        action = "create_contract"
    else:
        action = "manual_review"

    amount_match = re.search(r"[$]?(\d{1,3}(?:,\d{3})*(?:\.\d+)?)", text)
    amount = amount_match.group(1) if amount_match else None
    details = {
        "source": "chat_request",
        "role": payload.get("role", "buyer"),
        "request": payload.get("message", ""),
        "context": payload.get("context", ""),
    }
    if amount:
        details["amount"] = amount

    return action, details


def match_ariba_knowledge(message, context):
    # Short-circuit for greetings/off-topic short inputs
    text_only = (message or "").strip()
    if not text_only:
        return None
    if len(text_only.split()) <= 3 and re.search(r"\b(hi|hello|hey|thanks|thank you)\b", text_only, re.I):
        return None

    intent = infer_intent(f"{message} {context}")
    knowledge = load_ariba_knowledge()
    intent_priority = {
        "buyer_registration": "buyer_registration",
        "requisition_number": "requisition_number",
        "approval": "requisition_approval",
        "supplier_onboarding": "supplier_onboarding",
        "catalog_po": "catalogs_and_po",
    }
    specific_approval_terms = re.search(
        r"\b(delegation|delegate|substitute|substitution|escalation|timeout|stuck|no approver|wrong approver|approval flow diagram|process history)\b",
        f"{message} {context} {expand_abbreviations(f'{message} {context}')}",
        re.I,
    )
    specific_supplier_or_catalog_terms = re.search(
        r"\b(punchout|catalog|upload|load|error|exception|validation|integration|network|trading relationship|cart|cxml|slp|asn|ses|sbn|gr|goods receipt|service sheet|shipping notice)\b",
        f"{message} {context} {expand_abbreviations(f'{message} {context}')}",
        re.I,
    )
    target_id = intent_priority.get(intent)
    if intent == "approval" and (specific_approval_terms or specific_supplier_or_catalog_terms):
        target_id = None
    if intent in {"supplier_onboarding", "catalog_po"} and specific_supplier_or_catalog_terms:
        target_id = None
    if target_id:
        for item in knowledge:
            if item.get("id") == target_id and item.get("source_type") == "local_ariba":
                return item

    # Use the richer document matcher first
    candidate = find_local_doc_match(message, context)
    if candidate:
        return candidate

    # Fallback: tag + token overlap scoring across knowledge items
    if not knowledge:
        return None

    text = f"{message} {context}"
    best = None
    best_score = 0.0
    for item in knowledge:
        score = score_knowledge_item(message, context, item, intent)
        if score > best_score:
            best_score = score
            best = item

    return best if best_score >= 1.1 else None


def format_knowledge_hit(item):
    related_sources = item.get("related_sources", []) or []
    source_urls = []
    policy_refs = list(item.get("policy_references", []) or [item.get("title", item.get("id", "Local knowledge base"))])
    for source in [item] + related_sources:
        if source.get("url") and source.get("url") not in source_urls:
            source_urls.append(source.get("url"))
        for ref in source.get("policy_references", []) or []:
            if ref not in policy_refs:
                policy_refs.append(ref)
    return {
        "Summary": item.get("summary", ""),
        "KeyRisks": item.get("key_risks", []),
        "RecommendedNextStep": item.get("recommended_next_step", ""),
        "ConfidenceLevel": item.get("confidence", "High"),
        "PolicyReferences": policy_refs,
        "SourceUrls": source_urls,
        "MatchedSource": item.get("title", item.get("id", "Local knowledge base")),
        "Codes": item.get("codes", []),
        "RelatedSources": [
            {
                "title": source.get("title", source.get("id", "Knowledge source")),
                "summary": source.get("summary", ""),
                "url": source.get("url", ""),
                "source_type": source.get("source_type", ""),
            }
            for source in related_sources
        ],
    }


def knowledge_answer(item):
    return format_knowledge_hit(item)


def format_conversational_grounded_answer(item):
    title = item.get("title", "SAP reference")
    summary = item.get("summary", "")
    functionality = item.get("functionality", "")
    next_step = item.get("recommended_next_step", "")
    risks = item.get("key_risks", [])
    codes = item.get("codes", [])
    lines = [f"{title}."]
    if functionality:
        lines.append(f"Functionality: {functionality}.")
    if summary:
        lines.append(f"Use it for: {summary}.")
    if codes:
        lines.append("Important distinction: SAP T-codes are for SAP GUI/SAP S/4HANA, not SAP Ariba tenant screens or Ariba shortcuts.")
    if risks:
        lines.append("Watch-outs: " + "; ".join(risks) + ".")
    if next_step:
        lines.append(f"Safest next step: {next_step}")
    return "\n".join(lines)


def synthesized_answer_conflicts(answer, item):
    normalized = normalize_text(answer)
    if item.get("codes") and "not an sap ariba shortcut" in normalize_text(" ".join(item.get("key_risks", []))):
        if "ariba" in normalized:
            return True
        if "not an sap sap transaction" in normalized or "not a sap transaction" in normalized or "not an sap transaction" in normalized:
            return True
    return False


def synthesize_grounded_answer(payload, config, item, response_style="human", intent=None, fallback_text=None):
    if not config.get("llm_synthesis", True) or response_style not in {"human", "action"}:
        return fallback_text

    message = payload_text(payload)
    context = payload.get("context", "")
    facts = format_knowledge_hit(item)
    assistant_domain = "enterprise HR and IT helpdesk" if item.get("source_type") == "enterprise_helpdesk" else "SAP/SAP Ariba"
    prompt = f"""Answer like an expert {assistant_domain} chatbot.
Use only these facts; do not invent causes, emails, codes, menu paths, thresholds, tenant settings, or policy rules.
If the facts mention an SAP transaction code, describe it as SAP GUI/SAP S/4HANA, not SAP Ariba, unless the facts explicitly say Ariba.
Do not offer step-by-step instructions unless the facts include the steps.
Do not mention SAP unless the question or facts are about SAP.

Question: {message}
Context: {context}
Intent: {intent or infer_intent(message + ' ' + context)}
Facts: {json.dumps(facts, ensure_ascii=False)}

Plain-text answer. Be conversational, accurate, and concise. Use 3 to 5 short sentences. Include the safest next step."""
    try:
        synthesis_config = dict(config)
        synthesis_config["max_new_tokens"] = int(config.get("synthesis_max_new_tokens", 180))
        answer = call_local_model(prompt, synthesis_config, response_format="text")
        answer = coerce_model_answer(answer, payload, [])
        if item.get("codes") and "not an SAP Ariba shortcut" in " ".join(item.get("key_risks", [])):
            answer = re.sub(r"\bin SAP Ariba\b", "in SAP GUI/SAP S/4HANA", answer, flags=re.I)
            answer = re.sub(r"\bSAP Ariba transaction code\b", "SAP transaction code", answer, flags=re.I)
            answer = re.sub(r"\bAriba shortcut\b", "SAP transaction code", answer, flags=re.I)
        if synthesized_answer_conflicts(answer, item):
            append_audit({
                "ts": datetime.utcnow().isoformat(),
                "event": "llm_synthesis_rejected",
                "topic": item.get("id", item.get("title", "knowledge")),
                "detail": answer[:400],
            })
            return fallback_text
        if answer.strip():
            return answer.strip()
    except Exception as exc:
        append_audit({
            "ts": datetime.utcnow().isoformat(),
            "event": "llm_synthesis_fallback",
            "topic": item.get("id", item.get("title", "knowledge")),
            "detail": str(exc),
        })
    return fallback_text


def fallback_chat_response(payload, relevant_policies):
    message = payload_text(payload)
    intent = infer_intent(message + " " + (payload.get("context") or ""))
    policy_names = [name for name, _ in relevant_policies]
    if intent == "buyer_registration":
        summary = "SAP Ariba buyer setup is usually an admin or user-provisioning task, not a keyboard shortcut."
        next_step = "Use the buyer provisioning workflow in your tenant and verify the assigned role and permissions."
    elif intent == "requisition_number":
        summary = "A requisition number is a useful automation trigger for tracking, approvals, and downstream actions."
        next_step = "Send the requisition number to the webhook endpoint so the system can record it and trigger the next step."
    elif intent == "approval":
        summary = "Requisition approval should follow the configured workflow, budget checks, and delegated authority."
        next_step = "Confirm the approval chain and threshold before releasing the requisition."
    elif "shortcut" in message.lower():
        summary = "SAP Ariba shortcuts are tenant-specific, so the exact path depends on your organization."
        next_step = "Check your tenant guide or admin documentation for the exact menu path or shortcut."
    else:
        summary = "I can help with SAP Ariba workflows, approvals, supplier setup, requisitions, and automation."
        next_step = "Tell me the Ariba task, requisition number, or supplier scenario and I'll map it to a local action."

    return {
        "Summary": summary,
        "KeyRisks": [
            "Tenant-specific Ariba settings can change the exact menu path",
            "Approval and provisioning rules may differ by role and business unit",
        ],
        "RecommendedNextStep": next_step,
        "ConfidenceLevel": "Medium",
        "PolicyReferences": policy_names,
    }


def coerce_model_answer(answer, payload, relevant_policies):
    response_style = str(payload.get("response_style", "human")).lower()
    if response_style in {"human", "action"}:
        if isinstance(answer, dict):
            return format_human_answer(
                {
                    "title": answer.get("MatchedSource") or "SAP Ariba response",
                    "summary": answer.get("Summary") or answer.get("summary") or "",
                    "key_risks": answer.get("KeyRisks") or answer.get("risks") or [],
                    "recommended_next_step": answer.get("RecommendedNextStep") or answer.get("next_step") or "",
                    "policy_references": answer.get("PolicyReferences") or answer.get("references") or [],
                },
                style=response_style,
            )
        if isinstance(answer, str):
            text = answer.strip()
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    return format_human_answer(
                        {
                            "title": parsed.get("MatchedSource") or "SAP Ariba response",
                            "summary": parsed.get("Summary") or parsed.get("summary") or "",
                            "key_risks": parsed.get("KeyRisks") or parsed.get("risks") or [],
                            "recommended_next_step": parsed.get("RecommendedNextStep") or parsed.get("next_step") or "",
                            "policy_references": parsed.get("PolicyReferences") or parsed.get("references") or [],
                        },
                        style=response_style,
                    )
                if isinstance(parsed, str):
                    return parsed.strip()
            except Exception:
                pass
            return text
        return ""

    if isinstance(answer, dict):
        return json.dumps(answer, ensure_ascii=False)

    if not isinstance(answer, str):
        return json.dumps(fallback_chat_response(payload, relevant_policies), ensure_ascii=False)

    text = answer.strip()
    if not text:
        return json.dumps(fallback_chat_response(payload, relevant_policies), ensure_ascii=False)

    try:
        parsed = json.loads(text)
        return json.dumps(parsed, ensure_ascii=False)
    except Exception:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = text[start : end + 1]
        try:
            parsed = json.loads(candidate)
            return json.dumps(parsed, ensure_ascii=False)
        except Exception:
            pass

    policy_names = [name for name, _ in relevant_policies]
    wrapped = {
        "Summary": text,
        "KeyRisks": ["Model returned non-JSON output"],
        "RecommendedNextStep": "Review the model output and refine the prompt if stricter JSON formatting is required.",
        "ConfidenceLevel": "Low",
        "PolicyReferences": policy_names,
    }
    return json.dumps(wrapped, ensure_ascii=False)


def is_specific_ariba_operational_question(message, context):
    text = f"{message} {context}"
    if not is_ariba_related(text):
        return False
    search_text = f"{text} {expand_abbreviations(text)}"
    return bool(re.search(
        r"\b(delegation|delegate|substitute|substitution|escalation|timeout|stuck|no approver|wrong approver|approval flow diagram|process history|punchout|cxml|catalog upload|invoice exception|contract compliance|rfq|rfx|rfp|rfi|cig|slp|asn|ses|sbn|cro|service sheet|shipping notice|goods receipt|http 500)\b",
        search_text,
        re.I,
    ))


def wants_sap_transaction_guidance(message, context):
    text = f"{message} {context}"
    if match_exact_sap_code(message, context):
        return True
    if infer_intent(text) == "sap_shortcuts":
        return True
    actions = canonical_actions(text)
    return bool(actions & {"create", "change", "display", "list", "compare", "monitor", "process", "forecast"})


def route_answer(payload, config, relevant_policies):
    message = payload_text(payload)
    context = payload.get("context", "")
    response_style = str(payload.get("response_style", "human")).lower()
    if is_greeting_or_empty(message):
        greeting_item = {
            "id": "greeting",
            "title": "SAP Ariba Assistant",
            "summary": "The user is greeting the assistant or has not provided a SAP/Ariba task yet.",
            "key_risks": [],
            "recommended_next_step": "Invite the user to ask about SAP Ariba workflows, SAP procurement T-codes, requisitions, approvals, suppliers, catalogs, purchase orders, or automation.",
            "policy_references": ["SAP Ariba assistant behavior"],
            "confidence": "High",
        }
        fallback = greeting_answer(response_style)
        if response_style in {"human", "action"}:
            return synthesize_grounded_answer(payload, config, greeting_item, response_style, "greeting", fallback), greeting_item
        return fallback, greeting_item
    intent = infer_intent(f"{message} {context}")
    exact_code_item = match_exact_sap_code(message, context)
    if exact_code_item:
        exact_code_item = enrich_with_related_sources(exact_code_item, message, context)
        if response_style in {"human", "action"}:
            fallback = format_conversational_grounded_answer(exact_code_item)
            answer = synthesize_grounded_answer(payload, config, exact_code_item, response_style, intent, fallback)
            return answer, exact_code_item
        return json.dumps(format_knowledge_hit(exact_code_item), ensure_ascii=False), exact_code_item
    if intent == "sap_shortcuts":
        shortcut_item = enrich_with_related_sources(shortcut_catalog_item(message, context), message, context)
        if response_style in {"human", "action"}:
            fallback = format_human_answer(shortcut_item, intent=intent, style=response_style)
            answer = synthesize_grounded_answer(payload, config, shortcut_item, response_style, intent, fallback)
            return answer, shortcut_item
        return json.dumps(format_knowledge_hit(shortcut_item), ensure_ascii=False), shortcut_item
    enterprise_item = match_ariba_knowledge(message, context)
    if enterprise_item and enterprise_item.get("source_type") == "enterprise_helpdesk" and not has_explicit_sap_context(f"{message} {context}"):
        enterprise_item = enrich_with_related_sources(enterprise_item, message, context)
        if response_style in {"human", "action"}:
            fallback = playbook_answer(intent, payload, relevant_policies, style=response_style, source_item=enterprise_item)
            answer = synthesize_grounded_answer(payload, config, enterprise_item, response_style, intent, fallback)
            return answer, enterprise_item
        return json.dumps(format_knowledge_hit(enterprise_item), ensure_ascii=False), enterprise_item
    if intent in {"sourcing", "integration"}:
        knowledge_item = match_ariba_knowledge(message, context)
        if knowledge_item:
            knowledge_item = enrich_with_related_sources(knowledge_item, message, context)
            if response_style in {"human", "action"}:
                fallback = playbook_answer(intent, payload, relevant_policies, style=response_style, source_item=knowledge_item)
                answer = synthesize_grounded_answer(payload, config, knowledge_item, response_style, intent, fallback)
                return answer, knowledge_item
            return json.dumps(format_knowledge_hit(knowledge_item), ensure_ascii=False), knowledge_item
    if is_specific_ariba_operational_question(message, context):
        knowledge_item = match_ariba_knowledge(message, context)
        if knowledge_item:
            knowledge_item = enrich_with_related_sources(knowledge_item, message, context)
            if response_style in {"human", "action"}:
                fallback = playbook_answer(intent, payload, relevant_policies, style=response_style, source_item=knowledge_item)
                answer = synthesize_grounded_answer(payload, config, knowledge_item, response_style, intent, fallback)
                return answer, knowledge_item
            return json.dumps(format_knowledge_hit(knowledge_item), ensure_ascii=False), knowledge_item
    if intent in {"approval", "supplier_onboarding", "catalog_po", "buyer_registration", "requisition_number"} and not wants_sap_transaction_guidance(message, context):
        knowledge_item = match_ariba_knowledge(message, context)
        if knowledge_item and knowledge_item.get("source_type") != "downloaded_tcode":
            knowledge_item = enrich_with_related_sources(knowledge_item, message, context)
            if response_style in {"human", "action"}:
                fallback = playbook_answer(intent, payload, relevant_policies, style=response_style, source_item=knowledge_item)
                answer = synthesize_grounded_answer(payload, config, knowledge_item, response_style, intent, fallback)
                return answer, knowledge_item
            return json.dumps(format_knowledge_hit(knowledge_item), ensure_ascii=False), knowledge_item
    task_code_item = match_sap_code_by_task(message, context)
    if task_code_item:
        task_code_item = enrich_with_related_sources(task_code_item, message, context)
        if response_style in {"human", "action"}:
            fallback = format_conversational_grounded_answer(task_code_item)
            answer = synthesize_grounded_answer(payload, config, task_code_item, response_style, intent, fallback)
            return answer, task_code_item
        return json.dumps(format_knowledge_hit(task_code_item), ensure_ascii=False), task_code_item
    functionality_item = match_sap_functionality(message, context)
    if functionality_item:
        if response_style in {"human", "action"}:
            code_lines = [f"{code.get('code')}: {code.get('summary', '')}" for code in functionality_item.get("codes", [])]
            payload_item = {
                "title": functionality_item.get("title", "SAP functionality"),
                "summary": functionality_item.get("summary", ""),
                "key_risks": [
                    "These are SAP GUI transaction codes and may differ from SAP Ariba tenant screens",
                    "Access depends on your SAP role and authorization",
                ],
                "recommended_next_step": functionality_item.get("recommended_next_step", ""),
                "policy_references": functionality_item.get("policy_references", []),
                "codes": code_lines,
            }
            payload_item = enrich_with_related_sources(payload_item, message, context)
            fallback = format_human_answer(payload_item, intent=intent, style=response_style)
            answer = synthesize_grounded_answer(payload, config, payload_item, response_style, intent, fallback)
            return answer, functionality_item
        return json.dumps(format_knowledge_hit(functionality_item), ensure_ascii=False), functionality_item
    knowledge_item = match_ariba_knowledge(message, context)
    if knowledge_item:
        knowledge_item = enrich_with_related_sources(knowledge_item, message, context)
        if response_style in {"human", "action"}:
            fallback = playbook_answer(intent, payload, relevant_policies, style=response_style, source_item=knowledge_item)
            answer = synthesize_grounded_answer(payload, config, knowledge_item, response_style, intent, fallback)
            return answer, knowledge_item
        return json.dumps(format_knowledge_hit(knowledge_item), ensure_ascii=False), knowledge_item

    if is_ariba_related(f"{message} {context}") and intent != "general_procurement":
        playbook_item = {
            "id": intent,
            "title": {
                "buyer_registration": "SAP Ariba Buyer Registration",
                "requisition_number": "SAP Ariba Requisition Number",
                "approval": "SAP Ariba Approval Flow",
                "supplier_onboarding": "SAP Ariba Supplier Onboarding",
                "catalog_po": "SAP Ariba Catalog / Purchase Order",
            }.get(intent, "SAP Ariba Guidance"),
            "summary": fallback_chat_response(payload, relevant_policies).get("Summary", ""),
            "key_risks": fallback_chat_response(payload, relevant_policies).get("KeyRisks", []),
            "recommended_next_step": fallback_chat_response(payload, relevant_policies).get("RecommendedNextStep", ""),
            "policy_references": [name for name, _ in relevant_policies] or ["SAP Ariba local knowledge base"],
            "confidence": "Medium",
        }
        fallback = playbook_answer(intent, payload, relevant_policies, style=response_style)
        answer = synthesize_grounded_answer(payload, config, playbook_item, response_style, intent, fallback)
        return answer, {"id": intent}

    relevant_sources = find_relevant_sources(message, context)
    prompt = build_prompt(
        {
            "role": payload.get("role", "buyer"),
            "request": message,
            "context": context,
            "relevant_sources": relevant_sources,
            "response_style": response_style,
            "intent": intent,
        },
        config,
        relevant_policies,
    )
    try:
        model_format = "json" if response_style in {"structured", "json"} else "text"
        answer = call_local_model(prompt, config, response_format=model_format)
        coerced = coerce_model_answer(answer, payload, relevant_policies)
        if coerced != answer:
            append_audit({"ts": datetime.utcnow().isoformat(), "event": "model_invalid_output", "detail": str(answer)[:400]})
        return coerced, None
    except FutureTimeoutError:
        return json.dumps(fallback_chat_response(payload, relevant_policies), ensure_ascii=False), None
    except Exception:
        return json.dumps(fallback_chat_response(payload, relevant_policies), ensure_ascii=False), None


def handle_requisition_generated(payload, config):
    requisition_number = payload.get("requisition_number") or payload.get("req_number") or payload.get("request_number")
    if not requisition_number:
        raise ValueError("requisition_number is required")

    details = {
        "source": "ariba_webhook",
        "requisition_number": requisition_number,
        "status": payload.get("status", "generated"),
        "role": payload.get("role", "buyer"),
    }
    if payload.get("buyer"):
        details["buyer"] = payload["buyer"]
    if payload.get("requester"):
        details["requester"] = payload["requester"]

    simulate = bool(payload.get("simulate", True)) or not config.get("allow_ariba_calls", False)
    action = "requisition_number_generated"
    if not simulate:
        from ariba_adapter import execute_action
        result = execute_action(action, details, config)
    else:
        result = {
            "status": "simulated",
            "message": f"Recorded requisition {requisition_number} for downstream automation",
        }
        append_audit({
            "ts": datetime.utcnow().isoformat(),
            "event": "simulate_requisition_event",
            "requisition_number": requisition_number,
        })

    return {
        "status": "received",
        "action": action,
        "details": details,
        "simulate": simulate,
        "result": result,
    }


class ProcurementHandler(BaseHTTPRequestHandler):
    def _send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        cors_headers(self)
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, status, html):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        cors_headers(self)
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        cors_headers(self)
        self.end_headers()

    def do_GET(self):
        if self.path in {"/", "/index.html"}:
            config = load_config()
            html = render_homepage(config)
            self._send_html(200, html)
            return
        if self.path.startswith("/assets/"):
            serve_asset(self, self.path)
            return
        if self.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return
        if self.path == "/health":
            self._send_json(200, {"status": "ok", "local_only": True})
            return
        if self.path == "/procurement/session/clear":
            self._send_json(405, {"error": "Use POST"})
            return
        if self.path.startswith("/procurement/session/"):
            session_id = self.path.split('/')[-1]
            sess = SESSIONS.get(session_id)
            if not sess:
                self._send_json(404, {"error": "Session not found"})
                return
            self._send_json(200, {"session": sess})
            return
        self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        try:
            try:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length).decode("utf-8")
                payload = json.loads(raw) if raw else {}
            except Exception as exc:
                self._send_json(400, {"error": f"Invalid JSON: {exc}"})
                return

            config = load_config()
            config = apply_runtime_config_overrides(config, payload)

            if self.path == "/procurement/chat":
                session_id = payload.get("session_id") or str(uuid.uuid4())
                role = payload.get("role", "buyer")
                message = payload.get("message", "")
                auto_implement = bool(payload.get("auto_implement", False))

                sess = SESSIONS.setdefault(session_id, {"role": role, "history": []})
                sess["history"].append({"from": role, "text": message, "ts": datetime.utcnow().isoformat()})

                policies = load_policies(config)
                relevant_policies = find_relevant_policies(payload, policies)
                response_style = str(payload.get("response_style", "human")).lower()
                answer, knowledge_item = route_answer(payload, config, relevant_policies)
                if knowledge_item:
                    append_audit({
                        "ts": datetime.utcnow().isoformat(),
                        "event": "chat_knowledge",
                        "role": role,
                        "session": session_id,
                        "topic": knowledge_item.get("id", "unknown"),
                    })
                elif response_style in {"structured", "json"}:
                    try:
                        parsed = json.loads(answer)
                        if not isinstance(parsed, dict):
                            raise ValueError("non-object answer")
                    except Exception:
                        append_audit({
                            "ts": datetime.utcnow().isoformat(),
                            "event": "chat_model_invalid_output",
                            "session": session_id,
                            "detail": str(answer)[:400],
                        })
                        answer = json.dumps(fallback_chat_response(payload, relevant_policies), ensure_ascii=False)

                sess["history"].append({"from": "assistant", "text": answer, "ts": datetime.utcnow().isoformat()})
                persist_session(session_id)
                append_audit({"ts": datetime.utcnow().isoformat(), "event": "chat", "role": role, "session": session_id})
                response_payload = {
                    "session_id": session_id,
                    "answer": answer,
                    "model": config.get("ollama_model"),
                    "relevant_policies": [name for name, _ in relevant_policies],
                }

                if auto_implement:
                    action, details = derive_implementation(payload)
                    try:
                        from ariba_adapter import execute_action
                        implementation = execute_action(action, details, config)
                        simulate = bool(payload.get("simulate", True)) or not config.get("allow_ariba_calls", False)
                    except Exception as exc:
                        simulate = True
                        implementation = {"status": "failed", "error": str(exc)}
                    append_audit({
                        "ts": datetime.utcnow().isoformat(),
                        "event": "auto_implement",
                        "role": role,
                        "session": session_id,
                        "action": action,
                    })
                    response_payload["implementation"] = {
                        "action": action,
                        "details": details,
                        "simulate": simulate,
                        "result": implementation,
                    }

                self._send_json(200, response_payload)
                return

            if self.path == "/procurement/session/clear":
                session_id = payload.get("session_id")
                if not session_id:
                    self._send_json(400, {"error": "session_id is required"})
                    return
                clear_session(session_id)
                append_audit({
                    "ts": datetime.utcnow().isoformat(),
                    "event": "session_cleared",
                    "session": session_id,
                })
                self._send_json(200, {"status": "cleared", "session_id": session_id})
                return

            if self.path == "/procurement/ariba/webhook":
                role = payload.get("role", "admin")
                if role not in config.get("allowed_roles", []):
                    self._send_json(403, {"error": "Role not authorized"})
                    return
                try:
                    result = handle_requisition_generated(payload, config)
                except Exception as exc:
                    append_audit({
                        "ts": datetime.utcnow().isoformat(),
                        "event": "requisition_event_error",
                        "detail": str(exc),
                    })
                    self._send_json(400, {"error": str(exc)})
                    return

                append_audit({
                    "ts": datetime.utcnow().isoformat(),
                    "event": "requisition_generated",
                    "requisition_number": result["details"]["requisition_number"],
                })
                self._send_json(200, result)
                return

            if self.path == "/procurement/execute":
                role = payload.get("role", "")
                if role not in config.get("allowed_roles", []):
                    append_audit({"ts": datetime.utcnow().isoformat(), "event": "forbidden_execute", "role": role})
                    self._send_json(403, {"error": "Role not authorized"})
                    return

                action = payload.get("action")
                details = payload.get("details", {})
                simulate = payload.get("simulate", True)

                if simulate or not config.get("allow_ariba_calls", False):
                    log_entry = {
                        "ts": datetime.utcnow().isoformat(),
                        "event": "simulate_execute",
                        "role": role,
                        "action": action,
                        "details": details,
                    }
                    append_audit(log_entry)
                    sim_path = ROOT / "ariba_simulator.log"
                    with sim_path.open("a", encoding="utf-8") as f:
                        f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
                    self._send_json(200, {"result": "simulated", "log": str(sim_path)})
                    return

                try:
                    from ariba_adapter import execute_action
                    result = execute_action(action, details, config)
                except Exception as exc:
                    append_audit({"ts": datetime.utcnow().isoformat(), "event": "execute_error", "detail": str(exc)})
                    self._send_json(500, {"error": "Execution failed", "detail": str(exc)})
                    return

                append_audit({"ts": datetime.utcnow().isoformat(), "event": "execute", "role": role, "action": action})
                self._send_json(200, {"result": result})
                return

            if self.path == "/procurement/train":
                role = payload.get("role", "")
                if role not in config.get("allowed_roles", []):
                    self._send_json(403, {"error": "Role not authorized"})
                    return

                model_type = payload.get("model", "sentence_transformer")
                params = payload.get("params", {})
                job_id = str(uuid.uuid4())
                if model_type == "sentence_transformer":
                    cmd = [
                        sys.executable,
                        str(ROOT / "ml_pipeline" / "train_sentence_transformer.py"),
                        "--train-file",
                        params.get("train_file", "train_pairs.tsv"),
                        "--model",
                        params.get("model_path", config.get("embedding_model_path", "./models/embedding_model")),
                        "--output-dir",
                        params.get("output_dir", "./st_model"),
                        "--epochs",
                        str(params.get("epochs", 1)),
                    ]
                    if "validation_split" in params:
                        cmd.extend(["--validation-split", str(params["validation_split"])])
                    if "seed" in params:
                        cmd.extend(["--seed", str(params["seed"])])
                elif model_type == "lm":
                    mode = params.get("mode", "finetune")
                    if mode == "scratch":
                        cmd = [
                            sys.executable,
                            str(ROOT / "ml_pipeline" / "train_lm_from_scratch.py"),
                            "--corpus",
                            params.get("dataset", "./dataset.txt"),
                            "--output-dir",
                            params.get("output_dir", "./lm_scratch"),
                            "--epochs",
                            str(params.get("epochs", 1)),
                        ]
                    else:
                        cmd = [
                            sys.executable,
                            str(ROOT / "ml_pipeline" / "train_lm.py"),
                            "--train-file",
                            params.get("dataset", "./dataset.txt"),
                            "--base-model-path",
                            params.get("base_model_path", config.get("local_model_path", "./models/procurement_lm")),
                            "--output-dir",
                            params.get("output_dir", "./lm_local"),
                            "--epochs",
                            str(params.get("epochs", 1)),
                        ]
                    if "validation_split" in params:
                        cmd.extend(["--validation-split", str(params["validation_split"])])
                    if "seed" in params:
                        cmd.extend(["--seed", str(params["seed"])])
                else:
                    self._send_json(400, {"error": "Unsupported model type"})
                    return

                log_path = start_background_job(cmd, job_id)
                append_audit({"ts": datetime.utcnow().isoformat(), "event": "train_start", "role": role, "model": model_type, "job_id": job_id})
                self._send_json(200, {"job_id": job_id, "log": log_path})
                return

            if self.path == "/procurement/validate":
                role = payload.get("role", "")
                if role not in config.get("allowed_roles", []):
                    self._send_json(403, {"error": "Role not authorized"})
                    return

                model_type = payload.get("model", "lm")
                params = payload.get("params", {})
                job_id = str(uuid.uuid4())
                model_path = params.get("model_path", config.get("local_model_path", "./models/procurement_lm"))
                if model_type == "sentence_transformer":
                    model_path = params.get("model_path", config.get("embedding_model_path", "./models/embedding_model"))

                cmd = [
                    sys.executable,
                    str(ROOT / "ml_pipeline" / "validate_model.py"),
                    "--model-type",
                    model_type,
                    "--model-path",
                    model_path,
                    "--data-file",
                    params.get("data_file", "dataset.txt"),
                    "--output",
                    params.get("output", f"validation_{job_id}.json"),
                ]
                if model_type == "sentence_transformer" and "threshold" in params:
                    cmd.extend(["--threshold", str(params["threshold"])])

                log_path = start_background_job(cmd, job_id)
                append_audit({"ts": datetime.utcnow().isoformat(), "event": "validate_start", "role": role, "model": model_type, "job_id": job_id})
                self._send_json(200, {"job_id": job_id, "log": log_path})
                return

            if self.path == "/procurement/eda":
                role = payload.get("role", "")
                if role not in config.get("allowed_roles", []):
                    self._send_json(403, {"error": "Role not authorized"})
                    return

                input_dir = Path(payload.get("input_dir", ROOT / config.get("policy_folder", "policies")))
                output = payload.get("output")
                recursive = bool(payload.get("recursive", False))

                from ml_pipeline.eda import aggregate, analyze_dir

                docs = analyze_dir(input_dir, recursive=recursive)
                report = aggregate(docs)
                if output:
                    output_path = Path(output)
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

                append_audit({"ts": datetime.utcnow().isoformat(), "event": "eda", "role": role, "input_dir": str(input_dir), "docs": len(docs)})
                self._send_json(200, {"report": report, "output": output})
                return

            if self.path == "/procurement/assist":
                role = payload.get("role", "")
                if role not in config.get("allowed_roles", []):
                    append_audit({"ts": datetime.utcnow().isoformat(), "event": "forbidden", "role": role})
                    self._send_json(403, {"error": "Role not authorized"})
                    return

                policies = load_policies(config)
                relevant_policies = find_relevant_policies(payload, policies)
                answer, knowledge_item = route_answer(payload, config, relevant_policies)
                if knowledge_item:
                    append_audit({
                        "ts": datetime.utcnow().isoformat(),
                        "event": "assist_knowledge",
                        "role": role,
                        "policies": [name for name, _ in relevant_policies],
                        "topic": knowledge_item.get("id", "local"),
                    })
                append_audit({
                    "ts": datetime.utcnow().isoformat(),
                    "event": "assist",
                    "role": role,
                    "request": payload.get("request", "")[:200],
                    "policies": [name for name, _ in relevant_policies],
                })
                self._send_json(200, {
                    "answer": answer,
                    "model": config.get("model_backend", "ollama"),
                    "local_only": True,
                    "relevant_policies": [name for name, _ in relevant_policies],
                })
                return

            if self.path == "/procurement/assist":
                role = payload.get("role", "")
                if role not in config.get("allowed_roles", []):
                    append_audit({"ts": datetime.utcnow().isoformat(), "event": "forbidden", "role": role})
                    self._send_json(403, {"error": "Role not authorized"})
                    return

                policies = load_policies(config)
                relevant_policies = find_relevant_policies(payload, policies)
                policy_names = [name for name, _ in relevant_policies]

                # Normalize request text
                request_text = (payload.get("message") or payload.get("request") or "").strip()

                # Simple greeting/off-topic filter to avoid model hallucination on short inputs
                if len(request_text.split()) <= 3 and re.search(r"\b(hi|hello|hey|thanks|thank you)\b", request_text, re.I):
                    canned = {
                        "Summary": "Hello — I'm the procurement assistant. Ask a procurement question or include requisition details.",
                        "KeyRisks": [],
                        "RecommendedNextStep": "Try: 'How do I register a buyer in Ariba?' or provide a requisition number.",
                        "ConfidenceLevel": "N/A",
                        "PolicyReferences": [],
                    }
                    answer = json.dumps(canned, ensure_ascii=False)
                    append_audit({"ts": datetime.utcnow().isoformat(), "event": "assist_greeting", "role": role})
                    self._send_json(200, {
                        "answer": answer,
                        "model": config.get("model"),
                        "local_only": True,
                        "relevant_policies": policy_names,
                    })
                    return

                # Knowledge-first: check local SAP/Ariba knowledge before invoking model
                knowledge_item = match_ariba_knowledge(request_text, payload.get("context", ""))
                if knowledge_item:
                    answer = json.dumps(knowledge_answer(knowledge_item), ensure_ascii=False)
                    append_audit({"ts": datetime.utcnow().isoformat(), "event": "assist_knowledge", "role": role, "policies": policy_names, "topic": knowledge_item.get("id", "local")})
                else:
                    try:
                        prompt = build_prompt(payload, config, relevant_policies)
                        answer = call_local_model(prompt, config)
                        coerced = coerce_model_answer(answer, payload, relevant_policies)
                        if coerced != answer:
                            append_audit({"ts": datetime.utcnow().isoformat(), "event": "assist_model_invalid_output", "role": role, "detail": str(answer)[:400]})
                        answer = coerced
                    except Exception as exc:
                        append_audit({"ts": datetime.utcnow().isoformat(), "event": "model_error", "detail": str(exc), "policies": policy_names})
                        answer = json.dumps(fallback_chat_response(payload, relevant_policies), ensure_ascii=False)

                append_audit({
                    "ts": datetime.utcnow().isoformat(),
                    "event": "assist",
                    "role": role,
                    "request": payload.get("request", "")[:200],
                    "policies": policy_names,
                })
                self._send_json(200, {
                    "answer": answer,
                    "model": config.get("model"),
                    "local_only": True,
                    "relevant_policies": policy_names,
                })
                return

            self._send_json(404, {"error": "Not found"})
        except Exception as exc:
            append_audit({"ts": datetime.utcnow().isoformat(), "event": "unhandled_post_error", "detail": str(exc)})
            self._send_json(500, {"error": "Internal server error", "detail": str(exc)})


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    from http.server import ThreadingHTTPServer

    server = ThreadingHTTPServer((host, port), ProcurementHandler)
    print(f"Sam Copilot server running on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server")
        server.server_close()
