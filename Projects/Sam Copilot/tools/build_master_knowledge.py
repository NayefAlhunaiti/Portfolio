import json
import re
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "data" / "raw"
POLICY_DIR = ROOT / "policies"
OUTPUT_PATH = POLICY_DIR / "sap_ariba_master_knowledge.json"


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_zip_json(zip_path, member_name):
    with zipfile.ZipFile(zip_path) as archive:
        return json.loads(archive.read(member_name).decode("utf-8-sig"))


def stringify(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        return " ".join(stringify(item) for item in value if stringify(item)).strip()
    if isinstance(value, dict):
        parts = []
        for key, item in value.items():
            text = stringify(item)
            if text:
                parts.append(f"{title_from_key(str(key))}: {text}")
        return " ".join(parts).strip()
    return str(value).strip()


def title_from_key(value):
    value = re.sub(r"[_\-]+", " ", value).strip()
    return value[:1].upper() + value[1:] if value else ""


def normalize_text(value):
    return re.sub(r"[^a-z0-9]+", " ", str(value).lower()).strip()


def tags_from(*values):
    stopwords = {
        "about", "after", "also", "and", "ariba", "because", "before", "from",
        "have", "into", "sap", "that", "the", "this", "with", "your",
    }
    tags = []
    for value in values:
        for token in normalize_text(value).split():
            if len(token) < 4 or token in stopwords or token in tags:
                continue
            tags.append(token)
            if len(tags) >= 16:
                return tags
    return tags


def compact_list(values, limit=8):
    result = []
    for value in values or []:
        text = stringify(value)
        if text and text not in result:
            result.append(text)
        if len(result) >= limit:
            break
    return result


def make_record(
    item_id,
    title,
    summary,
    content="",
    tags=None,
    risks=None,
    next_step="",
    confidence="Reference",
    source_url="",
    references=None,
):
    summary = stringify(summary)
    content = stringify(content)
    if not item_id or not title or not (summary or content):
        return None
    return {
        "id": item_id,
        "title": title.strip(),
        "summary": summary or content[:500],
        "content": content,
        "tags": compact_list(tags or tags_from(title, summary, content), 20),
        "key_risks": compact_list(risks, 8),
        "recommended_next_step": stringify(next_step),
        "confidence": confidence or "Reference",
        "source_url": stringify(source_url),
        "policy_references": compact_list(references or ["SAP Ariba integrated master knowledge base"], 6),
    }


def from_bullseye_record(record):
    record_id = stringify(record.get("record_id") or record.get("id"))
    title = stringify(record.get("canonical_title") or record.get("title") or record.get("question"))
    summary = stringify(record.get("short_answer") or record.get("answer") or record.get("resolution"))
    content_parts = [
        stringify(record.get("module")),
        stringify(record.get("record_type")),
        stringify(record.get("symptoms")),
        stringify(record.get("conditions")),
        stringify(record.get("probable_causes")),
        stringify(record.get("diagnostic_steps")),
        stringify(record.get("resolution_steps")),
        stringify(record.get("workarounds")),
        stringify(record.get("retrieval_text")),
    ]
    next_step = stringify(record.get("recommended_next_step") or record.get("resolution_steps"))
    tags = compact_list(
        list(record.get("keywords") or [])
        + list(record.get("synonyms") or [])
        + list(record.get("user_intents") or [])
        + [record.get("module"), record.get("submodule"), record.get("record_type")],
        20,
    )
    risks = list(record.get("caveats") or []) + list(record.get("probable_causes") or [])
    return make_record(
        f"master_{normalize_text(record_id).replace(' ', '_')}",
        title,
        summary,
        " ".join(part for part in content_parts if part),
        tags=tags,
        risks=risks,
        next_step=next_step,
        confidence=stringify(record.get("confidence") or record.get("confidence_tier") or "Reference"),
        source_url=record.get("source_url") or record.get("primary_source_url") or "",
        references=["SAP Ariba master knowledge base"],
    )


def from_dataset_entry(entry, prefix):
    entry_id = stringify(entry.get("id"))
    title = stringify(entry.get("question") or entry.get("topic") or entry.get("title") or entry_id)
    summary = stringify(entry.get("answer") or entry.get("resolution") or entry.get("knowledge"))
    content = stringify(
        {
            "root_cause": entry.get("root_cause"),
            "resolution": entry.get("resolution"),
            "knowledge": entry.get("knowledge"),
            "source_type": entry.get("source_type"),
        }
    )
    return make_record(
        f"{prefix}_{normalize_text(entry_id or title).replace(' ', '_')}",
        title,
        summary,
        content,
        tags=[entry.get("category"), entry.get("source_type")] + tags_from(title, summary, content),
        risks=[entry.get("root_cause")] if entry.get("root_cause") else [],
        next_step=entry.get("resolution") or entry.get("answer") or "",
        confidence=stringify(entry.get("confidence") or "Reference"),
        source_url=entry.get("source_url") or "",
        references=["SAP Ariba chatbot support dataset"],
    )


def from_legacy_local_item(item):
    return make_record(
        f"legacy_{normalize_text(item.get('id') or item.get('title')).replace(' ', '_')}",
        stringify(item.get("title") or item.get("id")).replace("_", " ").title(),
        item.get("summary"),
        item.get("content", ""),
        tags=item.get("tags") or tags_from(item.get("title"), item.get("summary"), item.get("content")),
        risks=item.get("key_risks"),
        next_step=item.get("recommended_next_step", ""),
        confidence=item.get("confidence", "High"),
        references=item.get("policy_references") or ["SAP Ariba local knowledge base"],
    )


def from_legacy_comprehensive(data):
    records = []
    title = data.get("title", "SAP Ariba comprehensive knowledge base")

    overview = data.get("platform_overview")
    if isinstance(overview, dict):
        records.append(make_record(
            "legacy_ariba_platform_overview",
            "SAP Ariba Platform Overview",
            overview.get("what_it_is"),
            overview,
            tags=["platform", "overview", "upstream", "downstream", "network", "realm"],
            references=[title],
        ))

    for section_name in ("navigation", "implementation", "complex_processes_deep_dive"):
        section = data.get(section_name)
        if isinstance(section, dict):
            for key, value in section.items():
                records.append(make_record(
                    f"ariba_deep_dive_{normalize_text(key).replace(' ', '_')}" if section_name == "complex_processes_deep_dive" else f"legacy_{section_name}_{normalize_text(key).replace(' ', '_')}",
                    f"SAP Ariba {title_from_key(section_name)} - {title_from_key(key)}",
                    stringify(value).split(". ")[0][:500],
                    value,
                    tags=[section_name, key] + tags_from(key, value),
                    references=[title],
                ))

    modules = data.get("modules")
    if isinstance(modules, dict):
        for key, module in modules.items():
            records.append(make_record(
                f"legacy_module_{normalize_text(key).replace(' ', '_')}",
                f"SAP Ariba Module - {title_from_key(key)}",
                module.get("purpose") if isinstance(module, dict) else module,
                module,
                tags=["module", key] + tags_from(key, module),
                next_step="Verify tenant licensing and configuration before assuming the module is enabled.",
                references=[title],
            ))

    for index, item in enumerate(data.get("troubleshooting_playbook") or [], start=1):
        records.append(make_record(
            f"ariba_troubleshooting_{index}",
            f"SAP Ariba Troubleshooting - {stringify(item.get('symptom'))[:90]}",
            item.get("symptom"),
            item,
            tags=["troubleshooting"] + tags_from(item),
            risks=item.get("likely_causes") if isinstance(item, dict) else [],
            next_step=item.get("where_to_look") if isinstance(item, dict) else "",
            references=[title],
        ))

    for index, item in enumerate(data.get("best_practices") or [], start=1):
        records.append(make_record(
            f"legacy_best_practice_{index}",
            f"SAP Ariba Best Practice {index}",
            item,
            item,
            tags=["best practice"] + tags_from(item),
            references=[title],
        ))

    glossary = data.get("glossary")
    if isinstance(glossary, dict):
        for term, definition in glossary.items():
            records.append(make_record(
                f"legacy_glossary_{normalize_text(term).replace(' ', '_')}",
                f"SAP Ariba Glossary - {term}",
                definition,
                definition,
                tags=["glossary", term],
                references=[title],
            ))

    return [record for record in records if record]


def add_unique(records, record, seen):
    if not record:
        return
    signature = normalize_text(f"{record.get('title')} {record.get('summary')}")
    if not signature:
        return
    compact_signature = " ".join(signature.split()[:40])
    if compact_signature in seen:
        existing = seen[compact_signature]
        existing["tags"] = compact_list(existing.get("tags", []) + record.get("tags", []), 20)
        existing["key_risks"] = compact_list(existing.get("key_risks", []) + record.get("key_risks", []), 8)
        existing["policy_references"] = compact_list(
            existing.get("policy_references", []) + record.get("policy_references", []),
            6,
        )
        if record.get("source_url") and not existing.get("source_url"):
            existing["source_url"] = record["source_url"]
        return
    seen[compact_signature] = record
    records.append(record)


def main():
    records = []
    seen = {}

    master = read_zip_json(
        RAW_DIR / "SAP_Ariba_Master_Knowledge_Base.zip",
        "sap_ariba_knowledge_base_bullseye_v5_external_integrated.json",
    )
    for item in master.get("knowledge_base", []):
        add_unique(records, from_bullseye_record(item), seen)

    # The v5 master archive already includes the v3/v2/v1 chatbot datasets.
    # Keep those raw files in data/raw for traceability, but do not add them a
    # second time to the active policy file.

    legacy_local = read_json(POLICY_DIR / "sap_ariba_knowledge.json")
    for item in legacy_local:
        add_unique(records, from_legacy_local_item(item), seen)

    legacy_path = RAW_DIR / "legacy_sap_ariba_knowledge_base.json"
    if not legacy_path.exists():
        legacy_path = POLICY_DIR / "sap_ariba_knowledge_base.json"
    legacy_comprehensive = read_json(legacy_path)
    for item in from_legacy_comprehensive(legacy_comprehensive):
        add_unique(records, item, seen)

    records.sort(key=lambda item: (item.get("title", "").lower(), item.get("id", "")))
    OUTPUT_PATH.write_text(json.dumps(records, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {len(records)} deduplicated records to {OUTPUT_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
