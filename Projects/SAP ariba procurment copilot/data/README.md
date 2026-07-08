# Data

This folder keeps source knowledge files separate from active chatbot policy files.

- `raw/` contains the original downloaded JSON and ZIP files.
- `../tools/build_master_knowledge.py` reads the raw files and existing SAP Ariba policy files.
- `../policies/sap_ariba_master_knowledge.json` is the generated, deduplicated chatbot knowledge source.

When new SAP Ariba support data is added, place it in `raw/`, update the builder if the schema is new, then regenerate the master policy file.
