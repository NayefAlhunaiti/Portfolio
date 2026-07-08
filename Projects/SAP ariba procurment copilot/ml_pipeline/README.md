# ML Pipeline

This folder contains the local training and evaluation utilities used by the procurement assistant.

## Local-first workflow

1. Train or copy a sentence-transformer checkpoint into `../models/embedding_model`.
2. Train or copy a causal LM checkpoint into `../models/procurement_lm`.
3. Run EDA on procurement documents.
4. Build FAISS embeddings locally.
5. Train and validate models locally.

## Install

```powershell
python -m pip install -r ml_requirements.txt
```

## EDA

```powershell
python eda.py --input-dir ../policies --output report.json --recursive
```

## Embeddings

```powershell
python build_embeddings.py --input-dir ../policies --index-file policy_index.faiss --model ../models/embedding_model
```

```powershell
python retrieve.py --index-file policy_index.faiss --meta-file policy_meta.json --query "purchase requisition over $10000" --topk 3 --model ../models/embedding_model
```

## Sentence-transformer training

```powershell
python train_sentence_transformer.py --train-file train_pairs.tsv --model ../models/embedding_model --output-dir ./st_model --epochs 3 --validation-split 0.2
```

## Local LM training

Fine-tune a local base checkpoint:

```powershell
python train_lm.py --train-file dataset.txt --base-model-path ../models/procurement_lm --output-dir ./lm_local --epochs 1 --validation-split 0.2
```

Train from scratch with a local tokenizer and GPT-style config:

```powershell
python train_lm_from_scratch.py --corpus dataset.txt --output-dir ./lm_scratch --epochs 1 --validation-split 0.2
```

## Validation

```powershell
python validate_model.py --model-type lm --model-path ../models/procurement_lm --data-file dataset.txt --output lm_validation.json
```

```powershell
python validate_model.py --model-type sentence_transformer --model-path ../models/embedding_model --data-file train_pairs.tsv --output st_validation.json
```
