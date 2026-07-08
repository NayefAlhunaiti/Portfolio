import argparse
import json
import math
from pathlib import Path

import numpy as np
from datasets import Dataset
from scipy.stats import spearmanr
from sentence_transformers import SentenceTransformer
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    DataCollatorForLanguageModeling,
    Trainer,
    TrainingArguments,
)


def load_text_samples(path: Path):
    samples = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) >= 2:
            samples.append(f"Instruction:\n{parts[0]}\nResponse:\n{parts[1]}")
        else:
            samples.append(line)
    return samples


def load_sentence_pairs(path: Path):
    rows = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        score = float(parts[2]) if len(parts) >= 3 else 1.0
        rows.append((parts[0], parts[1], score))
    return rows


def validate_lm(model_path: Path, data_file: Path, output_path: Path, local_files_only=True):
    tokenizer = AutoTokenizer.from_pretrained(str(model_path), local_files_only=local_files_only, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token or tokenizer.unk_token

    model = AutoModelForCausalLM.from_pretrained(str(model_path), local_files_only=local_files_only)
    model.eval()

    samples = load_text_samples(data_file)
    dataset = Dataset.from_dict({"text": samples})

    def tokenize(batch):
        return tokenizer(batch["text"], truncation=True, max_length=512)

    tokenized = dataset.map(tokenize, batched=True, remove_columns=["text"])
    collator = DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False)
    args = TrainingArguments(
        output_dir=str(output_path.parent / "_validation_tmp"),
        per_device_eval_batch_size=2,
        dataloader_drop_last=False,
        report_to=[],
    )
    trainer = Trainer(model=model, args=args, eval_dataset=tokenized, data_collator=collator)
    metrics = trainer.evaluate()
    eval_loss = float(metrics.get("eval_loss", 0.0))
    metrics["perplexity"] = float(math.exp(eval_loss)) if eval_loss < 50 else float("inf")
    metrics["sample_count"] = len(samples)
    output_path.write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")
    return metrics


def validate_sentence_transformer(model_path: Path, data_file: Path, output_path: Path, threshold=0.6):
    rows = load_sentence_pairs(data_file)
    if not rows:
        raise ValueError(f"No sentence pairs found in {data_file}")

    model = SentenceTransformer(str(model_path))
    left_texts = [row[0] for row in rows]
    right_texts = [row[1] for row in rows]
    labels = np.array([row[2] for row in rows], dtype=float)

    left_embeddings = model.encode(left_texts, convert_to_numpy=True, normalize_embeddings=True)
    right_embeddings = model.encode(right_texts, convert_to_numpy=True, normalize_embeddings=True)
    similarities = np.sum(left_embeddings * right_embeddings, axis=1)

    metrics = {
        "sample_count": int(len(rows)),
        "similarity_mean": float(np.mean(similarities)),
        "similarity_std": float(np.std(similarities)),
        "threshold_accuracy": float(np.mean(similarities >= threshold)),
    }

    if len(np.unique(labels)) > 1:
        correlation, p_value = spearmanr(labels, similarities)
        metrics["spearman_correlation"] = float(correlation) if correlation == correlation else 0.0
        metrics["spearman_p_value"] = float(p_value) if p_value == p_value else 1.0
    else:
        metrics["spearman_correlation"] = 0.0
        metrics["spearman_p_value"] = 1.0

    output_path.write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")
    return metrics


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-type", required=True, choices=("lm", "sentence_transformer"))
    parser.add_argument("--model-path", required=True)
    parser.add_argument("--data-file", required=True)
    parser.add_argument("--output", default="validation_report.json")
    parser.add_argument("--threshold", type=float, default=0.6)
    parser.add_argument("--local-files-only", action="store_true", default=True)
    args = parser.parse_args()

    model_path = Path(args.model_path)
    data_file = Path(args.data_file)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if args.model_type == "lm":
        metrics = validate_lm(model_path, data_file, output_path, local_files_only=args.local_files_only)
    else:
        metrics = validate_sentence_transformer(
            model_path,
            data_file,
            output_path,
            threshold=args.threshold,
        )

    print(json.dumps(metrics, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
