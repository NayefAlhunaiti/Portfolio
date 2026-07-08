import argparse
import json
import random
from pathlib import Path

import numpy as np
from scipy.stats import spearmanr
from sentence_transformers import InputExample, SentenceTransformer, losses
from torch.utils.data import DataLoader


def read_pairs(path: Path):
    examples = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) >= 2:
            label = float(parts[2]) if len(parts) >= 3 else 1.0
            examples.append(InputExample(texts=[parts[0], parts[1]], label=label))
    return examples


def split_examples(examples, validation_split, seed):
    if not examples:
        return [], []
    if validation_split <= 0 or len(examples) < 2:
        return examples, []

    shuffled = examples[:]
    random.Random(seed).shuffle(shuffled)
    split_index = max(1, int(len(shuffled) * (1 - validation_split)))
    split_index = min(split_index, len(shuffled) - 1)
    return shuffled[:split_index], shuffled[split_index:]


def evaluate_examples(model, examples):
    if not examples:
        return {}

    left_texts = [example.texts[0] for example in examples]
    right_texts = [example.texts[1] for example in examples]
    labels = np.array([example.label for example in examples], dtype=float)

    left_embeddings = model.encode(left_texts, convert_to_numpy=True, normalize_embeddings=True)
    right_embeddings = model.encode(right_texts, convert_to_numpy=True, normalize_embeddings=True)
    similarities = np.sum(left_embeddings * right_embeddings, axis=1)

    metrics = {
        "validation_count": int(len(examples)),
        "similarity_mean": float(np.mean(similarities)),
        "similarity_std": float(np.std(similarities)),
    }

    if len(np.unique(labels)) > 1:
        correlation, p_value = spearmanr(labels, similarities)
        metrics["spearman_correlation"] = float(correlation) if correlation == correlation else 0.0
        metrics["spearman_p_value"] = float(p_value) if p_value == p_value else 1.0
    else:
        metrics["spearman_correlation"] = 0.0
        metrics["spearman_p_value"] = 1.0

    return metrics


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--train-file", required=True)
    parser.add_argument("--model", default="./models/embedding_model")
    parser.add_argument("--output-dir", default="./st_model")
    parser.add_argument("--epochs", type=int, default=1)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--validation-split", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    model_path = Path(args.model)
    if not model_path.exists():
        raise SystemExit(f"Local sentence-transformer model not found: {model_path}")

    train_examples, validation_examples = split_examples(read_pairs(Path(args.train_file)), args.validation_split, args.seed)
    if not train_examples:
        raise SystemExit("Training data is empty")

    model = SentenceTransformer(str(model_path))
    train_loader = DataLoader(train_examples, shuffle=True, batch_size=args.batch_size)
    train_loss = losses.MultipleNegativesRankingLoss(model)

    model.fit(train_objectives=[(train_loader, train_loss)], epochs=args.epochs, output_path=args.output_dir)

    metrics = {"train_count": len(train_examples)}
    metrics.update(evaluate_examples(model, validation_examples))
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "training_metrics.json").write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")
    print("Saved fine-tuned model to", args.output_dir)
    if validation_examples:
        print(json.dumps(metrics, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
