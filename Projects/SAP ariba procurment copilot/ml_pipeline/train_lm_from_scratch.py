import argparse
import json
import math
import random
from pathlib import Path

from datasets import Dataset
from tokenizers import ByteLevelBPETokenizer
from transformers import (
    DataCollatorForLanguageModeling,
    GPT2Config,
    GPT2LMHeadModel,
    GPT2TokenizerFast,
    Trainer,
    TrainingArguments,
)


def sample_text_from_file(path: Path):
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


def collect_samples(source: Path):
    if source.is_dir():
        samples = []
        for file_path in sorted(source.rglob("*")):
            if file_path.is_file() and file_path.suffix.lower() in {".txt", ".md", ".tsv"}:
                samples.extend(sample_text_from_file(file_path))
        return samples
    return sample_text_from_file(source)


def split_samples(samples, validation_split, seed):
    if not samples:
        return [], []
    if validation_split <= 0 or len(samples) < 2:
        return samples, []

    shuffled = samples[:]
    random.Random(seed).shuffle(shuffled)
    split_index = max(1, int(len(shuffled) * (1 - validation_split)))
    split_index = min(split_index, len(shuffled) - 1)
    return shuffled[:split_index], shuffled[split_index:]


def train_tokenizer(samples, output_dir, vocab_size, min_frequency):
    output_dir.mkdir(parents=True, exist_ok=True)
    tokenizer = ByteLevelBPETokenizer()
    tokenizer.train_from_iterator(
        samples,
        vocab_size=vocab_size,
        min_frequency=min_frequency,
        special_tokens=["<|endoftext|>"],
    )
    tokenizer.save_model(str(output_dir))

    fast_tokenizer = GPT2TokenizerFast.from_pretrained(str(output_dir))
    fast_tokenizer.eos_token = "<|endoftext|>"
    fast_tokenizer.pad_token = fast_tokenizer.eos_token
    fast_tokenizer.bos_token = fast_tokenizer.eos_token
    fast_tokenizer.save_pretrained(str(output_dir))
    return fast_tokenizer


def tokenize_dataset(dataset, tokenizer, max_length):
    def tokenize(batch):
        return tokenizer(batch["text"], truncation=True, max_length=max_length)

    return dataset.map(tokenize, batched=True, remove_columns=["text"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--output-dir", default="./lm_scratch")
    parser.add_argument("--epochs", type=int, default=1)
    parser.add_argument("--validation-split", type=float, default=0.2)
    parser.add_argument("--vocab-size", type=int, default=8000)
    parser.add_argument("--min-frequency", type=int, default=2)
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument("--hidden-size", type=int, default=256)
    parser.add_argument("--layers", type=int, default=6)
    parser.add_argument("--heads", type=int, default=8)
    parser.add_argument("--per-device-train-batch-size", type=int, default=2)
    parser.add_argument("--per-device-eval-batch-size", type=int, default=2)
    parser.add_argument("--learning-rate", type=float, default=5e-4)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    corpus_path = Path(args.corpus)
    if not corpus_path.exists():
        raise SystemExit(f"Corpus not found: {corpus_path}")

    samples = collect_samples(corpus_path)
    if not samples:
        raise SystemExit("Corpus is empty")

    train_samples, eval_samples = split_samples(samples, args.validation_split, args.seed)
    if not train_samples:
        raise SystemExit("Training split is empty")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    tokenizer = train_tokenizer(samples, output_dir, args.vocab_size, args.min_frequency)

    train_dataset = Dataset.from_dict({"text": train_samples})
    eval_dataset = Dataset.from_dict({"text": eval_samples}) if eval_samples else None
    train_tokenized = tokenize_dataset(train_dataset, tokenizer, args.max_length)
    eval_tokenized = tokenize_dataset(eval_dataset, tokenizer, args.max_length) if eval_dataset is not None else None

    config = GPT2Config(
        vocab_size=len(tokenizer),
        n_positions=args.max_length,
        n_ctx=args.max_length,
        n_embd=args.hidden_size,
        n_layer=args.layers,
        n_head=args.heads,
        bos_token_id=tokenizer.eos_token_id,
        eos_token_id=tokenizer.eos_token_id,
    )
    model = GPT2LMHeadModel(config)
    collator = DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False)

    training_args = TrainingArguments(
        output_dir=args.output_dir,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.per_device_train_batch_size,
        per_device_eval_batch_size=args.per_device_eval_batch_size,
        learning_rate=args.learning_rate,
        eval_strategy="epoch" if eval_tokenized is not None else "no",
        save_strategy="epoch",
        save_total_limit=2,
        logging_steps=10,
        report_to=[],
        seed=args.seed,
        load_best_model_at_end=bool(eval_tokenized is not None),
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_tokenized,
        eval_dataset=eval_tokenized,
        data_collator=collator,
    )
    trainer.train()

    metrics = {"train_count": len(train_samples), "eval_count": len(eval_samples)}
    if eval_tokenized is not None:
        eval_metrics = trainer.evaluate()
        eval_loss = float(eval_metrics.get("eval_loss", 0.0))
        eval_metrics["perplexity"] = float(math.exp(eval_loss)) if eval_loss < 50 else float("inf")
        metrics.update(eval_metrics)

    trainer.save_model(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)
    (output_dir / "training_metrics.json").write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")
    print("Saved scratch LM to", args.output_dir)
    print(json.dumps(metrics, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
