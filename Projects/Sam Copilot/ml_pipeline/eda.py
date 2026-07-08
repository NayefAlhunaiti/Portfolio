import argparse
import json
from collections import Counter
from pathlib import Path
import re


def analyze_dir(path: Path, recursive=False):
    docs = []
    iterator = path.rglob("*") if recursive else path.glob("*")
    for p in sorted(iterator):
        if p.is_file() and p.suffix.lower() in ('.txt', '.md'):
            text = p.read_text(encoding='utf-8')
            words = [word.lower() for word in re.findall(r"[A-Za-z0-9_]{2,}", text)]
            docs.append({
                'name': p.name,
                'path': str(p),
                'chars': len(text),
                'words': len(words),
                'lines': len(text.splitlines()),
                'sample': text[:200],
                'top_terms': Counter(words).most_common(10),
            })
    return docs


def aggregate(docs):
    total_docs = len(docs)
    total_chars = sum(d['chars'] for d in docs)
    total_words = sum(d['words'] for d in docs)
    total_lines = sum(d['lines'] for d in docs)
    avg_words = total_words / total_docs if total_docs else 0
    avg_chars = total_chars / total_docs if total_docs else 0
    vocab = Counter()
    for doc in docs:
        vocab.update(term for term, _ in doc['top_terms'])
    return {
        'total_docs': total_docs,
        'total_chars': total_chars,
        'total_words': total_words,
        'total_lines': total_lines,
        'avg_words': avg_words,
        'avg_chars': avg_chars,
        'vocab_size': len(vocab),
        'top_terms': vocab.most_common(25),
        'docs': docs,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input-dir', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--recursive', action='store_true')
    args = parser.parse_args()

    p = Path(args.input_dir)
    if not p.exists():
        raise SystemExit('input directory not found')

    docs = analyze_dir(p, recursive=args.recursive)
    report = aggregate(docs)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    print('Wrote', args.output)


if __name__ == '__main__':
    main()
