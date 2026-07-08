import argparse
import json
from pathlib import Path

import faiss
from sentence_transformers import SentenceTransformer


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--index-file', required=True)
    parser.add_argument('--meta-file', required=True)
    parser.add_argument('--model', default='./models/embedding_model')
    parser.add_argument('--query', required=True)
    parser.add_argument('--topk', type=int, default=3)
    args = parser.parse_args()

    model_path = Path(args.model)
    if not model_path.exists():
        raise SystemExit(f'Local embedding model not found: {model_path}')

    model = SentenceTransformer(str(model_path))
    q_emb = model.encode([args.query], convert_to_numpy=True)
    faiss.normalize_L2(q_emb)

    index = faiss.read_index(args.index_file)
    D, I = index.search(q_emb, args.topk)

    meta = json.loads(Path(args.meta_file).read_text(encoding='utf-8'))
    results = []
    for dist, idx in zip(D[0], I[0]):
        if idx < 0:
            continue
        entry = meta[idx]
        results.append({'score': float(dist), 'id': entry['id'], 'text': entry['text']})

    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
