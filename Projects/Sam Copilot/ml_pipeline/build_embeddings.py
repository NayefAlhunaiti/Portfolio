import argparse
import json
from pathlib import Path

import faiss
from sentence_transformers import SentenceTransformer


def load_docs(input_dir: Path):
    docs = []
    for p in sorted(input_dir.glob('*')):
        if p.is_file() and p.suffix.lower() in ('.txt', '.md'):
            docs.append({'id': p.name, 'text': p.read_text(encoding='utf-8')})
    return docs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input-dir', required=True)
    parser.add_argument('--model', default='./models/embedding_model')
    parser.add_argument('--index-file', default='policy_index.faiss')
    parser.add_argument('--meta-file', default='policy_meta.json')
    args = parser.parse_args()

    model_path = Path(args.model)
    if not model_path.exists():
        raise SystemExit(f'Local embedding model not found: {model_path}')

    input_dir = Path(args.input_dir)
    docs = load_docs(input_dir)
    if not docs:
        raise SystemExit(f'No .txt or .md documents found in {input_dir}')
    texts = [d['text'] for d in docs]

    model = SentenceTransformer(str(model_path))
    embeddings = model.encode(texts, show_progress_bar=True, convert_to_numpy=True)

    dim = embeddings.shape[1]
    index = faiss.IndexFlatIP(dim)
    # normalize for cosine similarity
    faiss.normalize_L2(embeddings)
    index.add(embeddings)

    index_path = Path(args.index_file)
    index_path.parent.mkdir(parents=True, exist_ok=True)
    faiss.write_index(index, str(index_path))
    meta = [{'id': d['id'], 'text': d['text'][:1000]} for d in docs]
    meta_path = Path(args.meta_file)
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(json.dumps(meta, ensure_ascii=False), encoding='utf-8')
    print('Wrote index and meta')


if __name__ == '__main__':
    main()
