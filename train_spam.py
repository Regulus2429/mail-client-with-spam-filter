"""Train from local ham/ and spam/ directories. Never downloads datasets."""
import argparse
import hashlib
import json
from pathlib import Path

from mailproject.spam import extract_text


def load_dataset(root):
    records = {}
    duplicates = 0
    for label in ('ham', 'spam'):
        folder = Path(root) / label
        if not folder.is_dir():
            raise ValueError(f'缺少数据目录: {folder}')
        for path in sorted(folder.rglob('*')):
            if not path.is_file():
                continue
            try:
                text = extract_text(path.read_bytes())
            except Exception as exc:
                raise ValueError(f'无法解析 {path}: {exc}') from exc
            if not text:
                continue
            digest = hashlib.sha256(text.encode('utf-8')).hexdigest()
            if digest in records:
                if records[digest][1] != label:
                    raise ValueError(f'同一文本具有冲突标签: {path}')
                duplicates += 1
            else:
                records[digest] = (text, label)
    rows = list(records.values())
    if any(sum(label == c for _, label in rows) < 10 for c in ('ham', 'spam')):
        raise ValueError('去重后每类至少需要 10 封非空邮件')
    return [x[0] for x in rows], [x[1] for x in rows], duplicates


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', required=True, help='包含 ham/ 和 spam/ 的本地目录')
    parser.add_argument('--out', default='models/spam')
    parser.add_argument('--seed', type=int, default=42)
    args = parser.parse_args()
    import joblib
    import sklearn
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.naive_bayes import MultinomialNB
    from sklearn.pipeline import Pipeline
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, ConfusionMatrixDisplay

    texts, labels, duplicates = load_dataset(args.data)
    train_x, remaining_x, train_y, remaining_y = train_test_split(
        texts, labels, test_size=.3, stratify=labels, random_state=args.seed)
    valid_x, test_x, valid_y, test_y = train_test_split(
        remaining_x, remaining_y, test_size=.5, stratify=remaining_y, random_state=args.seed)
    # Select alpha on validation data only; the test set is evaluated once.
    candidates = []
    for alpha in (.1, .5, 1.0):
        model = Pipeline([
            ('tfidf', TfidfVectorizer(ngram_range=(1, 2), max_features=100000)),
            ('classifier', MultinomialNB(alpha=alpha)),
        ])
        model.fit(train_x, train_y)
        report = classification_report(valid_y, model.predict(valid_x), output_dict=True, zero_division=0)
        candidates.append((report['spam']['f1-score'], alpha, model))
    score, alpha, model = max(candidates, key=lambda row: row[0])
    predicted = model.predict(test_x)
    matrix = confusion_matrix(test_y, predicted, labels=['ham', 'spam'])
    metrics = {
        'seed': args.seed, 'sklearn_version': sklearn.__version__, 'duplicates_removed': duplicates,
        'split_sizes': {'train': len(train_y), 'validation': len(valid_y), 'test': len(test_y)},
        'class_counts': {c: labels.count(c) for c in ('ham', 'spam')},
        'alpha': alpha, 'validation_spam_f1': score,
        'accuracy': accuracy_score(test_y, predicted),
        'classification_report': classification_report(test_y, predicted, output_dict=True, zero_division=0),
        'confusion_matrix_labels': ['ham', 'spam'],
        'confusion_matrix_rows_true_columns_predicted': matrix.tolist(),
        'ham_false_positive_rate': float(matrix[0, 1] / matrix[0].sum()),
    }
    output = Path(args.out)
    output.mkdir(parents=True, exist_ok=True)
    joblib.dump({'format_version': 1, 'pipeline': model, 'metadata': metrics}, output / 'model.joblib')
    (output / 'metrics.json').write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding='utf-8')
    ConfusionMatrixDisplay(matrix, display_labels=['ham', 'spam']).plot()
    plt.tight_layout()
    plt.savefig(output / 'confusion_matrix.png', dpi=160)
    plt.close()
    print(json.dumps(metrics, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
