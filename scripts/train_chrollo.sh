#!/bin/bash
set -e

echo "🎯 Training Chrollo Classifier"
echo "=============================="

source venv/bin/activate

if [ ! -f "data/sample_training.jsonl" ]; then
    echo "❌ Training data not found: data/sample_training.jsonl"
    exit 1
fi

python -m protocols.p3chrollo.train \
    --data data/sample_training.jsonl \
    --out models/chrollo_rf.joblib \
    --trees 100 \
    --depth 15

echo "✅ Training complete! Model saved to models/chrollo_rf.joblib"
