#!/bin/bash
set -e

echo "🚀 RAGIN Setup Script"
echo "===================="

# Check Python version
python_version=$(python3 --version 2>&1 | grep -oP '\d+\.\d+')
if (( $(echo "$python_version < 3.9" | bc -l) )); then
    echo "❌ Python 3.9+ required. Found: $python_version"
    exit 1
fi
echo "✓ Python $python_version"

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Start infrastructure
echo "Starting Redis and Qdrant..."
docker-compose up -d redis qdrant

# Wait for services
echo "Waiting for services..."
sleep 5

# Check Ollama
if command -v ollama &> /dev/null; then
    echo "✓ Ollama detected"
    echo "Pulling models..."
    ollama pull qwen2:7b
    ollama pull nomic-embed-text
else
    echo "⚠ Ollama not found. Install from https://ollama.ai or use another provider."
fi

echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "1. Train Chrollo: python -m protocols.p3chrollo.train --data data/sample_training.jsonl"
echo "2. Run orchestrator: python -m pipeline.orchestrator"
echo "3. Run API server: python -m pipeline.apiserver"
