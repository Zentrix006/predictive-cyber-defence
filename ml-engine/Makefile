# ML Engine Makefile
# Usage: make <target>

.PHONY: help install test train evaluate export clean

# Default target
help:
	@echo "ML Engine - World Model Training"
	@echo ""
	@echo "Available targets:"
	@echo "  install       - Install dependencies in virtual environment"
	@echo "  test          - Run model tests (synthetic data)"
	@echo "  test-components - Test individual model components"
	@echo "  train         - Train model with config"
	@echo "  evaluate      - Evaluate trained model"
	@echo "  export        - Export model to ONNX"
	@echo "  clean         - Clean up generated files"
	@echo ""

# Install dependencies
install:
	python -m venv venv
	venv/bin/pip install --upgrade pip
	venv/bin/pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121
	venv/bin/pip install torch-scatter torch-sparse torch-cluster torch-spline-conv -f https://data.pyg.org/whl/torch-2.4.0+cu121.html
	venv/bin/pip install -r requirements.txt

# Run synthetic data tests
test:
	venv/bin/python scripts/test_synthetic.py

# Test individual components
test-components:
	venv/bin/python -c "
import sys
sys.path.insert(0, '.')
from scripts.test_synthetic import test_model_components
test_model_components()
"

# Train model
train:
	venv/bin/python scripts/train.py

# Train with custom config
train-config:
	venv/bin/python scripts/train.py --config-path=configs --config-name=model_config

# Evaluate model
evaluate:
	@read -p "Checkpoint path: " checkpoint; \
	venv/bin/python scripts/evaluate.py --checkpoint $$checkpoint

# Export to ONNX
export:
	@read -p "Checkpoint path: " checkpoint; \
	venv/bin/python scripts/export_onnx.py --checkpoint $$checkpoint

# Run with docker
docker-build:
	docker build -t cyber-defence-ml .

docker-run:
	docker run --gpus all -v $(PWD):/app cyber-defence-ml make train

# Clean up
clean:
	rm -rf __pycache__
	rm -rf *.pyc
	rm -rf .pytest_cache
	rm -rf .mypy_cache
	rm -rf logs
	rm -rf checkpoints
	rm -rf wandb
	rm -rf mlruns
	rm -rf *.onnx

# Format code
format:
	venv/bin/black scripts training models
	venv/bin/ruff check --fix scripts training models

# Type check
typecheck:
	venv/bin/mypy scripts training models

# Lint
lint:
	venv/bin/ruff check scripts training models

# Generate synthetic data for testing
generate-data:
	venv/bin/python scripts/generate_synthetic_data.py