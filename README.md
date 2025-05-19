# SentinelOne FP-Detection Pipeline

## Setup

1. Create & activate a virtual environment  
   ```bash
   cd c:/Users/Fabio/Documents/VScode/MasterThesis
   python -m venv .venv
   .venv/Scripts/activate   # Windows
   source .venv/bin/activate  # Linux/Mac

2. Install dependencies
   pip install -r requirements.txt

3. Ensure Python sees your s1_pipeline package:
# from project root:
set PYTHONPATH=./src        # Windows
export PYTHONPATH=./src     # Linux/Mac

Running the pipeline
From the project root, launch all steps in one go:
python -m scripts.pipeline --steps fetch split train infer

Or run individual steps:
# fetch data
python scripts/fetch_data.py --since-days 2 --output ./data/raw.json

# split
python scripts/split_data.py --input ./data/raw.json --out-dir ./data/splits

# train
python scripts/train_model.py --train-json ./data/splits/random/train.json \
                              --test-json  ./data/splits/random/test.json

# infer
python scripts/run_inference.py --input-json ./data/splits/random/test.json \
                                --model       ./models/s1_fp_detector.cbm \
                                --output      ./results/infer.json

That should eliminate the path warnings, install all required packages, and let you spin up the full pipeline easily.