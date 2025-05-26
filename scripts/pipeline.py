#!/usr/bin/env python3
# scripts/pipeline.py
import sys, argparse, logging
from s1_pipeline import config, utils
import scripts.fetch_data   as fetch_data
import scripts.split_data   as split_data
import scripts.train_model  as train_model
import scripts.run_inference as run_inference

def main():
    utils.setup_logging(config.LOG_LEVEL)
    log = logging.getLogger("main")

    p = argparse.ArgumentParser()
    p.add_argument("--steps", nargs="+",
                   choices=["fetch","split","train","infer"],
                   default=["fetch","split","train","infer"])
    p.add_argument("--use-gpu", action="store_true")
    args = p.parse_args()

    if "fetch" in args.steps:
        log.info("→ STEP: fetch")
        sys.argv = [""]  # plus fetch-specific args
        fetch_data.main()

    if "split" in args.steps:
        log.info("→ STEP: split")
        sys.argv = [""]  # plus split-specific args
        split_data.main()

    if "train" in args.steps:
        log.info("→ STEP: train")
        sys.argv = [""]  # plus train-specific args
        train_model.main()

    if "infer" in args.steps:
        log.info("→ STEP: infer")
        sys.argv = [""]  # plus inference-specific args
        run_inference.main()

    log.info("Pipeline complete.")

if __name__ == "__main__":
    main()
    pass