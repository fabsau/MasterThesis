#!/usr/bin/env python3
import os, json, logging, random, argparse
from datetime import datetime, timezone
from collections import defaultdict
from tqdm import tqdm

from s1_pipeline import config, utils

def main():
    utils.setup_logging(config.LOG_LEVEL)
    log = logging.getLogger("main")

    p = argparse.ArgumentParser(
      description="Split SentinelOne export into train/test JSONs"
    )
    p.add_argument("--input",       "-i", default=config.INPUT_FILE)
    p.add_argument("--out-dir",     default=config.OUT_DIR)
    p.add_argument("--train-tpl",   default=None)
    p.add_argument("--test-tpl",    default=None)
    p.add_argument("--methods",     "-m", nargs="+",
                   choices=config.METHODS, default=config.METHODS)
    p.add_argument("--test-size",   "-s", type=float,
                   default=config.TEST_SIZE)
    p.add_argument("--cutoff-date", "-c", default=config.CUTOFF_DATE)
    p.add_argument("--seed",        "-r", type=int,
                   default=config.SEED)
    p.add_argument("--max-threats", "-n", type=int,
                   default=config.MAX_THREATS)
    p.add_argument("--time-field",  default=config.TIME_FIELD)
    p.add_argument("--group-fields",nargs="+",
                   default=config.GROUP_FIELDS)
    p.add_argument("--id-field",    default=config.ID_FIELD)
    p.add_argument("--iso-format",  default=config.ISO_FORMAT)
    args = p.parse_args()

    log.info("Loading %s …", args.input)
    threats, exported_at = utils.load_threats(args.input)
    if args.max_threats:
        threats = threats[:args.max_threats]
    log.info("Total threats loaded: %d", len(threats))

    for method in args.methods:
        log.info("== Splitting with method: %s ==", method)

        if method == "random":
            tr, te = utils.random_split(threats, args.test_size, args.seed)

        elif method == "group":
            tr, te = utils.group_split(
                threats, args.test_size,
                args.seed, args.group_fields
            )

        elif method == "time":
            tr, te = utils.time_split(
                args.test_size, args.cutoff_date,
                args.time_field, args.iso_format,
                threats
            )

        elif method == "temporal-group":
            tr, te = utils.temporal_group_split(
                args.test_size, args.cutoff_date,
                args.time_field, args.iso_format,
                args.group_fields, threats
            )
        else:
            raise ValueError(f"Unknown method: {method}")

        # Final train = everything except test IDs (preserve original order)
        te_ids = set(
            utils.get_by_path(t, args.id_field) for t in te
            if utils.get_by_path(t, args.id_field) is not None
        )
        train_final = [
            t for t in threats
            if utils.get_by_path(t, args.id_field) not in te_ids
        ]

        # Build output paths
        if args.train_tpl and args.test_tpl:
            train_path = args.train_tpl.format(out_dir=args.out_dir, method=method)
            test_path  = args.test_tpl.format(out_dir=args.out_dir, method=method)
        else:
            train_path = os.path.join(args.out_dir, method, "train.json")
            test_path  = os.path.join(args.out_dir, method, "test.json")

        log.info("Method %s → train: %d, test: %d",
                 method, len(train_final), len(te))

        utils.write_dataset(train_final, exported_at, train_path)
        utils.write_dataset(te,          exported_at, test_path)

    log.info("All splits complete.")

if __name__ == "__main__":
    main()
    pass