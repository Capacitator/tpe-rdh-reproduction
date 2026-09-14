# Output Artifact Manifest

The `output/` directory contains generated validation and demonstration artifacts. These files are included so the intermediate and final results can be inspected without rerunning every experiment.

Canonical validation outputs:

- `final_demo/`: stage images and report from `experiments/final_demo.py`.
- `section6/`: project validation metrics from `experiments/run_section6_experiments.py`; these are separate from the paper authors' official tables.
- `uct_colour_all_blocks/`: UCT validation results for block sizes 8, 16, 32, and 64.
- `uct_colour_b16/`: UCT stage outputs for block size 16.
- `final_thumbnail_comparison.png`, `final_thumbnail_metrics.csv`, `thumbnail_metrics.csv`, and `thumbnail_validation.png`: thumbnail-preservation validation artifacts.

Demo/debug artifacts:

- `demo_*.png`: compact visual demonstrations for individual components.
- `demo_*.npy`: small NumPy arrays saved beside the demo images so intermediate matrices and images can be inspected exactly. These are not required to run the code, but they are useful as trace artifacts for the demonstration.

Submission-ready synthetic results are in `results/`, not `output/`.
