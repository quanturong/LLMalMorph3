#!/bin/bash

# Improved pipeline script với tất cả cải tiến
# Tương tự run_generate_llm_code.sh nhưng với automation features

# Load config
if [ -f "run_scripts/generate_llm_code_config.cfg" ]; then
    source run_scripts/generate_llm_code_config.cfg
else
    echo "Error: run_scripts/generate_llm_code_config.cfg not found"
    exit 1
fi

# Set default values
AUTO_FIX=${AUTO_FIX:-false}
RUN_TESTS=${RUN_TESTS:-false}
PARALLEL=${PARALLEL:-false}
USE_CACHE=${USE_CACHE:-false}
MAX_FIX_ATTEMPTS=${MAX_FIX_ATTEMPTS:-3}

# Build command
BASE_CMD=(
    "python"
    "run_pipeline_improved.py"
    "--source_file=$source_file"
    "--num_func=$num_funcs"
    "--llm=$llm"
    "--output_dir=$output_dir"
    "--trials=$trials"
)

# Add improvement flags
if [ "$AUTO_FIX" = "true" ]; then
    BASE_CMD+=("--auto_fix")
fi

if [ "$RUN_TESTS" = "true" ]; then
    BASE_CMD+=("--run_tests")
fi

if [ "$PARALLEL" = "true" ]; then
    BASE_CMD+=("--parallel")
fi

if [ "$USE_CACHE" = "true" ]; then
    BASE_CMD+=("--use_cache")
fi

BASE_CMD+=("--max_fix_attempts=$MAX_FIX_ATTEMPTS")

# Run strategies
for i in {1..6}; do
    STRATEGY="strat_$i"
    LOG_FILE="$log_dir/ST_${i}_improved.log"
    
    echo "Running strategy $STRATEGY with improvements..."
    "${BASE_CMD[@]}" "--strategy=$STRATEGY" > "$LOG_FILE" 2>&1
    
    if [ $? -eq 0 ]; then
        echo "✓ Strategy $STRATEGY completed"
    else
        echo "✗ Strategy $STRATEGY failed (check $LOG_FILE)"
    fi
done

echo "All strategies executed with improvements."

