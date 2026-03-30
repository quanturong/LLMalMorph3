#!/bin/bash
# Full Pipeline Script: Extract datasets → Stage 1 → Stage 2 → Compilation
# Hỗ trợ C và C++ datasets

set -e  # Exit on error

echo "========================================"
echo "LLMalMorph Full Pipeline"
echo "Stage 1 + Stage 2 + Compilation"
echo "========================================"
echo ""

# Check if config exists
if [ ! -f "full_pipeline_config.json" ]; then
    echo "Error: full_pipeline_config.json not found"
    exit 1
fi

# Check if MISTRAL_API_KEY is set
if [ -z "$MISTRAL_API_KEY" ]; then
    echo "Warning: MISTRAL_API_KEY environment variable not set"
    echo "Please set it with: export MISTRAL_API_KEY='your-api-key'"
    echo ""
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Parse command line arguments
LLM_MODEL=${1:-codestral}
STRATEGY=${2:-strat_1}
NUM_FUNCTIONS=${3:-5}
MAX_FILES=${4:-}

echo "Configuration:"
echo "  LLM Model: $LLM_MODEL"
echo "  Strategy: $STRATEGY"
echo "  Number of Functions: $NUM_FUNCTIONS"
if [ -n "$MAX_FILES" ]; then
    echo "  Max Files (testing): $MAX_FILES"
fi
echo ""

# Step 1: Extract datasets
echo "========================================"
echo "Step 1: Extracting datasets..."
echo "========================================"
python extract_datasets.py
if [ $? -ne 0 ]; then
    echo "Warning: Dataset extraction had issues"
    echo "You may need to manually extract C.rar and CPP.rar"
    echo ""
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Step 2: Process C dataset
echo ""
echo "========================================"
echo "Step 2: Processing C Dataset..."
echo "========================================"
if [ -d "C_dataset" ]; then
    MAX_FILES_ARG=""
    if [ -n "$MAX_FILES" ]; then
        MAX_FILES_ARG="--max_files $MAX_FILES"
    fi
    
    python full_pipeline.py \
        --dataset_dir C_dataset \
        --file_pattern "*.c" \
        --llm "$LLM_MODEL" \
        --strategy "$STRATEGY" \
        --num_functions "$NUM_FUNCTIONS" \
        --output_dir "./full_pipeline_output/C_dataset" \
        --auto_fix \
        --max_fix_attempts 3 \
        --use_cache \
        $MAX_FILES_ARG
    
    C_RESULT=$?
    echo ""
    echo "C Dataset processing completed with exit code: $C_RESULT"
else
    echo "Warning: C_dataset directory not found, skipping C dataset"
    C_RESULT=1
fi

# Step 3: Process C++ dataset
echo ""
echo "========================================"
echo "Step 3: Processing C++ Dataset..."
echo "========================================"
if [ -d "CPP_dataset" ]; then
    MAX_FILES_ARG=""
    if [ -n "$MAX_FILES" ]; then
        MAX_FILES_ARG="--max_files $MAX_FILES"
    fi
    
    python full_pipeline.py \
        --dataset_dir CPP_dataset \
        --file_pattern "*.cpp" \
        --llm "$LLM_MODEL" \
        --strategy "$STRATEGY" \
        --num_functions "$NUM_FUNCTIONS" \
        --output_dir "./full_pipeline_output/CPP_dataset" \
        --auto_fix \
        --max_fix_attempts 3 \
        --use_cache \
        $MAX_FILES_ARG
    
    CPP_RESULT=$?
    echo ""
    echo "C++ Dataset processing completed with exit code: $CPP_RESULT"
else
    echo "Warning: CPP_dataset directory not found, skipping C++ dataset"
    CPP_RESULT=1
fi

# Summary
echo ""
echo "========================================"
echo "Pipeline Execution Summary"
echo "========================================"
echo "C Dataset: $([ $C_RESULT -eq 0 ] && echo '✓ Success' || echo '✗ Failed or Skipped')"
echo "C++ Dataset: $([ $CPP_RESULT -eq 0 ] && echo '✓ Success' || echo '✗ Failed or Skipped')"
echo ""
echo "Results saved to: ./full_pipeline_output/"
echo "Logs saved to: full_pipeline.log"
echo "========================================"

# Exit with success if at least one dataset succeeded
if [ $C_RESULT -eq 0 ] || [ $CPP_RESULT -eq 0 ]; then
    exit 0
else
    exit 1
fi







