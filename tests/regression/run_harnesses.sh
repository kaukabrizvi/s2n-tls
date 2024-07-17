#!/bin/bash

# Function to run a harness
run_harness() {
    local harness=$1
    local output_file="cachegrind.out.${harness}"
    local annotated_output="perf_outputs/${harness}_annotated.txt"

    echo "Running harness: $harness"
    cargo build --release
    valgrind --tool=cachegrind --cachegrind-out-file=$output_file target/release/$harness
    cg_annotate $output_file > $annotated_output

    echo "Annotated output saved to: $annotated_output"
}

# Create the perf_outputs directory if it doesn't exist
mkdir -p perf_outputs

# Check if any harness is specified
if [ $# -eq 0 ]; then
    echo "No harness specified. Running all harnesses..."
    harnesses=(config_create config_configure create_cert data_transfer rsa_handshake ecdsa_handshake resumption cleanup_connection)
else
    # Use the specified harnesses
    harnesses=("$@")
fi

# Run each specified harness
for harness in "${harnesses[@]}"; do
    run_harness $harness
done

