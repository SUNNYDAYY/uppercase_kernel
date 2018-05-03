#!/bin/bash

mkdir -p ~/.ipython/kernels/uppercase_kernel/
START_SCRIPT_PATH=$(cd `dirname "${BASH_SOURCE[0]}"` && pwd)/kernel.py
PYTHON_PATH=$(which python)
CONTENT='{
   "argv": ["'${PYTHON_PATH}'", "'${START_SCRIPT_PATH}'", "{connection_file}"],
                "display_name": "uppercase_kernel",
                "language": "uppercase_kernel"
}'
echo $CONTENT > ~/.ipython/kernels/simple_kernel/kernel.json
