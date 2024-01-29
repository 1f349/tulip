#!/bin/bash
cd "$(dirname -- "$(readlink -f -- "$0";)";)"

python3 -m http.server 2020
