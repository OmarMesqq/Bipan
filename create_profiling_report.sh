#!/bin/bash
set -euo pipefail

echo "Creating Gecko report..."
python3 $NDK_HOME/simpleperf/gecko_profile_generator.py -i perf.data --symfs /Users/omar/Downloads/repos/Bipan/src/obj/local/arm64-v8a/ > firefox_report.json

echo "Creating HTML report..."
python3 $NDK_HOME/simpleperf/report_html.py  -i perf.data -o simple_report.html

echo "Done"
