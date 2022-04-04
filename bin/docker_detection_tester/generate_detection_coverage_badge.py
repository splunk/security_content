import argparse
import json
import sys

RAW_BADGE_SVG = '''<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="20">
<linearGradient id="a" x2="0" y2="100%">
  <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
  <stop offset="2" stop-opacity=".1"/>
</linearGradient>

<rect rx="3" width="60" height="20" fill="#555"/> <!-- Comment -->
<rect rx="3" x="60" width="40" height="20" fill="#4c1"/>

<path fill="#4c1" d="M58 0h4v20h-4z"/>

<rect rx="3" width="100" height="20" fill="url(#a)"/>
<g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="30" y="14">{}</text>
    <text x="80" y="14">{}</text>
</g>
</svg>'''


parser = argparse.ArgumentParser(description='Use a summary.json file to generate a test coverage badge')
parser.add_argument('-i', "--input_summary_file", type=argparse.FileType('r'), required = True,
                    help='Summary file to use to generate the pass percentage badge')
parser.add_argument('-o', "--output_badge_file", type=argparse.FileType('w'), required = True,
                    help='Name of the badge to output')
parser.add_argument('-s', "--badge_string", type=str, required = True,
                    help='Name of the badge to output')



try:
   results = parser.parse_args()
except Exception as e:
   print(f"Error parsing arguments: {str(e)}")
   exit(1)

try:
   summary_info = json.loads(results.input_summary_file.read())
except Exception as e:
   print(f"Error loading {results.input_summary_file.name} JSON file: {str(e)}")
   sys.exit(1)

if 'summary' not in summary_info:
   print("Missing 'summary' key in {results.input_summary_file.name}")
   sys.exit(1)
elif 'PASS_RATE' not in summary_info['summary'] or 'TESTS_PASSED' not in summary_info['summary']:
   print(f"Missing PASS_RATE in 'summary' section of {results.input_summary_file.name}")
   sys.exit(1)
pass_percent = 100 * summary_info['summary']['PASS_RATE']


try:
   results.output_badge_file.write(RAW_BADGE_SVG.format(results.badge_string, "{:2.1f}%".format(pass_percent)))
except Exception as e:
   print(f"Error generating badge: {str(e)}")
   sys.exit(1)


print(f"Badge {results.output_badge_file.name} successfully generated!")
sys.exit(0)

