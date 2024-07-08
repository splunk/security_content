# Extract total_fail value and debug print it
total_fail=$(yq e '.summary.total_fail' test_results/summary.yml)
echo "Extracted total_fail: [$total_fail]"

# Check if total_fail is a valid integer and greater than one
if [[ "$total_fail" =~ ^[0-9]+$ ]] && [ "$total_fail" -gt 1 ]; then
  echo "CI Failure: There are failed tests."
  echo -e "Name | Status | Test Type"
  echo -e "---- | ------ | ---------"
  
  # Loop through each item in tested_detections and print required fields with color only for unit testing
  yq e '.tested_detections[] | .name as $name | .tests[] | select(.test_type == "unit") | "\($name) | \(.success) | \(.test_type)"' test_results/summary.yml | while IFS='|' read -r name status test_type; do
    name=$(echo $name | xargs)  # Trim whitespace
    status=$(echo $status | xargs)  # Trim whitespace
    test_type=$(echo $test_type | xargs)  # Trim whitespace
    
    if [ "$status" == "true" ]; then
      echo -e "${name} | \033[32mPASS\033[0m | ${test_type}"
    else
      echo -e "${name} | \033[31mFAIL\033[0m | ${test_type}"
    fi
  done
  
  exit 1  # Fail the CI job
else
  echo "CI Success: No failed tests."
fi