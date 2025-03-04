#!/bin/bash

# Change to the GitHubScan directory
cd /Users/georgeszulc/GitHubScan

# Remove any existing report
rm -f report.pdf

# Run the scan on DVWA repository
echo "Running scan on DVWA repository..."
python3 githubscan.py https://github.com/digininja/DVWA.git --output-format pdf > scan_output.log 2>&1

# Check if the report was generated
if [ -f "report.pdf" ]; then
    echo "PDF report generated successfully!"
    ls -la report.pdf
    
    # Check file size to ensure it's not empty
    file_size=$(stat -f%z report.pdf)
    echo "Report size: $file_size bytes"
    
    if [ $file_size -gt 1000 ]; then
        echo "Report appears to be valid (size > 1KB)"
    else
        echo "Warning: Report file is very small, may be incomplete"
    fi
else
    echo "Error: PDF report was not generated!"
    cat scan_output.log
    exit 1
fi

echo "Scan completed successfully!" 