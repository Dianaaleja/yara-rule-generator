#!/usr/bin/env bash
# Author: Pierre Gronau <Pierre.Gronau@ndaal.eu>
# Copyright (c) 2024
# Copyright (c) Pierre Gronau <Pierre.Gronau@ndaal.eu>
# Copyright (c) ndaal, Germany
# License: All content is licensed under the terms of the <MIT License>
# Developed on: Debian 12.x x86 architecture; macOS Sonoma x86 architecture
# Tested on: Debian 12.x x86 architecture; macOS Sonoma x86 architecture

# This bash script is a comprehensive tool for performing security and 
# code analysis using multiple tools. Here's a brief description of what it does:
# Sets up error handling and cleanup mechanisms to ensure robust execution.
# Defines three main functions:
# a. run_gitleaks: Runs the Gitleaks tool to detect potential secrets and 
#    sensitive information in the input file.
# b. run_yara: Executes YARA rules on the input file to identify patterns or 
#    signatures that might indicate malicious content or security issues.
# c. run_ripgrep: Uses ripgrep to search for specific patterns defined in a rule 
#    file within the input file.
# Each function:
# - Checks if the required tool (Gitleaks, YARA, or ripgrep) is installed.
# - Verifies the existence of input and rule files.
# - Executes the respective tool with specific parameters.
# - Saves the output to a log file and displays it.
# The script includes error handling and informative messages throughout 
# its execution.
# It's designed to be flexible, allowing different input files and rule sets 
# to be used for each tool.
# This script appears to be part of a larger security analysis toolkit, 
# providing a streamlined way to run multiple security checks on a given input file 
# using different specialized tools.

# Set $IFS to only newline and tab.
IFS=$'\n\t'

trap cleanup SIGINT SIGTERM ERR EXIT

cleanup() {
    trap - SIGINT SIGTERM ERR EXIT
    printf "%b\n" "\nCleanup is running"
    # Additional cleanup tasks can be added here if needed
}

# Function to run Gitleaks
run_gitleaks() {
    local input_file="$1"
    local gitleaks_file="$2"
    local log_file="${input_file_base}_gitleaks_findings_${DIRDATE}.log"

    check_file_exists "${gitleaks_file}" "true"
    check_file_exists "${input_file}" "true"

    if command -v gitleaks &> /dev/null; then
        info_msg "Using Gitleaks rule fle %s\n" "${gitleaks_file}"
        info_msg "Running Gitleaks on %s\n" "${input_file}"
        # This will make tee ignore any interrupt signals and continue running until it finishes.
        gitleaks detect -c "${gitleaks_file}" --redact --no-git --verbose --source "${input_file}" | tee -i "${log_file}" || true
        debug_msg "dddd"
        cat_msg "${log_file}"
    else
        error_msg "Gitleaks not found. Please install it to run Gitleaks rules.\n" >&2
        exit 1
    fi
}

# Function to run YARA
run_yara() {
    local input_file="$1"
    local yara_file="$2"
    local log_file="${input_file_base}_YARA_findings_${DIRDATE}.log"

    check_file_exists "${yara_file}" "true"
    check_file_exists "${input_file}" "true"

    if command -v yara &> /dev/null; then
        info_msg "Using YARA rule fle %s\n" "${yara_file}"
        info_msg "Running YARA on %s\n" "${input_file}"
        # This will make tee ignore any interrupt signals and continue running until it finishes.
        yara -m -s -g -e -S "${yara_file}" "${input_file}" | tee -i "${log_file}" || true
        #cat "${log_file}"
    else
        error_msg "YARA not found. Please install it to run YARA rules.\n" >&2
        exit 1
    fi
}


# Function to run ripgrep
run_ripgrep() {
    local input_file="$1"
    local ripgrep_file="$2"
    local log_file="${input_file_base}_ripgrep_findings_${DIRDATE}.log"

    check_file_exists "${input_file}" "true"
    check_file_exists "${ripgrep_file}" "true"

    if command -v rg &> /dev/null; then
        info_msg "Using ripgrep rule fle %s\n" "${ripgrep_file}"
        info_msg "Running ripgrep on %s\n" "${input_file}"
        # This will make tee ignore any interrupt signals and continue running until it finishes.
        rg --file="${ripgrep_file}" "${input_file}" --case-sensitive --multiline --no-ignore --line-number | tee -i "${log_file}" || true
        #cat "${log_file}"
    else
        error_msg "Ripgrep (rg) not found. Please install it to run ripgrep patterns.\n" >&2
        exit 1
    fi
}
