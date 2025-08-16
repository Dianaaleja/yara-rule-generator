#!/usr/bin/env bash
# Author: Pierre Gronau <Pierre.Gronau@ndaal.eu>
# Copyright (c) 2024
# Copyright (c) Pierre Gronau <Pierre.Gronau@ndaal.eu>
# Copyright (c) ndaal, Germany
# License: All content is licensed under the terms of the <MIT License>
# Developed on: Debian 12.x x86 architecture; macOS Sonoma x86 architecture
# Tested on: Debian 12.x x86 architecture; macOS Sonoma x86 architecture

# This bash script defines a function called remove_first_lines that removes a specified number of lines from the beginning of a file. Here's a breakdown of what the script does:

# - It sets various bash options to control error handling and variable usage.
# - It defines a cleanup function that will be called when the script exits,
#   either normally or due to an error.
# - The remove_first_lines function takes two arguments: the number of lines to remove and the file to modify.
# - It checks that both arguments are provided, and that the file exists.
# - It validates that the first argument is a positive integer.
# - It detects the operating system (either macOS or Linux) and uses the sed command to remove the specified number of lines from the file. The -i option tells sed to modify the file in place.
# - If the operating system is not supported, it prints an error message and returns 1.
# - Finally, it prints a verbose message indicating that the lines have been removed.
# The script does not execute the remove_first_lines function by default, 
# but it can be called from other parts of the script or from the command line.

# Enable strict mode
set -o errexit  # Exit on error
set -o errtrace # Exit on error in functions
set -o nounset  # Exit on undefined variables
set -o pipefail # Exit on pipe failures
# set -o xtrace # Uncomment for debugging

# Set safe field separator
# nosemgrep: ifs-tampering
IFS=$'\n\t'

trap cleanup SIGINT SIGTERM ERR EXIT

cleanup() {
    trap - SIGINT SIGTERM ERR EXIT
    printf "%b\n" "\nCleanup is running"
    # Additional cleanup tasks can be added here if needed
}

remove_first_lines() {
    local lines_to_remove="$1"
    local file="$2"

    # Check if both arguments are provided
    if [ $# -ne 2 ]; then
        error_msg "This function requires two arguments."
        verbose_msg "Usage: remove_first_lines <number_of_lines> <filename>"
        return 1
    fi

    # Check if the file exists
    if [[ ! -f "${file}" ]]; then
        error_msg "File '${file}' not found."
        return 1
    fi

    # Validate that the first argument is a positive integer
    if ! [[ "${lines_to_remove}" =~ ^[0-9]+$ ]] || [ "${lines_to_remove}" -eq 0 ]; then
        error_msg "Invalid number of lines. Please provide a positive integer."
        return 1
    fi

    # Detect OS
    local os_type
    local "os_type=$(uname)"
    readonly os_type

    if [[ "${os_type}" == "Darwin" ]]; then
        # macOS
        sed -i '' "1,${lines_to_remove}d" "$file"
    elif [[ "${os_type}" == "Linux" ]]; then
        # Linux
        sed -i "1,${lines_to_remove}d" "$file"
    else
        error_msg "Unsupported operating system: $os_type"
        return 1
    fi

    verbose_msg "Removed first ${lines_to_remove} lines from ${file}"
}
