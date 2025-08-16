#!/usr/bin/env bash
# Author: Pierre Gronau <Pierre.Gronau@ndaal.eu>
# Copyright (c) 2024
# Copyright (c) Pierre Gronau <Pierre.Gronau@ndaal.eu>
# Copyright (c) ndaal, Germany
# License: All content is licensed under the terms of the <MIT License>
# Developed on: Debian 12.x x86 architecture; macOS Sonoma x86 architecture
# Tested on: Debian 12.x x86 architecture; macOS Sonoma x86 architecture

# This bash script defines two main functions for text manipulation in files:
# - replace_pattern_in_file:
# - Purpose: Replaces a specified pattern with an empty string in a given file.
# - Usage: replace_pattern_in_file <file_path> <pattern>
# - Features:
#   - Validates input parameters
#   - Creates a backup of the original file before modification
#   - Uses different sed commands for macOS/BSD and Linux systems
#   - Provides error handling and informative messages
# remove_chars_from_file:
# - Purpose: Removes a specified number of characters from the beginning of each line in a file.
# - Usage: remove_chars_from_file <file_path> <num_chars_to_remove>
# - Features:
#   - Validates input parameters, ensuring the number of characters is a positive integer
#   - Creates a backup of the original file before modification
#   - Uses different sed commands for macOS/BSD and Linux systems
#   - Provides error handling and informative messages
# The script also includes:
# Error handling and exit strategies (set -o commands)
# A cleanup function triggered on script exit or interruption
# A constant DIRDATE for timestamping backups
# Overall, this script provides utility functions for text manipulation in files, 
# with a focus on cross-platform compatibility (macOS and Linux) and 
# safe file operations through backups and error handling.

# Set $IFS to only newline and tab.
IFS=$'\n\t'

trap cleanup SIGINT SIGTERM ERR EXIT

cleanup() {
    trap - SIGINT SIGTERM ERR EXIT
    printf "%b\n" "\nCleanup is running"
    # Additional cleanup tasks can be added here if needed
}

DIRDATE="$(date +"%Y-%m-%d")"
readonly DIRDATE

replace_pattern_in_file() {
  local usage="Usage: replace_pattern_in_file <file_path> <pattern>"
  
  if [ "$#" -ne 2 ]; then
    info_msg "${usage}"
    return 1
  fi

  local file_path="${1}"
  local pattern="${2}"

  if [ -z "${pattern}" ]; then
    error_msg "Pattern to replace cannot be empty"
    return 1
  fi

  if [ ! -f "${file_path}" ]; then
    error_msg "File not found: ${file_path}"
    return 1
  fi

  # Create a backup of the original file
  if ! cp -f -p -v "${file_path}" "${file_path}_${DIRDATE}.bak"; then
     error_msg "Failed to create a backup of the file"
     return 1
  fi

  # For macOS/BSD sed
  if [[ "$(uname)" == "Darwin" ]]; then
    sed -i '' -E "s/${pattern}//g" "${file_path}"
  else
    # For GNU sed (Linux)
    sed -i -E "s/${pattern}//g" "${file_path}"
  fi

  if sed -i "" "s/${pattern}//g" "${file_path}"; then
    info_msg "Replaced pattern '${pattern}' with an empty string in ${file_path}"
  else
    error_msg "Failed to modify the file"
    return 1
  fi

}

remove_chars_from_file() {
  local usage="Usage: remove_chars_from_file <file_path> <num_chars_to_remove>"
  
  if [ "$#" -ne 2 ]; then
    info_msg "${usage}"
    return 1
  fi

  local file_path="${1}"
  local chars_to_remove="${2}"

  if ! [[ "${chars_to_remove}" =~ ^[0-9]+$ ]]; then
    error_msg "Second argument must be a positive integer"
    return 1
  fi

  if [ "${chars_to_remove}" -lt 1 ]; then
    error_msg "Number of characters to remove must be greater than or equal to 1"
    return 1
  fi

  if [ ! -f "${file_path}" ]; then
    error_msg "File not found: ${file_path}"
    return 1
  fi

  # Create a backup of the original file
  if ! cp -f -p -v "${file_path}" "${file_path}_${DIRDATE}.bak"; then
     error_msg "Failed to create a backup of the file"
     return 1
  fi

  # For macOS/BSD sed
  if [[ "$(uname)" == "Darwin" ]]; then
    sed -i '' -E "s/^.{${chars_to_remove}}//" "${file_path}"
  else
    # For GNU sed (Linux)
    sed -i -E "s/^.{${chars_to_remove}}//" "${file_path}"
  fi

  if sed -i "" "s/^${chars_to_remove}//g" "${file_path}"; then
    echo "Removed ${chars_to_remove} characters from the beginning of each line in ${file_path}"
  else
    error_msg "Failed to modify the file"
    return 1
  fi
}
