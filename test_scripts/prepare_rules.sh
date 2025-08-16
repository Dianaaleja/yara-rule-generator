#!/usr/bin/env bash
# Author: Pierre Gronau <Pierre.Gronau@ndaal.eu>
# Copyright (c) 2024
# Copyright (c) Pierre Gronau <Pierre.Gronau@ndaal.eu>
# Copyright (c) ndaal, Germany
# License: All content is licensed under the terms of the <MIT License>
# Developed on: Debian 12.x x86 architecture; macOS Sonoma x86 architecture
# Tested on: Debian 12.x x86 architecture; macOS Sonoma x86 architecture

# This bash script is a utility for managing and verifying a set of required files, ensuring they are present, creating checksums, and setting file permissions. Here's a brief description of what it does:
# Setup and Initialization:
# Sets up error handling and cleanup mechanisms.
# Defines constants for version, script name, and paths.
# Initializes a verbose mode variable for detailed logging.
# Functions:
# - cleanup: Runs cleanup tasks when the script exits or encounters an error.
# - error_exit: Prints an error message and exits the script.
# - error_msg: Prints an error message.
# - info_msg: Prints an informational message.
# - show_version: Displays the script version.
# - verbose_msg: Prints verbose messages if verbose mode is enabled.
# - create_checksum: Creates a SHA3-512 checksum for a given file.
# - set_file_permissions: Sets file permissions to 644 for a given file.
# - get_file_permissions: Retrieves file permissions for a given file.
# - Directory and File Management:
# - Checks if a specific directory exists (tools), and creates it if it doesn't.
# Defines an array of required files that the script will manage.
# Command-Line Options:
# Parses command-line options for help (-h or --help), verbose mode (-v or --verbose), 
# and version information (-V or --version).
# Main Execution:
# - Verifies the existence of required files.
# - Creates checksums and sets permissions for each required file.
# If verbose mode is enabled, it provides detailed information about file permissions and checksums.
# Resets script permissions to make it executable.
# Final Output:
# - Prints the script name, path, and confirms the script has finished execution.
# This script ensures that a set of required files are present, secure, 
# and properly managed, providing detailed logging and error handling throughout its execution.

# Exit on error. Append "|| true" if you expect an error.
#set -o errexit
# Exit on error inside any functions or subshells.
#set -o errtrace
# Do not allow use of undefined vars. Use ${VAR:-} to use an undefined VAR
#set -o nounset
# Catch the error in case a command in a pipeline fails
set -o pipefail

# Set $IFS to only newline and tab.
IFS=$'\n\t'

# Cleanup function
cleanup() {
    trap - SIGINT SIGTERM ERR EXIT
    printf "%b\n" "\nCleanup is running"
    # Additional cleanup tasks can be added here if needed
}

# Set trap for cleanup
trap cleanup SIGINT SIGTERM ERR EXIT

# Initialize verbose variable
verbose=0

# Function for error handling
error_exit() {
    printf "\e[31;47mError:\e[0m %s\n" "${1:-"Unknown Error"}" >&2
    exit 1
}

# Function to print error messages
error_msg() {
    printf "\e[31;47mError:\e[0m %s\n" "${1}" >&2
}

# Function to print info messages
info_msg() {
    printf "\e[1;34mInfo:\e[0m %s\n" "${1}" >&2
}

# Function to display version information
show_version() {
    printf "\e[1;34mInfo:\e[0m %s\n" "${SCRIPT_NAME}" "${VERSION}"
}

# Function to print verbose messages
verbose_msg() {
    if [[ "${verbose}" -eq 1 ]]; then
        printf "Verbose: %s\n" "${1}" >&2
    fi
}

# Define constants
VERSION="0.5.2"
readonly VERSION

SCRIPT_NAME="$(basename "${0}")"
readonly SCRIPT_NAME

SCRIPT_PATH="$(realpath "$(dirname "${0}")")"
readonly SCRIPT_PATH

SCRIPT_PATH_WITH_NAME="${SCRIPT_PATH}/${SCRIPT_NAME}"
readonly SCRIPT_PATH_WITH_NAME

DIRECTORY="${SCRIPT_PATH}/tools"
info_msg "${DIRECTORY}"

if [ ! -d "${DIRECTORY}" ]; then
    # Control will enter here if ${DESTINATION} doesn't exist.
    mkdir -p -v "${DIRECTORY}"
    #touch "${DIRECTORY}/placeholder.txt"
    printf "Info: the directory ${DIRECTORY} is created. %s\n"
fi

# Define file names
PREPARE_RULES_FILE="$(basename "${0}")"
FUNCTIONS_FILE="message_functions.sh"
META_FILE="windows_asr_rules.meta"
REMOVE_FIRST_LINES_FUNCTION_FILE="remove_first_lines_function.sh"
CREATE_HASHES_FUNCTIONS_FILE="create_hashes_functions.sh"
RUN_RULES_TOOLS_FUNCTIONS_FILE="run_rules_tools_functions.sh"
MANIPULATE_INPUT_FILE_FUNCTIONS_FILE="manipulate_input_file_functions.sh"

# Define an array of required files
required_files=(
    "${PREPARE_RULES_FILE}"
    "${FUNCTIONS_FILE}"
    "${META_FILE}"
    "${REMOVE_FIRST_LINES_FUNCTION_FILE}"
    "${CREATE_HASHES_FUNCTIONS_FILE}"
    "${RUN_RULES_TOOLS_FUNCTIONS_FILE}"
    "${MANIPULATE_INPUT_FILE_FUNCTIONS_FILE}"
)


# Function to display usage information
usage() {
    cat << EOF
Usage: ${SCRIPT_NAME} [options]

Options:
  -h, --help         Display this help message
  -v, --verbose      Increase verbosity
  -V, --version      Display version information
EOF
}

# Function to create checksum
create_checksum() {
    local file="${1}"
    local checksum_file="${file}.sha3-512"
    info_msg "Creating checksum for ${file}"
    openssl dgst -sha3-512 -r "${file}" | awk '{print $1}' > "${checksum_file}" || error_exit "Failed to create checksum for ${file}"
    chmod 644 "${checksum_file}"
    info_msg "Created checksum for ${file}"
    info_msg "Checksum is:"
    cat "${checksum_file}"
}

# Function to set file permissions
set_file_permissions() {
    local file="${1}"
    info_msg "Setting file permissions for ${file}"
    chmod 644 "${file}" || error_exit "Failed to set permissions for ${file}"
    verbose_msg "Set file permissions for ${file}"
}

# Function to get file permissions
get_file_permissions() {
  local file="${1}"
  if [[ "$(uname)" == "Darwin" ]]; then
    # macOS (BSD-based)
    stat -f "%p" "${file}"
  else
    # Linux and most Unix-like systems
    stat -c "%a" "${file}"
  fi
}

# Parse command-line options
while [[ "${#}" -gt 0 ]]; do
    case "${1}" in
        -h|--help)
            usage
            exit 0
            ;;
        -v|--verbose)
            verbose=$((verbose + 1))
            verbose_msg "Verbose messages are enabled"
            ;;
        -V|--version)
            show_version
            exit 0
            ;;
        *)
            break
            ;;
    esac
    shift
done

# Main script execution

# Check if required files exist
for file in "${required_files[@]}"; do
    [[ -f "${file}" ]] || error_exit "${file} not found"
done

# Create checksums and set permissions
for file in "${required_files[@]}"; do
    create_checksum "${file}"
    set_file_permissions "${file}"
    verbose_msg "File permissions for ${file}: $(get_file_permissions "${file}")"
    verbose_msg "$(ls -l "${file}")"
done

# Display file information if verbose
if [[ "${verbose}" -eq 1 ]]; then
    for file in "${required_files[@]}"; do
        verbose_msg "File permissions for ${file}.sha3-512: $(get_file_permissions "${file}.sha3-512")"
        verbose_msg "$(ls -l "${file}.sha3-512")"
        verbose_msg "Checksum for sha3-512 is:"
        cat "${file}.sha3-512"
    done
fi

info_msg "Reset script_name settings: ${PREPARE_RULES_FILE}" 
chmod +x "${PREPARE_RULES_FILE}"

cleanup

script_name1="$(basename "${0}")"
printf "%b\n" "\nscript_name1: ${script_name1}\n"
script_path1="$(realpath "$(dirname "${0}")")"
printf "%b\n" "\nscript_path1: ${script_path1}\n"
script_path_with_name="${script_path1}/${script_name1}"
printf "%b\n" "\nScript path with name: ${script_path_with_name}\n"
printf "%b\n" "\nScript finished\n"
exit 0
