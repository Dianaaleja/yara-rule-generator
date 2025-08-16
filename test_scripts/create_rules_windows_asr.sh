#!/usr/bin/env bash
# Author: Pierre Gronau <Pierre.Gronau@ndaal.eu>
# Copyright (c) 2024
# Copyright (c) Pierre Gronau <Pierre.Gronau@ndaal.eu>
# Copyright (c) ndaal, Germany
# License: All content is licensed under the terms of the <MIT License>
# Developed on: Debian 12.x x86 architecture; macOS Sonoma x86 architecture
# Tested on: Debian 12.x x86 architecture; macOS Sonoma x86 architecture

# The solution exists of several artefacts:
# metadata file: windows_asr_rules.meta
# message_functions.sh
# input file: windows_asr_rules.csv
# prepare_rules.sh
## prepare_rules.sh creates some checksum files like windows_asr_rules.meta.sha3-512
## also setting chmod 644 for several files
# create_rules_windows_asr.sh
## this script creates three rule files from the input file:
### "${input_file_base}_gitleaks_rules.toml"
### "${input_file_base}_yara_rules.yara"
### "${input_file_base}_ripgrep_patterns.txt"
## this script creates three finding files from the rule files:
### "${input_file_base}_gitleaks_findings_${DIRDATE}.log"
### "${input_file_base}_YARA_findings_${DIRDATE}.log"
### "${input_file_base}_ripgrep_findings_${DIRDATE}.log"
## create a metadata file:
### "${metadata_output}" like "windows_asr_rules_metadata.txt"
## many variables are defined readonly or local for security reasons

# This script is designed to extract and print the name and path of the script itself, 
# as well as the full path including the script name. Here's a breakdown of what 
# each line does:
#
# script_name1="$(basename "${0}")": This line extracts the name of the script 
# from the special variable ${0}, which holds the path to the script. The basename 
# command removes the directory path, leaving only the script name.
# 
# printf "%b\n" "\nscript_name1: ${script_name1}\n": This line prints the script name 
# to the console.
#
# script_path1="$(realpath "$(dirname "${0}")")": This line extracts the directory path 
# of the script from the special variable ${0}. The dirname command removes the script name, 
# leaving only the directory path. The realpath command then resolves any symbolic links 
# in the path, resulting in the absolute path to the script's directory.
#
# printf "%b\n" "\nscript_path1: ${script_path1}\n": This line prints the script's directory path 
# to the console.
#
# script_path_with_name="${script_path1}/${script_name1}": This line constructs the full path 
# to the script by concatenating the directory path and the script name.
# 
# printf "%b\n" "\nScript path with name: ${script_path_with_name}\n": This line prints 
# the full path to the script to the console.
#
# printf "%b\n" "\nScript finished\n": This line prints a message indicating that the script 
# has finished executing.
#
# exit 0: This line exits the script with a status code of 0, indicating successful execution.
#
# In summary, this script provides information about its own name and location, 
# which can be useful for debugging or logging purposes.

# Set $IFS to only newline and tab.
IFS=$'\n\t'

trap cleanup SIGINT SIGTERM ERR EXIT

cleanup() {
    trap - SIGINT SIGTERM ERR EXIT
    printf "%b\n" "\nCleanup is running"
    # Additional cleanup tasks can be added here if needed
}

SCRIPT_NAME="$(basename "${0}")"
readonly SCRIPT_NAME

SCRIPT_PATH="$(realpath "$(dirname "${0}")")"
readonly SCRIPT_PATH

SCRIPT_PATH_WITH_NAME="${SCRIPT_PATH}/${SCRIPT_NAME}"
readonly SCRIPT_PATH_WITH_NAME

DIRECTORY="${SCRIPT_PATH}/tools"
printf "Info: the directory is ${DIRECTORY}. %s\n"

if [ ! -d "${DIRECTORY}" ]; then
    # Control will enter here if ${DESTINATION} doesn't exist.
    mkdir -p -v "${DIRECTORY}"
    #touch "${DIRECTORY}/placeholder.txt"
    printf "Info: the directory ${DIRECTORY} is created. %s\n"
fi

# Define the path to the functions file and its checksum file
FUNCTIONS_FILE="message_functions.sh"
readonly FUNCTIONS_FILE
printf "%s\n" "${FUNCTIONS_FILE}"
CHECKSUM_FUNCTIONS_FILE="${FUNCTIONS_FILE}.sha3-512"
readonly CHECKSUM_FUNCTIONS_FILE
printf "%s\n" "${CHECKSUM_FUNCTIONS_FILE}"

# Function to get file permissions
get_file_permissions() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        stat -f "%Lp" "$1"
    else
        stat -c "%a" "$1"
    fi
}

# create checksum with
# openssl dgst -sha3-512 -r message_functions.sh | awk '{print $1}' > message_functions.sh.sha3-512
# Function to verify checksum
verify_checksum() {
    local file="${1}"
    local hash_file="${2}"
    local expected_hash
    local actual_hash

    if [[ ! -f "${hash_file}" ]]; then
        printf "Error: Checksum file '%s' not found.\n" "${hash_file}" >&2
        exit 1
    fi

    expected_hash="$(cat "${hash_file}")"
    actual_hash="$(openssl dgst -sha3-512 -r "${file}" | awk '{print $1}')"

    if [[ "${expected_hash}" != "${actual_hash}" ]]; then
        printf "Error: SHA3-512 checksum verification failed for '%s'.\n" "${file}" >&2
        exit 1
    fi
}

# Check if the functions file exists
if [[ ! -f "${FUNCTIONS_FILE}" ]]; then
    printf "Error: Required file '%s' not found.\n" "${FUNCTIONS_FILE}" >&2
    exit 1
fi

# Check if the checksum file exists
if [[ ! -f "${CHECKSUM_FUNCTIONS_FILE}" ]]; then
    printf "Error: Checksum file '%s' not found.\n" "${CHECKSUM_FUNCTIONS_FILE}" >&2
    exit 1
fi

check_file_permissions() {
  local file_path="$1"
  local expected_perms="644"
  local file_perms
  file_perms="$(get_file_permissions "${file_path}")"
  if [[ "${file_perms}" != "${expected_perms}" ]]; then
    printf "Error: Incorrect permissions on '%s'. Expected %s, found %s.\n" "${file_path}" "${expected_perms}" "${file_perms}" >&2
    exit 1
  fi
}

check_file_permissions "${FUNCTIONS_FILE}"
check_file_permissions "${CHECKSUM_FUNCTIONS_FILE}"

# Verify file integrity
verify_checksum "${FUNCTIONS_FILE}" "${CHECKSUM_FUNCTIONS_FILE}"

# Source the message functions file
# shellcheck source=/dev/null
source "${FUNCTIONS_FILE}"

show_simple_ascii_art

line_msg ""

hint_msg "Adjust verbose variable"
verbose=1
verbose_msg "Verbose variable is: ${verbose}"

hint_msg "Adjust debug variable"
debug=0
verbose_msg "Debug variable is: ${debug}"

# Now you can use the functions
if [[ ${debug} -eq 1 ]]; then
    line_msg ""
    debug_msg "Debug mode is on"
    error_msg "An error occurred"
    info_msg "This is an informational message"
    hint_msg "Here's a hint for you"
    verbose_msg "Verbose messages are enabled"
    warning_msg "This is a warning"
    line_msg ""
else
    line_msg ""
    error_msg "An error occurred"
    info_msg "This is an informational message"
    hint_msg "Here's a hint for you"
    verbose_msg "Verbose messages are enabled"
    warning_msg "This is a warning"
    line_msg ""
fi

input_file="windows_asr_rules.csv"
verbose_msg "input_file is: ${input_file}"

input_file_base="${input_file%.*}"
verbose_msg "Removes extension .csv from ${input_file}"
info_msg "input_file_base is: ${input_file_base}"

# Function to check if a file exists
check_file_exists() {
    local file="$1"
    local is_input="$2"

    if [[ "${is_input}" == "true" ]]; then
        if [[ ! -f "${file}" ]]; then
            error_msg "Input file '${file}' not found."
            exit 1
        fi
    else
        if [[ -f "${file}" ]]; then
            warning_msg "Output file '${file}' already exists. It will be overwritten."
        fi
    fi
}

META_FILE="${input_file_base}.meta"
readonly META_FILE
verbose_msg "${META_FILE}"

CHECKSUM_META_FILE="${META_FILE}.sha3-512"
readonly CHECKSUM_META_FILE
verbose_msg "${CHECKSUM_META_FILE}"

check_file_exists "${META_FILE}" "true"
check_file_exists "${CHECKSUM_META_FILE}" "true"

check_file_permissions "${META_FILE}"
check_file_permissions "${CHECKSUM_META_FILE}"

# Verify file integrity
verify_checksum "${META_FILE}" "${CHECKSUM_META_FILE}"

# Source the Metadata variables file
# shellcheck source=/dev/null
source "${META_FILE}"

line_msg ""

REMOVE_FIRST_LINES_FUNCTION_FILE="remove_first_lines_function.sh"
readonly REMOVE_FIRST_LINES_FUNCTION_FILE
verbose_msg "${REMOVE_FIRST_LINES_FUNCTION_FILE}"

CHECKSUM_REMOVE_FIRST_LINES_FUNCTION_FILE="${REMOVE_FIRST_LINES_FUNCTION_FILE}.sha3-512"
readonly CHECKSUM_REMOVE_FIRST_LINES_FUNCTION_FILE
verbose_msg "${CHECKSUM_REMOVE_FIRST_LINES_FUNCTION_FILE}"

check_file_exists "${REMOVE_FIRST_LINES_FUNCTION_FILE}" "true"
check_file_exists "${CHECKSUM_REMOVE_FIRST_LINES_FUNCTION_FILE}" "true"

check_file_permissions "${REMOVE_FIRST_LINES_FUNCTION_FILE}"
check_file_permissions "${CHECKSUM_REMOVE_FIRST_LINES_FUNCTION_FILE}"

# Verify file integrity
verify_checksum "${REMOVE_FIRST_LINES_FUNCTION_FILE}" "${CHECKSUM_REMOVE_FIRST_LINES_FUNCTION_FILE}"

# Source the remove_first_lines_function file
# shellcheck source=/dev/null
source "${REMOVE_FIRST_LINES_FUNCTION_FILE}"

line_msg ""

RUN_RULES_TOOLS_FUNCTIONS_FILE="run_rules_tools_functions.sh"
readonly RUN_RULES_TOOLS_FUNCTIONS_FILE
verbose_msg "${RUN_RULES_TOOLS_FUNCTIONS_FILE}"

CHECKSUM_RUN_RULES_TOOLS_FUNCTIONS_FILE="${RUN_RULES_TOOLS_FUNCTIONS_FILE}.sha3-512"
readonly CHECKSUM_RUN_RULES_TOOLS_FUNCTIONS_FILE
verbose_msg "${CHECKSUM_RUN_RULES_TOOLS_FUNCTIONS_FILE}"

check_file_exists "${RUN_RULES_TOOLS_FUNCTIONS_FILE}" "true"
check_file_exists "${CHECKSUM_RUN_RULES_TOOLS_FUNCTIONS_FILE}" "true"

check_file_permissions "${RUN_RULES_TOOLS_FUNCTIONS_FILE}"
check_file_permissions "${CHECKSUM_RUN_RULES_TOOLS_FUNCTIONS_FILE}"

# Verify file integrity
verify_checksum "${RUN_RULES_TOOLS_FUNCTIONS_FILE}" "${CHECKSUM_RUN_RULES_TOOLS_FUNCTIONS_FILE}"

# Source the create_hashes_functions file
# shellcheck source=/dev/null
source "${RUN_RULES_TOOLS_FUNCTIONS_FILE}"

line_msg ""

CREATE_HASHES_FUNCTIONS_FILE="create_hashes_functions.sh"
readonly CREATE_HASHES_FUNCTIONS_FILE
verbose_msg "${CREATE_HASHES_FUNCTIONS_FILE}"

CHECKSUM_CREATE_HASHES_FUNCTIONS_FILE="${CREATE_HASHES_FUNCTIONS_FILE}.sha3-512"
readonly CHECKSUM_CREATE_HASHES_FUNCTIONS_FILE
verbose_msg "${CHECKSUM_CREATE_HASHES_FUNCTIONS_FILE}"

check_file_exists "${CREATE_HASHES_FUNCTIONS_FILE}" "true"
check_file_exists "${CHECKSUM_CREATE_HASHES_FUNCTIONS_FILE}" "true"

check_file_permissions "${CREATE_HASHES_FUNCTIONS_FILE}"
check_file_permissions "${CHECKSUM_CREATE_HASHES_FUNCTIONS_FILE}"

# Verify file integrity
verify_checksum "${CREATE_HASHES_FUNCTIONS_FILE}" "${CHECKSUM_CREATE_HASHES_FUNCTIONS_FILE}"

# Source the create_hashes_functions file
# shellcheck source=/dev/null
source "${CREATE_HASHES_FUNCTIONS_FILE}"

line_msg ""

MANIPULATE_INPUT_FILE_FUNCTIONS_FILE="create_hashes_functions.sh"
readonly MANIPULATE_INPUT_FILE_FUNCTIONS_FILE
verbose_msg "${MANIPULATE_INPUT_FILE_FUNCTIONS_FILE}"

CHECKSUM_MANIPULATE_INPUT_FILE_FUNCTIONS_FILE="${MANIPULATE_INPUT_FILE_FUNCTIONS_FILE}.sha3-512"
readonly CHECKSUM_MANIPULATE_INPUT_FILE_FUNCTIONS_FILE
verbose_msg "${CHECKSUM_MANIPULATE_INPUT_FILE_FUNCTIONS_FILE}"

check_file_exists "${MANIPULATE_INPUT_FILE_FUNCTIONS_FILE}" "true"
check_file_exists "${CHECKSUM_MANIPULATE_INPUT_FILE_FUNCTIONS_FILE}" "true"

check_file_permissions "${MANIPULATE_INPUT_FILE_FUNCTIONS_FILE}"
check_file_permissions "${CHECKSUM_MANIPULATE_INPUT_FILE_FUNCTIONS_FILE}"

# Verify file integrity
verify_checksum "${MANIPULATE_INPUT_FILE_FUNCTIONS_FILE}" "${CHECKSUM_MANIPULATE_INPUT_FILE_FUNCTIONS_FILE}"

# Source the create_hashes_functions file
# shellcheck source=/dev/null
source "${MANIPULATE_INPUT_FILE_FUNCTIONS_FILE}"

line_msg ""
hint_msg "Adjust hashes variable"
hashes=0
verbose_msg "Hashes variable is: ${hashes}"

if [ "${hashes}" -eq 1 ]; then
  verbose_msg "We will create several hash values"
  check_commands
  eval "$(generate_hashes "Your string here")"

  # Create CSV file
  create_csv "hashes_output.csv" "$(declare -p hash_results)"

else
  hint_msg "We do not create any hash values"
fi

line_msg ""
# Define constants
DIRDATE=$(date +"%Y-%m-%d")
readonly DIRDATE
verbose_msg "${DIRDATE}"

check_readonly() {
  local variables=("COPYRIGHT" "LICENSE" "SHARING" "VERSION" "STATUS" "CREATED" "MODIFIED" "AUTHOR" "CATEGORY" "REFERENCE" "SEVERITY" "SOURCE" "TAG1" "TAG2")
  for var in "${variables[@]}"; do
    if declare -p "${var}" | grep -q '^declare -r'; then
      info_msg "${var} is readonly"
    else
      error_msg "${var} is not readonly"
      exit 1
    fi
  done
}

check_readonly
line_msg ""

# Function to enrich metadata
enrich_metadata() {
    local output_file="$1"

    cat <<EOF > "${output_file}"
# Metadata for rule generation
# Created on: ${CREATED}
# Modified on: ${MODIFIED}
# Severity: ${SEVERITY}

COPYRIGHT="${COPYRIGHT}"
LICENSE="${LICENSE}"
SHARING="${SHARING}"
VERSION="${VERSION}"
AUTHOR="${AUTHOR}"
CATEGORY="${CATEGORY}"
REFERENCE="${REFERENCE}"
SEVERITY="${SEVERITY}"
SOURCE="${SOURCE}"
TAG1="${TAG1}"
TAG2="${TAG2}"
STATUS="${STATUS}"
CREATED="${CREATED}"
MODIFIED="${MODIFIED}"
EOF
}

# Function to create Gitleaks rule
create_gitleaks_rule() {
    local id="$1"
    local asr_rule="$2"
    local metadata_comment="$3"
    local metadata_tactic="$4"
    local output_file="$5"

    local description="${asr_rule} ${metadata_comment} ${metadata_tactic}"
    info_msg "Remove all double quotes from the string"
    description="${description//\"/}"

    cat >> "${output_file}" << EOF
[[rules]]
id = "${TAG1}_${TAG2}_${id}"
description = "${description}"
regex = '''${id}'''
keywords = [
    "${id}",
]    
tags = [
    "${TAG1}",
    "${TAG2}",
    "${LICENSE}",
    "${SHARING}",
    "Version: ${VERSION}",
    "${AUTHOR}",
    "Category: ${CATEGORY}",
    "${REFERENCE}",
    "Severity: ${SEVERITY}",
    "Source: ${SOURCE}",
    "${STATUS}",
    "created: ${CREATED}",
    "modified: ${MODIFIED}",
]

EOF
}

# Function to create YARA rule
create_yara_rule() {
    local id="$1"
    local asr_rule="$2"
    local metadata_comment="$3"
    local metadata_tactic="$4"
    local output_file="$5"

    local description="${asr_rule} - ${metadata_comment} - ${metadata_tactic}"
    info_msg "Remove all double quotes from the string"
    description="${description//\"/}"

    # Replace hyphens with underscores for a valid YARA rule name
    local rule_name="${TAG1}_${TAG2}_${id//[^a-zA-Z0-9]/_}"

    cat <<EOF >> "${output_file}"
rule ${rule_name} 
{
    meta:
        description = "${description}"
        os = "${TAG1}"
        type = "${TAG2}"
        license = "${LICENSE}"
        copyright = "${COPYRIGHT}"
        sharing = "${SHARING}"
        Version = "${VERSION}"
        Author = "${AUTHOR}"
        Category = "${CATEGORY}"
        reference = "${REFERENCE}"
        Severity = "${SEVERITY}"
        Source = "${SOURCE}"
        Status = "${STATUS}"
        created = "${CREATED}"
        modified = "${MODIFIED}"

    strings:
        \$id = "${id}"

    condition:
        \$id
}

EOF
}


# Function to create ripgrep patterns
create_ripgrep_patterns() {
    local input_file="$1"
    local output_file="$2"

    touch "${output_file}"
    tail -n +2 "${input_file}" | while IFS=, read -r id asr_rule metadata_comment metadata_tactic; do
        printf "%s\n" "${id}" >> "${output_file}"
    done
}

# Enrich metadata
metadata_output="windows_asr_rules_metadata.txt"
enrich_metadata "${metadata_output}"

# Main script starts here

gitleaks_output="${input_file_base}_gitleaks_rules.toml"
readonly gitleaks_output
verbose_msg "gitleaks_rules are: ${gitleaks_output}"
rm -f -v "${gitleaks_output}"
yara_output="${input_file_base}_yara_rules.yara"
readonly yara_output
verbose_msg "yara_rules are: ${yara_output}"
rm -f -v "${yara_output}"
ripgrep_patterns="${input_file_base}_ripgrep_patterns.txt"
readonly ripgrep_patterns
verbose_msg "ripgrep_patterns are: ${ripgrep_patterns}"
rm -f -v "${ripgrep_patterns}"

line_msg ""
verbose_msg "Create Gitleaks rules"
gitleaks_rules_file="${gitleaks_output}"
while IFS=, read -r id asr_rule metadata_comment metadata_tactic; do
    verbose_msg "Create Gitleaks rules"
    create_gitleaks_rule "${id}" "${asr_rule}" "${metadata_comment}" "${metadata_tactic}" "${gitleaks_rules_file}"
done < "${input_file}"

line_msg ""
verbose_msg "Create YARA rules"
yara_rules_file="${yara_output}"
while IFS=, read -r id asr_rule metadata_comment metadata_tactic; do
    verbose_msg "Create YARA rules"
    create_yara_rule "${id}" "${asr_rule}" "${metadata_comment}" "${metadata_tactic}" "${yara_rules_file}"
done < "${input_file}"

line_msg ""
verbose_msg "Create ripgrep patterns"
ripgrep_patterns_file="${ripgrep_patterns}"
create_ripgrep_patterns "${input_file}" "${ripgrep_patterns_file}"

line_msg ""
info_msg "Run Gitleaks"

verbose_msg "input ${input_file}"
verbose_msg "rules ${gitleaks_output}"

verbose_msg "remove lines from ${gitleaks_output}"
remove_first_lines 23 "${gitleaks_output}"

run_gitleaks "${input_file}" "${gitleaks_output}"

line_msg ""
info_msg "Run YARA"

verbose_msg "input ${input_file}"
verbose_msg "rules ${yara_output}"

verbose_msg "remove lines from ${yara_output}"
remove_first_lines 26 "${yara_output}"

run_yara "${input_file}" "${yara_output}"

line_msg ""
info_msg "Run ripgrep"

verbose_msg "rules ${ripgrep_patterns}"
run_ripgrep "${input_file}" "${ripgrep_patterns_file}"



line_msg ""
hint_msg "this is the end my friend"
line_msg ""

cleanup

script_name1="$(basename "${0}")"
printf "%b\n" "\nscript_name1: ${script_name1}\n"
script_path1="$(realpath "$(dirname "${0}")")"
printf "%b\n" "\nscript_path1: ${script_path1}\n"
script_path_with_name="${script_path1}/${script_name1}"
printf "%b\n" "\nScript path with name: ${script_path_with_name}\n"
printf "%b\n" "\nScript finished\n"
exit 0
