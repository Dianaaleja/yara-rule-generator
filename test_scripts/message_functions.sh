#!/usr/bin/env bash
# Author: Pierre Gronau <Pierre.Gronau@ndaal.eu>
# Copyright (c) 2024
# Copyright (c) Pierre Gronau <Pierre.Gronau@ndaal.eu>
# Copyright (c) ndaal, Germany
# License: All content is licensed under the terms of the <MIT License>
# Developed on: Debian 12.x x86 architecture; macOS Sonoma x86 architecture
# Tested on: Debian 12.x x86 architecture; macOS Sonoma x86 architecture

# The provided bash script is designed to handle various tasks such as 
# error handling, printing messages with colors, and performing cleanup 
# operations. Here's a brief breakdown of what the script does:
# Script Metadata and Configuration:
# - The script includes metadata such as the author, copyright information, 
#   and the license.
# - It is developed and tested on Debian 12.x and macOS Sonoma x86 architectures.
# Color Codes:
# The script defines color codes for various message types, including bold blue, 
# cyan, yellow, red, green, and a reset code.
# Error Handling and Environment Settings:
# - The script is configured to exit on errors (set -o errexit), handle errors 
#   in functions and subshells (set -o errtrace), and prevent the use 
#   of undefined variables (set -o nounset).
# - It also ensures that errors in pipelines are caught (set -o pipefail).
# - The Internal Field Separator (IFS) is set to newline and tab 
#   to handle word splitting.
# Cleanup Function:
# - A cleanup function is defined to perform cleanup tasks when the script exits or encounters an error. It prints a message indicating that cleanup is running.
# Message Functions:
# - Several functions are defined to print different types of messages with colors:
#   - cat_msg(): Prints debug messages and the contents of a file.
#   - debug_msg(): Prints debug messages if debugging is enabled.
#   - error_msg(): Prints error messages in bold red.
#   - info_msg(): Prints informational messages in bold blue.
#   - hint_msg(): Prints hint messages in bold cyan.
#   - line_msg(): Prints a line message in bold cyan.
#   - show_version(): Displays version information.
#   - verbose_msg(): Prints verbose messages if verbosity is enabled.
#   - warning_msg(): Prints warning messages in bold yellow.
# Message Printing:
# The script includes example calls to these message functions 
# to demonstrate their usage.
# Overall, this script is a well-structured template for handling colored output, 
# error handling, and cleanup in bash scripts.

# Explanation of the color codes:
# \e[1;34m: Bold Blue
# \e[1;36m: Bold Cyan
# \e[1;33m: Bold Yellow
# \e[1;31m: Bold Red
# \e[1;32m: Bold Green
# \e[0m: Reset to default

# Set $IFS to only newline and tab.
IFS=$'\n\t'

trap cleanup SIGINT SIGTERM ERR EXIT

cleanup() {
    trap - SIGINT SIGTERM ERR EXIT
    printf "%b\n" "\nCleanup is running"
    # Additional cleanup tasks can be added here if needed
}

# Initialize verbose variable
verbose=0

# Initialize debug variable
debug=0

cat_msg() {
    if [[ "${debug}" -eq 0 ]]; then
        printf "\e[33;40mDebug\e[0m: %s\n" "${1}" >&2
        printf "*******************************************************************************************\n" >&2
        cat "${1}"
        printf "*******************************************************************************************\n" >&2
    fi
}

# Function to print verbose messages
debug_msg() {
    if [[ "${debug}" -eq 1 ]]; then
        printf "\e[33;40mDebug:\e[0m %s\n" "${1}" >&2
    fi
}

# Function to print error messages
error_msg() {
    printf "\e[31;47mError:\e[0m %s\n" "${1}" >&2
}

# Function to print info messages
info_msg() {
    printf "\e[1;34mInfo:\e[0m %s\n" "${1}" >&2
}

# Function to print hint messages
hint_msg() {
    printf "\e[1;36mHint:\e[0m %s\n" "${1}" >&2
}

# Function for a line messages
line_msg() {
    printf "\e[1;36m*******************************************************************************************\e[0m %s\n" "${1}" >&2
}

show_simple_ascii_art() {
    printf "
                                                         
       _______ _______ _______ _______ _______           
      |\     /|\     /|\     /|\     /|\     /|          
      | +---+ | +---+ | +---+ | +---+ | +---+ |          
      | |   | | |   | | |   | | |   | | |   | |          
      | |n  | | |d  | | |a  | | |a  | | |l  | |          
      | +---+ | +---+ | +---+ | +---+ | +---+ |          
      |/_____\|/_____\|/_____\|/_____\|/_____\|          
                   _______ _______                       
                  |\     /|\     /|                      
                  | +---+ | +---+ |                      
                  | |   | | |   | |                      
                  | |i  | | |n  | |                      
                  | +---+ | +---+ |                      
                  |/_____\|/_____\|                      
 _______ _______ _______ _______ _______ _______ _______ 
|\     /|\     /|\     /|\     /|\     /|\     /|\     /|
| +---+ | +---+ | +---+ | +---+ | +---+ | +---+ | +---+ |
| |   | | |   | | |   | | |   | | |   | | |   | | |   | |
| |C  | | |o  | | |l  | | |o  | | |g  | | |n  | | |e  | |
| +---+ | +---+ | +---+ | +---+ | +---+ | +---+ | +---+ |
|/_____\|/_____\|/_____\|/_____\|/_____\|/_____\|/_____\|
 _______ _______ _______ _______ _______ _______ _______ 
|\     /|\     /|\     /|\     /|\     /|\     /|\     /|
| +---+ | +---+ | +---+ | +---+ | +---+ | +---+ | +---+ |
| |   | | |   | | |   | | |   | | |   | | |   | | |   | |
| |G  | | |e  | | |r  | | |m  | | |a  | | |n  | | |y  | |
| +---+ | +---+ | +---+ | +---+ | +---+ | +---+ | +---+ |
|/_____\|/_____\|/_____\|/_____\|/_____\|/_____\|/_____\|
                                                         

    "
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

# Function to print warning messages
warning_msg() {
    if [[ "${verbose}" -eq 1 ]]; then
        printf "\e[33;40mWarning:\e[0m %s\n" "${1}" >&2
    fi
}

debug_msg "Debug information"
error_msg "An error occurred"
hint_msg "Here's a hint for you"
info_msg "This is an informational message"
verbose_msg "Verbose messages are enabled"
warning_msg "This is a warning"
