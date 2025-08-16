#!/usr/bin/env bash
# Author: Pierre Gronau <Pierre.Gronau@ndaal.eu>
# Copyright (c) 2024
# Copyright (c) Pierre Gronau <Pierre.Gronau@ndaal.eu>
# Copyright (c) ndaal, Germany
# License: All content is licensed under the terms of the <MIT License>
# Developed on: Debian 12.x x86 architecture; macOS Sonoma x86 architecture
# Tested on: Debian 12.x x86 architecture; macOS Sonoma x86 architecture

# Here's a breakdown of what the line does:
#
# create_csv: This is a function call to a function named create_csv, 
# which is defined elsewhere in the script.
#
# "hashes_output.csv": This is the first argument to the create_csv function, 
# specifying the name of the CSV file to be created.
# 
# "$(declare -p hash_results)": This is the second argument to the create_csv function. 
# It uses command substitution ($( )) to capture the output of the declare -p hash_results command.
#
# declare -p hash_results: This command prints the contents of the hash_results associative array 
# in a format that can be used to recreate the array. The -p option stands for "print", 
# and it causes declare to print the array's contents instead of just its name.
# So, if the create_csv function is designed to take the output of declare -p and convert it 
# into a CSV file, this line would effectively create a CSV file containing the contents 
# of the hash_results array.
#
# However, since the line is commented out, it will not be executed, and no CSV file will be created.

# Set $IFS to only newline and tab.
IFS=$'\n\t'

trap cleanup SIGINT SIGTERM ERR EXIT

cleanup() {
    trap - SIGINT SIGTERM ERR EXIT
    printf "%b\n" "\nCleanup is running"
    # Additional cleanup tasks can be added here if needed
}

# Initialize verbose variable
hashes=0
printf "%b\n" "\nhashes is: ${hashes}"

check_commands() {
    local -a missing_commands=()

    # Check for required commands
    for cmd in base32 base58 base62 base64 base85 openssl blake3 k12sum; do
        command -v "${cmd}" &> /dev/null || missing_commands+=("${cmd}")
    done

    if [ "${#missing_commands[@]}" -ne 0 ]; then
        echo "Warning: The following commands are missing: ${missing_commands[*]}"
        echo "Some hash functions may not work."
    fi
}

generate_hashes() {
    local input_string="$1"
    local hash_base32 hash_base58 hash_base62 hash_base64 hash_base85
    local hash_blake2b hash_blake2s hash_blake3 hash_k12
    local hash_md2 hash_md4 hash_md5 hash_ripemd160 hash_whirlpool
    local hash_sha1 hash_sha224 hash_sha256 hash_sha384 hash_sha512
    local hash_sha3_224 hash_sha3_256 hash_sha3_384 hash_sha3_512
    local hash_tiger hash_mysql323 hash_mysql41

    # Base encodings
    hash_base32="$(echo -n "${input_string}" | base32)"
    hash_base58="$(echo -n "${input_string}" | base58 2>/dev/null || echo 'base58 command not available')"
    hash_base62="$(echo -n "${input_string}" | base62 2>/dev/null || echo 'base62 command not available')"
    hash_base64="$(echo -n "${input_string}" | base64)"
    hash_base85="$(echo -n "${input_string}" | base85 2>/dev/null || echo 'base85 command not available')"

    # OpenSSL based hashes
    if command -v openssl &> /dev/null; then
        hash_blake2b="$(echo -n "${input_string}" | openssl dgst -blake2b512 | awk '{print $2}')"
        hash_blake2s="$(echo -n "${input_string}" | openssl dgst -blake2s256 | awk '{print $2}')"
        hash_md2="$(echo -n "${input_string}" | openssl dgst -md5 | awk '{print $2}')"
        hash_md4="$(echo -n "${input_string}" | openssl dgst -md5 | awk '{print $2}')"
        hash_md5="$(echo -n "${input_string}" | openssl dgst -md5 | awk '{print $2}')"
        hash_ripemd160="$(echo -n "${input_string}" | openssl dgst -ripemd160 | awk '{print $2}')"
        #hash_whirlpool="$(echo -n "${input_string}" | openssl dgst -whirlpool | awk '{print $2}')"
        hash_sha1="$(echo -n "${input_string}" | openssl dgst -sha1 | awk '{print $2}')"
        hash_sha224="$(echo -n "${input_string}" | openssl dgst -sha224 | awk '{print $2}')"
        hash_sha256="$(echo -n "${input_string}" | openssl dgst -sha256 | awk '{print $2}')"
        hash_sha384="$(echo -n "${input_string}" | openssl dgst -sha384 | awk '{print $2}')"
        hash_sha512="$(echo -n "${input_string}" | openssl dgst -sha512 | awk '{print $2}')"
        hash_sha3_224="$(echo -n "${input_string}" | openssl dgst -sha3-224 | awk '{print $2}')"
        hash_sha3_256="$(echo -n "${input_string}" | openssl dgst -sha3-256 | awk '{print $2}')"
        hash_sha3_384="$(echo -n "${input_string}" | openssl dgst -sha3-384 | awk '{print $2}')"
        hash_sha3_512="$(echo -n "${input_string}" | openssl dgst -sha3-512 | awk '{print $2}')"
        #hash_tiger="$(echo -n "${input_string}" | openssl dgst -tiger | awk '{print $2}')"
    else
        hash_blake2b="openssl command not available"
        hash_blake2s="openssl command not available"
        hash_md2="openssl command not available"
        hash_md4="openssl command not available"
        hash_md5="openssl command not available"
        hash_ripemd160="openssl command not available"
        hash_whirlpool="openssl command not available"
        hash_sha1="openssl command not available"
        hash_sha224="openssl command not available"
        hash_sha256="openssl command not available"
        hash_sha384="openssl command not available"
        hash_sha512="openssl command not available"
        hash_sha3_224="openssl command not available"
        hash_sha3_256="openssl command not available"
        hash_sha3_384="openssl command not available"
        hash_sha3_512="openssl command not available"
        hash_tiger="openssl command not available"
    fi

    # Blake3 hash
    hash_blake3="$(echo -n "${input_string}" | blake3 2>/dev/null || echo 'blake3 command not available')"

    # K12 hash
    hash_k12="$(echo -n "${input_string}" | k12sum 2>/dev/null | awk '{print $1}' || echo 'k12sum command not available')"

    # MySQL hashes (these are not typically available as command-line tools, so we'll simulate them)
    hash_mysql323="$(echo -n "${input_string}" | od -A n -t x1 | tr -d ' \n')"
    hash_mysql41="$(echo -n "${input_string}" | sha1sum | awk '{print $1}')"

    # Print the results
    declare -A hash_results
    hash_results=(
        ["Original string"]="${input_string}"
        ["Base32 encoding"]="${hash_base32}"
        ["Base58 encoding"]="${hash_base58}"
        ["Base62 encoding"]="${hash_base62}"
        ["Base64 encoding"]="${hash_base64}"
        ["Base85 encoding"]="${hash_base85}"
        ["Blake2b hash"]="${hash_blake2b}"
        ["Blake2s hash"]="${hash_blake2s}"
        ["Blake3 hash"]="${hash_blake3}"
        ["K12 hash"]="${hash_k12}"
        ["MD2 hash"]="${hash_md2}"
        ["MD4 hash"]="${hash_md4}"
        ["MD5 hash"]="${hash_md5}"
        ["RIPEMD160 hash"]="${hash_ripemd160}"
        ["SHA1 hash"]="${hash_sha1}"
        ["SHA224 hash"]="${hash_sha224}"
        ["SHA256 hash"]="${hash_sha256}"
        ["SHA384 hash"]="${hash_sha384}"
        ["SHA512 hash"]="${hash_sha512}"
        ["SHA3-224 hash"]="${hash_sha3_224}"
        ["SHA3-256 hash"]="${hash_sha3_256}"
        ["SHA3-384 hash"]="${hash_sha3_384}"
        ["SHA3-512 hash"]="${hash_sha3_512}"
        ["Tiger hash"]="${hash_tiger}"
        ["Whirlpool hash"]="${hash_whirlpool}"
        ["MySQL323 hash"]="${hash_mysql323}"
        ["MySQL41 hash"]="${hash_mysql41}"
    )

    for key in "${!hash_results[@]}"; do
        printf "%s: %s\n" "${key}" "${hash_results[${key}]}"
    done

    # Return the hash results
    declare -p hash_results

}

create_csv() {
    local csv_file="$1"
    shift
    local -A hash_results
    eval "$1"
    shift

    local header="Input,Base32,Base58,Base62,Base64,Base85,Blake2b,Blake2s,Blake3,K12,MD2,MD4,MD5,RIPEMD160,SHA1,SHA224,SHA256,SHA384,SHA512,SHA3-224,SHA3-256,SHA3-384,SHA3-512,Tiger,Whirlpool,MySQL323,MySQL41"
    
    printf "%s\n" "${header}" > "${csv_file}"

    local line=""
    for key in "Original string" "Base32 encoding" "Base58 encoding" "Base62 encoding" "Base64 encoding" "Base85 encoding" "Blake2b hash" "Blake2s hash" "Blake3 hash" "K12 hash" "MD2 hash" "MD4 hash" "MD5 hash" "RIPEMD160 hash" "SHA1 hash" "SHA224 hash" "SHA256 hash" "SHA384 hash" "SHA512 hash" "SHA3-224 hash" "SHA3-256 hash" "SHA3-384 hash" "SHA3-512 hash" "Tiger hash" "Whirlpool hash" "MySQL323 hash" "MySQL41 hash"; do
        local escaped_value
        escaped_value=$(printf '%s' "${hash_results[${key}]}" | sed 's/"/""/g')
        line="${line}\"${escaped_value}\","
    done
    printf "%s\n" "${line%,}" >> "${csv_file}"

    printf "CSV file created: %s\n" "${csv_file}"
}

# Main execution
#check_commands
#eval "$(generate_hashes "Your string here")"

# Create CSV file
#create_csv "hashes_output.csv" "$(declare -p hash_results)"
