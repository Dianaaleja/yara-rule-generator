"""
Module for generating YARA rules from input files.

This module processes text files and CSV files to generate YARA rules
that can be used for malware detection and analysis.
"""

import argparse
import csv
import os
import re
from datetime import datetime

# Check for yara-python availability
try:
    import yara
    YARA_AVAILABLE = True
    print("yara-python available.")
except ImportError:
    YARA_AVAILABLE = False
    print("yara-python not available. Install with pip install yara-python")

# Step 1: Data Loading and Preparation
def load_data_and_handle_encoding(data_dir):
    """
    Loads text content from files in a directory and handles UnicodeDecodeError.

    Args:
        data_dir (str): The path to the directory containing the input files.

    Returns:
        dict: A dictionary with file names as keys and their content as values.
    """
    data = {}

    for filename in os.listdir(data_dir):
        file_path = os.path.join(data_dir, filename)

        if os.path.isfile(file_path):
            label = os.path.splitext(filename)[0]
            print(f"Processing: {filename}")

            try:
                # Try UTF-8 first
                with open(file_path, 'r', encoding='utf-8') as file_handle:
                    content = file_handle.read()
                print("Read with UTF-8")
            except UnicodeDecodeError:
                try:
                    # Try latin-1 if UTF-8 fails
                    with open(file_path, 'r', encoding='latin-1') as file_handle:
                        content = file_handle.read()
                    print("Read with latin-1")
                except Exception as encoding_error:
                    print(f"Error reading {filename}: {encoding_error}")
                    content = ""
            except Exception as general_error:
                print(f"Unexpected error with {filename}: {general_error}")
                content = ""

            if content:
                data[label] = content
                print(f"Loaded content: {len(content)} characters")
            else:
                print("Empty or unreadable file")

    print(f"\n Total files uploaded: {len(data)}")
    return data


# Step 2: YARA Rule Generation
def generate_yara_rule_text(label, content):
    """
    Generates the text for a YARA rule.

    Args:
        label (str): The name of the rule, derived from the file name.
        content (str): The content of the file to be converted into YARA strings.

    Returns:
        str: A string containing the complete YARA rule syntax.
    """
    print(f"Generating rule for: {label}")

    # Create a valid YARA identifier
    yara_identifier = re.sub(r'[^a-zA-Z0-9_]', '_', label)
    yara_strings = []

    # More aggressive sanitization
    sanitized_content = re.sub(r'[\x00-\x1F\x7F-\x9F]', '', content)
    sanitized_content = sanitized_content.replace('\r\n', '\n').replace('\r', '\n')

    if label == "Microsoft_Defender_All_signatures_list":
        # Special handling for CSV
        lines = sanitized_content.strip().split('\n')
        if not lines:
            print("Empty CSV file")
            return ""

        csv_reader = csv.reader(lines)

        # Skip header if it exists
        try:
            first_row = next(csv_reader)
            header_keywords = ['name', 'signature', 'hash', 'file']
            if first_row and any(word in first_row[0].lower() for word in header_keywords):
                print(f"Header detected and skipped: {first_row[0]}")
            elif first_row and first_row[0].strip():
                escaped_string = (first_row[0].strip()
                                .replace('\\', '\\\\')
                                .replace('"', '\\"'))
                if escaped_string:
                    yara_strings.append(f'\t$s0 = "{escaped_string}"')
        except StopIteration:
            print("Empty CSV or no data")
            return ""

        string_counter = len(yara_strings)
        for row in csv_reader:
            if row and row[0]:
                sanitized_string = row[0].strip()
                if sanitized_string:
                    escaped_string = (sanitized_string
                                    .replace('\\', '\\\\')
                                    .replace('"', '\\"'))
                    yara_strings.append(f'\t$s{string_counter} = "{escaped_string}"')
                    string_counter += 1

        print(f"Valid strings found: {len(yara_strings)}")
        if not yara_strings:
            print(f"No valid strings found for {label}")
            return ""

        strings_section = "\n".join(yara_strings)
        rule = f'''rule {yara_identifier} : {label} {{
    strings:
{strings_section}
    condition:
        any of them
}}

'''
        return rule

    # Handling for text files
    lines = sanitized_content.strip().split('\n')
    string_counter = 0

    for line in lines:
        cleaned_line = line.strip()
        if cleaned_line and not cleaned_line.startswith(('#', '//')):
            escaped_line = (cleaned_line
                          .replace('\\', '\\\\')
                          .replace('"', '\\"'))
            yara_strings.append(f'\t$s{string_counter} = "{escaped_line}"')
            string_counter += 1

    print(f"Valid strings found: {len(yara_strings)}")

    if not yara_strings:
        print(f"No valid strings found for {label}")
        return ""

    strings_section = "\n".join(yara_strings)
    rule = f'''rule {yara_identifier} : {label} {{
    strings:
{strings_section}
    condition:
        any of them
}}

'''
    return rule


# Step 3: Compilation and Storage
def compile_and_save_yara_rules(rules_dict, output_directory="../output",
                               filename="compiled_rules.yar"):
    """
    Compiles and saves YARA rules.

    Args:
        rules_dict (dict): A dictionary with YARA rule syntax strings.
        output_directory (str): The path to the output directory.
        filename (str): The name of the output file.

    Returns:
        bool: True if the process was successful, False otherwise.
    """
    print(f"\n{'='*60}")
    print("COMPILING AND SAVING YARA RULES")
    print(f"{'='*60}")

    if not rules_dict:
        print("ERROR: No rules to compile")
        return False

    if not os.path.exists(output_directory):
        os.makedirs(output_directory)
        print(f"Directory created: {output_directory}")

    valid_rules = []
    for label, rule_text in rules_dict.items():
        if rule_text and rule_text.strip():
            valid_rules.append(rule_text)
            print(f"Valid rule included: {label}")
        else:
            print(f"Empty rule omitted: {label}")

    if not valid_rules:
        print("ERROR: No valid rules to save")
        return False

    combined_rules = "\n".join(valid_rules)
    combined_rules = re.sub(r'[\x00]', '', combined_rules)
    output_file = os.path.join(output_directory, filename)

    print("\nSUMMARY:")
    print(f"   Valid rules: {len(valid_rules)}")
    print(f"   Total size: {len(combined_rules):,} characters")
    print(f"   Destination file: {output_file}")

    try:
        with open(output_file, 'w', encoding='utf-8') as output_handle:
            output_handle.write(combined_rules)

        if os.path.exists(output_file):
            file_size = os.path.getsize(output_file)
            print("\nFILE SAVED SUCCESSFULLY!")
            print(f"   Location: {os.path.abspath(output_file)}")
            print(f"   Size: {file_size:,} bytes")
            print(f"   Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            print("ERROR: The file was not created")
            return False

        if YARA_AVAILABLE:
            print("\nValidating YARA syntax...")
            try:
                compiled_rules = yara.compile(source=combined_rules)
                print("Valid YARA syntax - Rules compiled correctly")

                compiled_file = output_file.replace('.yar', '_compiled.yar')
                compiled_rules.save(compiled_file)
                print(f"Compiled version saved: {compiled_file}")

            except yara.SyntaxError as syntax_error:
                print(f"YARA syntax error: {syntax_error}")
                print("Text file saved for manual review")
            except Exception as compilation_error:
                print(f"Compilation error: {compilation_error}")
                print("Text file saved correctly")
        else:
            print("yara-python not available - Only text file was saved")

        print("\nSample of the generated file:")
        with open(output_file, 'r', encoding='utf-8') as sample_file:
            lines = sample_file.readlines()[:15]
            for i, line in enumerate(lines, 1):
                print(f"   {i:2d}: {line.rstrip()}")
            if len(lines) >= 15:
                print("   ...")

        return True

    except Exception as general_error:
        import traceback
        print(f"UNEXPECTED ERROR: {general_error}")
        traceback.print_exc()
        return False

# Step 4: Main execution functions
def main_execution_with_output(input_directory, output_directory):
    """
    Main function that executes the entire process with specified output directory.

    Args:
        input_directory (str): Path to the directory with input files.
        output_directory (str): Path to the output directory for compiled rules.
    """
    print("STARTING FULL YARA GENERATION PROCESS")
    print("="*60)

    # 1. Load data
    print("\n1. LOADING DATA...")
    raw_data = load_data_and_handle_encoding(input_directory)

    if not raw_data:
        print("No data loaded. Process terminated.")
        return False

    print(f"Files loaded: {list(raw_data.keys())}")

    # 2. Generate YARA rules
    print("\n2. GENERATING YARA RULES...")
    yara_rules_dict = {}

    for label, content in raw_data.items():
        rule_text = generate_yara_rule_text(label, content)
        if rule_text:
            yara_rules_dict[label] = rule_text

    print(f"\nRules generated: {len(yara_rules_dict)}/{len(raw_data)}")

    if not yara_rules_dict:
        print("No valid rules generated. Process terminated.")
        return False

    # 3. Compile and save
    print("\n3. COMPILING AND SAVING...")
    success = compile_and_save_yara_rules(yara_rules_dict, output_directory)

    if success:
        print("\nPROCESS COMPLETED SUCCESSFULLY!")
    else:
        print("\nError in the compilation process")

    return success

def scan_file_with_yara(rules_path, target_file):
    """
    Scans a target file using a compiled YARA rule set.

    Args:
        rules_path (str): The file path to the compiled YARA rules (.yar).
        target_file (str): The path to the file to be scanned.
    """
    if not YARA_AVAILABLE:
        print("\nERROR: yara-python is not installed. Cannot perform scan.")
        return

    print(f"\n{'='*60}")
    print("🔬 PERFORMING SCAN WITH YARA")
    print(f"{'='*60}")

    if not os.path.exists(rules_path):
        print(f"ERROR: Compiled rules file not found at: {rules_path}")
        return

    if not os.path.exists(target_file):
        print(f"ERROR: Target file not found at: {target_file}")
        return

    try:
        compiled_rules = yara.compile(filepath=rules_path)
        matches = compiled_rules.match(filepath=target_file)

        if matches:
            print(f"MATCH FOUND in {target_file}!")
            for match in matches:
                print(f"   - Rule Name: {match.rule}")
                print(f"     Tags: {', '.join(match.tags)}")
                print(f"     Meta: {match.meta}")
                print("     Strings found:")
                for string_match in match.strings:
                    print(f"       - Offset: {string_match[0]}, "
                          f"Identifier: {string_match[1]}, Data: {string_match[2]}")
        else:
            print(f"No matches found in {target_file}.")

    except yara.Error as yara_error:
        print(f"YARA error during scan: {yara_error}")
    except Exception as general_error:
        print(f"An unexpected error occurred: {general_error}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate YARA rules from input files.")
    parser.add_argument("input_path", type=str,
                        help="Path to the directory with the input files.")
    parser.add_argument("output_path", type=str,
                        help="Path to the output directory for the compiled rules.")

    args = parser.parse_args()

    input_dir = args.input_path
    output_dir = args.output_path

    if not os.path.exists(input_dir):
        print(f"ERROR: Input directory not found: {input_dir}")
    else:
        main_execution_with_output(input_dir, output_dir)
