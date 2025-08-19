# 🔍 Generating YARA Rules from Security Indicators

## 🚀 Project Overview
This project is an automation tool to generate YARA rules from text files containing security indicators (IOCs), such as malware signatures, file names, and hashes.  
The goal is to create a **robust** and **automated** process that converts raw data sources into functional detection rules for information security.

## ⚙️ Functionality
The main script, `generate_yara_rules.py`, performs the following steps:

1. **Data Loading and Preparation**  
   Reads text files from an input folder, handles different encodings (such as UTF-8 and latin-1), and sanitizes the content to remove invalid characters.

2. **YARA Rule Generation**  
   Converts the content of each file into an individual YARA rule. Each line in the input file is transformed into a `string` within the rule.

3. **Compilation and Storage**  
   Compiles the generated rules into a single `.yar` file. Robust error handling ensures that rules with syntax errors are skipped without stopping the process.

4. **Validation**  
   Allows scanning a target file with the newly created rules to validate their functionality.

## 🛡️ Shell Script Hardening and Security Audit

To ensure the reliability and security of the automation pipeline, we conducted a thorough security audit of the create_hashes_functions.sh script. This analysis identified critical security risks and opportunities for improvement.

As a result, the following actions were taken:

* **Removal of the `eval Command:** The script's primary security risk was the use of `eval`, which posed a severe command injection vulnerability. This command has been entirely removed and replaced with a safer, more robust method.

* **Adoption of Best Practices:** The script was refactored to align with secure Bash practices. This includes adding `set -euo pipefail` to ensure the script stops on errors, quoting all variables (`"$file"`), and resetting the Internal Field Separator (`IFS`).

* **Improved Efficiency and Modularity:** The script has been rewritten to reduce its dependency on external subprocesses, such as `openssl`, `awk`, and `sed. By leveraging native Python libraries, we achieved a more efficient, portable, and maintainable solution.

These changes provide a stable and secure foundation for the project's automation process, mitigating security risks and improving overall performance.


## 📂 Project Structure

```
data_scientist_yara_project/
├── my_analysis_and_refactoring
│ ├── refactored_scripts
│  └── code_refactoring_analysis.ipynb
│  └── refactored_hashes.csv
│  └── security_audit.md
├── new_input_files/
│ ├── Adware.txt
│ ├── Backdoor.txt
│ └── ...
├── notebooks/
│ ├── data_preparation_and_modeling.ipynb
│ └── yara_rule_generation.ipynb
├── src/
│ └── generate_rules_ml.py
├── output/
│ └── compiled_rules.yar
├── venv/
└── requirements.txt
```

## 💻 Requirements
* Python 3.x  
* yara-python:  
```bash
pip install yara-python
```

## 🕹️ Usage
1. **Generate and Compile Rules**
```bash
python src/generate_yara_rules.py new_input_files output
```

2. **Generate, Compile, and Scan a File**

To validate the rules, use the --scan argument followed by the path to the file you want to scan:
```bash
python src/generate_yara_rules.py new_input_files output --scan new_input_files/Behavior.txt
```
### 🔒 Repository Configuration

This repository includes configuration files to ensure best practices for code search and security.

* **Ripgrep:** A `.ripgreprc` file has been implemented to configure efficient code searches, excluding unnecessary files and directories from the search scope.

* **Gitleaks:** A `.gitleaks.toml` file is included to scan the repository for secrets. To run Gitleaks locally and verify the configuration, it is required to install the tool using Homebrew:

    ```bash
    brew install gitleaks
    ```