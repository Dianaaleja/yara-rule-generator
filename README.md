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

## 📂 Project Structure

```
data_scientist_yara_project/
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
