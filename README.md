Forensic Evidence Analyzer

Project Overview

The Forensic Evidence Analyzer is a Python-based digital forensics tool developed for the IT 360 Final Project at Illinois State University.

The program analyzes files within a specified directory and extracts forensic information, including file metadata, cryptographic hashes, and file signatures. It can identify potential file extension mismatches and generate a CSV report containing the results.

Features

  - File Metadata Extraction: Retrieves file names, extensions, sizes, and modification               timestamps.
  - Cryptographic Hashing: Calculates MD5, SHA-1, and SHA-256 hashes.
  - File Signature Analysis: Identifies JPEG, PNG, PDF, and ZIP file signatures.
  - Extension Mismatch Detection: Flags files whose extensions do not match their detected            formats.
  - Directory Analysis: Analyzes multiple files within a specified folder.
  - CSV Reporting: Generates a report containing the forensic findings.
  - Basic Error Handling: Handles missing directories, empty folders, and file access errors.

Requirements

  -Python 3
  -Windows, Linux, or macOS
  -No external Python libraries required

Installation

  1. Download or clone this repository.
  2. Open a terminal or PowerShell window.
  3. Navigate to the project directory.
  4. Verify that Python 3 is installed.

Usage

  To analyze the default sample evidence directory:
        py src/main.py
  To specify a different directory:
        py src/main.py "C:\Evidence"
  On systems without the Windows Python launcher, use python3 instead of py.

Output

  The program generates a CSV report at:
        output/forensic_report.csv

The report contains:

  - File name and absolute path
  - File extension
  - File size
  - Last modification timestamp
  - MD5, SHA-1, and SHA-256 hashes
  - Detected file type
  - Extension verification status

Limitations

  - File signature detection currently supports JPEG, PNG, PDF, and ZIP.
  - Files with unrecognized signatures are classified as Unknown.
  - The program analyzes files directly within the selected directory, not nested subdirectories.
  - File extension mismatches do not necessarily indicate malicious activity.
  - The program is intended for educational forensic analysis and is not a replacement for            professional forensic software.

Video Demonstration

    Presentation video: Coming soon.

Author

HenryB999

IT 360 - Digital Forensics Final Project

Illinois State University
