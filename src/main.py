import os
import hashlib
from datetime import datetime
import csv
import sys


def calculate_hashes(file_path):
    # Create hash objects
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    # Read the file in chunks to handle larger files
    with open(file_path, "rb") as file:
        while True:
            data = file.read(4096)

            if not data:
                break

            md5_hash.update(data)
            sha1_hash.update(data)
            sha256_hash.update(data)

    return (
        md5_hash.hexdigest(),
        sha1_hash.hexdigest(),
        sha256_hash.hexdigest()
    )

def check_file_signature(file_path):
    # Known file signatures
    signatures = {
        b"\xFF\xD8\xFF": "JPEG",
        b"\x89PNG": "PNG",
        b"%PDF-": "PDF",
        b"PK\x03\x04": "ZIP"
    }

    # Read the first 8 bytes of the file
    with open (file_path, "rb") as file: 
        header = file.read(8)

    # Compare the header against known signatures
    for signature, file_type in signatures.items():
        if header.startswith(signature):
            return file_type
    
    return "Unknown"

def check_extension(file_path, detected_type):
    # Expected extensions for supported file types
    expected_extensions = {
        "JPEG": [".jpg", ".jpeg"],
        "PNG": [".png"],
        "PDF": [".pdf"],
        "ZIP": [".zip"]
    }

    extension = os.path.splitext(file_path)[1].lower()

    # Unknown signatures cannot be reliably checked
    if detected_type == "Unknown":
        return "Unknown File Type"
    
    if extension in expected_extensions.get(detected_type, []):
        return "Normal"
    
    return "WARNING: Extension Mismatch"

def analyze_file(file_path):
    print("\n----- FILE ANALYSIS -----")

    file_name = os.path.basename(file_path)
    file_extension = os.path.splitext(file_name)[1]
    file_size = os.path.getsize(file_path)

    modification_time = os.path.getmtime(file_path)
    readable_time = datetime.fromtimestamp(modification_time)

    # Calculate hashes
    md5, sha1, sha256 = calculate_hashes(file_path)

    # Analyze signature and extension
    detected_type = check_file_signature(file_path)
    status = check_extension(file_path, detected_type)

    # Display results
    print(f"File Name: {file_name}")
    print(f"File Extension: {file_extension}")
    print(f"File Size: {file_size} bytes")
    print(f"Last Modified: {readable_time}")

    print("\n----- CRYPTOGRAPHIC HASHES -----")
    print(f"MD5: {md5}")
    print(f"SHA-1: {sha1}")
    print(f"SHA-256: {sha256}")

    print("\n----- FILE SIGNATURE ANALYSIS -----")
    print(f"Detected File Type: {detected_type}")
    print(f"Status: {status}")

    # Return results for CSV reporting
    return {
        "File Name": file_name,
        "File Path": os.path.abspath(file_path),
        "Extension": file_extension,
        "Size (Bytes)": file_size,
        "Last Modified": str(readable_time),
        "MD5": md5,
        "SHA-1": sha1,
        "SHA-256": sha256,
        "Detected Type": detected_type,
        "Status": status
    }

def generate_report(results):
    output_path = "output/forensic_report.csv"

    os.makedirs("output", exist_ok=True)

    with open(output_path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file, 
            fieldnames=results[0].keys()
        )

        writer.writeheader()
        writer.writerows(results)

    print(f"\nReport generated: {output_path}")

def main():
    print("===================================")
    print("   FORENSIC EVIDENCE ANALYZER")
    print("===================================")

    # Allow the user to specify evidence folder
    if len(sys.argv) > 2:
        print("ERROR: Too many arguments.")
        print("Usage: py src/main.py [evidence_folder]")
        return

    if len(sys.argv) == 2:
        evidence_folder = sys.argv[1]
    else:
        evidence_folder = "data/sample_evidence"

    results = []

    print(f"\nEvidence Directory: {evidence_folder}")

    if not os.path.isdir(evidence_folder):
        print("ERROR: Evidence folder not found.")
        return

    for file_name in sorted(os.listdir(evidence_folder)):
        file_path = os.path.join(evidence_folder, file_name)

        if os.path.isfile(file_path):
            try:
                result = analyze_file(file_path)
                results.append(result)
            except OSError as error:
                print(f"ERROR analyzing {file_name}: {error}")

    if results:
        generate_report(results)
        print(f"\nAnalysis complete. Files analyzed: {len(results)}")
    else:
        print("No files were successfully analyzed.")

if __name__ == "__main__":
    main()