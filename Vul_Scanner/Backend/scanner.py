import subprocess
import json
import os
import shutil


def run_static_analysis(filepath):

    os.makedirs(SCAN_ROOT,exist_ok=True)

    language = detect_language(filepath)

    if not language:
        raise Exception("Unsupported file type or language")

    prepared_source = os.path.join(SCAN_ROOT,'source')
    prepare_scan_folder(filepath, prepared_source)

    result_file = run_codeql_run(prepared_source,language)
    findings = parse_codeql_output(result_file)

    print(f"CodeQL scan completed successfully for {language}.")
    print(f"Found {len(findings)} vulnerabilities or issues.")


    return findings

LANGUAGE_MAP = {".py": "python",
                ".cpp": "cpp",
                ".c": "cpp",
                ".cc": "cpp",
                ".h": "cpp",
                ".java": "java"}
SCAN_ROOT = "\\scans\\"


def detect_language(file_or_folder):
    extensions = set()
    if os.path.isfile(file_or_folder):
        ext = os.path.splitext(file_or_folder)[1].lower()
        extensions.add(ext)
    else:
        for root, _, files in os.walk(file_or_folder):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                extensions.add(ext)
    for ext in extensions:
        if ext in LANGUAGE_MAP:
            return LANGUAGE_MAP[ext]
    return None


def prepare_scan_folder(filepath, target_folder):
    if os.path.exists(target_folder):
        shutil.rmtree(target_folder)
    os.makedirs(target_folder)

    if os.path.isfile(filepath):
        shutil.copy(str(filepath), str(os.path.join(target_folder,os.path.basename(filepath))))
    else:
        shutil.copytree(filepath, target_folder, dirs_exist_ok = True)

def run_codeql_run(source_path, language):
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(BASE_DIR,SCAN_ROOT, "\\codeql-db")
    if os.path.exists(db_path):
        shutil.rmtree(db_path)

    subprocess.run([
        "codeql", "database", "create", db_path,
        f"--language={language}",
        f"--source-root={source_path}"
    ], check=True)

    output_json = os.path.join(SCAN_ROOT, "results.sarif")

    QUERY_SUITE_PATH = {
        "python":"D:\\cql\\codeql\\qlpacks\\codeql\\python-queries\\1.6.1\\codeql-suites\\python-code-scanning.qls",
        "cpp":"D:/cql/codeql/qlpacks/codeql/cpp-queries",
        "java": "D:/cql/codeql/qlpacks/codeql/java-queries"
    }

    query_suite = QUERY_SUITE_PATH.get(language)
    subprocess.run(["codeql", "database", "analyze", db_path, query_suite, "--format=sarifv2.1.0", f"--output={output_json}"],
                   check=True)

    return output_json


def parse_codeql_output(output_json):
    with open(output_json,"r") as f:
        data = json.load(f)

    runs = data.get('runs', [])
    if not runs:
        return []
    results_data = runs[0].get("results", [])

    results = []
    for result in results_data:
        message = result['message']['text']
        filepath = result['locations'][0]['physicalLocation']['artifactLocation']['uri']
        start_line = result['locations'][0]['physicalLocation']['region'].get('startLine')
        rule_id = result.get('ruleId')

        results.append({"message":message,
                        "ruleId":rule_id,
                        "file":filepath,
                        "start_line":start_line,
                        })
    return results


if __name__ == '__main__':
    file_path = 'C:\\Users\\HC\\PycharmProjects\\CyberGuard\\Vul_Scanner\\Backend\\test.py'
    scan_res = run_static_analysis(file_path)
    for res in scan_res:
        print(res)