import os
import re
import json
import signal
import hashlib
import argparse
import subprocess
import locale
import concurrent.futures
import threading
from pathlib import Path
from collections import OrderedDict

# ================== I18N Support ==================
LANG_DICT = {
    "en": {
        "terminating": "\nSafely terminating process...",
        "file_deleted": "✗ File deleted {path}",
        "new_file": "✓ New file detected {path}",
        "verifying": "Verifying {path}",
        "verify_success": "✓ Verification passed {path}",
        "encrypted_file": "🔒 Encrypted file {path}",
        "verify_fail": "✗ File corrupted {path}",
        "interrupted": "🛑 Verification interrupted {path}",
        "process_error": "! Processing error {path}: {error}",
        "files_to_verify": "\n▶ Found {total} files to verify\n",
        "dir_not_exist": "Error: Directory {path} does not exist",
        "7z_not_found": "7z.exe not found at {path}",
        "argparse_description": "Incremental compressed file verification tool",
        "argparse_directory_help": "Directory path to scan",
        "argparse_7zip_help": "Path to 7z.exe (default: %(default)s)",
        "argparse_exe_help": "Include executable files in scan",
        "argparse_lang_help": "Force output language (en/zh)",
        "argparse_output_help": "Output directory for results (default: %(default)s)",
        "argparse_threads_help": "Number of verification threads (default: %(default)s)"
    },
    "zh": {
        "terminating": "\n正在安全终止进程...",
        "file_deleted": "✗ 文件已删除 {path}",
        "new_file": "✓ 发现新文件 {path}",
        "verifying": "正在验证 {path}",
        "verify_success": "✓ 验证通过 {path}",
        "encrypted_file": "🔒 加密文件 {path}",
        "verify_fail": "✗ 文件损坏 {path}",
        "interrupted": "🛑 验证已中断 {path}",
        "process_error": "! 处理错误 {path}: {error}",
        "files_to_verify": "\n▶ 发现 {total} 个待验证文件\n",
        "dir_not_exist": "错误：目录 {path} 不存在",
        "7z_not_found": "未找到 7z.exe（路径：{path}）",
        "argparse_description": "增量式压缩文件验证工具",
        "argparse_directory_help": "需要扫描的目录路径",
        "argparse_7zip_help": "7z.exe 路径（默认：%(default)s）",
        "argparse_exe_help": "包含可执行文件扫描",
        "argparse_lang_help": "强制指定输出语言（zh/en）",
        "argparse_output_help": "结果输出目录（默认：%(default)s）",
        "argparse_threads_help": "验证线程数（默认：%(default)s）"
    }
}

class I18N:
    """Internationalization handler with automatic language detection"""
    def __init__(self):
        self.lang = self.detect_language()
    
    def detect_language(self):
        """Auto-detect system language with English default"""
        try:
            sys_lang = locale.getlocale(locale.LC_CTYPE)[0]
            if sys_lang and "Chinese" in sys_lang:
                return 'zh'
            else:
                return 'en'
        except:
            return 'en'
    
    def set_language(self, lang):
        """Manually set output language"""
        if lang in LANG_DICT:
            self.lang = lang
    
    def __call__(self, key, **kwargs):
        """Retrieve localized string with parameter substitution"""
        return LANG_DICT[self.lang][key].format(**kwargs)

LANG = I18N()  # Initialize internationalization
# ===================================================

# Global termination flag
exit_flag = False
# Dictionary to track processes across threads
current_processes = {}
# Lock for thread safety
current_processes_lock = threading.Lock()

def signal_handler(sig, frame):
    """Handle termination signals (Ctrl+C) and clean up resources"""
    global exit_flag
    print(LANG("terminating"))
    exit_flag = True
    
    # Terminate all running processes
    with current_processes_lock:
        for process in list(current_processes.values()):
            if process and process.poll() is None:
                process.terminate()

def get_dir_hash(target_dir):
    """Generate MD5 hash for directory path (first 8 characters)"""
    abs_path = str(target_dir.resolve())
    return hashlib.md5(abs_path.encode()).hexdigest()[:8]

def is_first_volume(filename):
    """Check if RAR file is the first volume in a multi-part archive"""
    name = filename.lower()
    if match := re.search(r'part(\d+)\.rar$', name):
        return int(match.group(1).lstrip('0') or '0') == 1
    return True

def scan_physical_files(directory, check_exe):
    """Scan directory for archive files and executables (if enabled)"""
    extensions = {'.zip', '.7z', '.001', '.rar'}
    if check_exe: extensions.add('.exe')
    
    found = OrderedDict()
    for f in directory.rglob('*'):
        if f.suffix.lower() in extensions:
            if f.suffix.lower() == '.rar' and not is_first_volume(f.name):
                continue
            abs_path = str(f.resolve())
            found[abs_path] = f.stat().st_mtime_ns
    return found

def merge_file_records(existing, physical):
    """Merge existing records with physical filesystem scan results"""
    merged = OrderedDict()
    
    # Process existing records
    for path, record in existing.items():
        if path not in physical:
            if existing[path]["result"] != "deleted":
                merged[path] = {
                    'result': 'deleted',
                    'timestamp': record['timestamp']
                }
                print(LANG("file_deleted", path=path))
        else:
            new_record = record.copy()
            if record['timestamp'] != physical[path]:
                new_record.update({
                    'result': 'unchecked',
                    'timestamp': physical[path]
                })
            merged[path] = new_record
    
    # Process new files
    new_files = set(physical.keys()) - set(existing.keys())
    for path in new_files:
        print(LANG("new_file", path=path))
    
    # Merge physical files
    for path, mtime in physical.items():
        if path not in merged:
            merged[path] = {
                'result': 'unchecked',
                'timestamp': mtime
            }
    
    return OrderedDict(sorted(merged.items(), key=lambda x: x[0]))

def verify_7z_availability(seven_zip_exe):
    """Validate 7-Zip executable path exists"""
    if not Path(seven_zip_exe).exists():
        raise FileNotFoundError(LANG("7z_not_found", path=seven_zip_exe))

def process_file(result_file, seven_zip_exe, file_path):
    """Validate archive file integrity using 7-Zip and update results"""
    global current_processes
    if exit_flag: return

    print(LANG("verifying", path=file_path))
    temp_file = f"{result_file}.tmp.{os.getpid()}.{threading.get_ident()}"
    
    try:
        # Run verification command
        process = subprocess.Popen(
            [seven_zip_exe, "t", "-p\"\"", file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding='utf-8',
            errors='replace'
        )
        
        # Register process in the global dictionary
        with current_processes_lock:
            current_processes[file_path] = process
            
        output, _ = process.communicate()
        
        # Parse verification results
        encrypted_keywords = {'password', 'encrypted'}
        is_encrypted = any(kw in output.lower() for kw in encrypted_keywords)
        
        # Thread-safe file update with file lock
        with threading.Lock():
            with open(result_file, 'r', encoding='utf-8') as f_in:
                data = json.load(f_in, object_pairs_hook=OrderedDict)
                
            record = data['files'].get(file_path)
            
            if record and record['result'] != 'deleted':
                if process.returncode == 0:
                    record['result'] = 'success'
                    print(LANG("verify_success", path=file_path))
                elif is_encrypted:
                    record['result'] = 'encrypted'
                    print(LANG("encrypted_file", path=file_path))
                elif not exit_flag:
                    record['result'] = 'failure'
                    print(LANG("verify_fail", path=file_path))
                else:
                    print(LANG("interrupted", path=file_path))
                
                data['files'][file_path] = record
            
            with open(temp_file, 'w', encoding='utf-8') as f_out:
                json.dump(data, f_out, indent=2, ensure_ascii=False)
        
            os.replace(temp_file, result_file)

    except Exception as e:
        print(LANG("process_error", path=file_path, error=str(e)))
        if Path(temp_file).exists():
            os.remove(temp_file)
    finally:
        # Clean up process entry
        with current_processes_lock:
            if file_path in current_processes:
                del current_processes[file_path]

def process_directory(target_dir, seven_zip_exe, check_exe, output_dir, threads=1):
    """Main processing loop for directory scanning and file verification"""
    signal.signal(signal.SIGINT, signal_handler)
    
    dir_hash = get_dir_hash(target_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    result_file = output_path / f"result_{dir_hash}.json"
    target_dir = target_dir.resolve()
    physical_files = scan_physical_files(target_dir, check_exe)

    # Initialize or load existing records
    if not result_file.exists():
        data = OrderedDict([
            ("target_directory", str(target_dir)),
            ("files", OrderedDict())
        ])
    else:
        with open(result_file, 'r', encoding='utf-8') as f:
            data = json.load(f, object_pairs_hook=OrderedDict)
    
    # Merge records
    existing_files = data.get('files', OrderedDict())
    merged_files = merge_file_records(existing_files, physical_files)
    data['files'] = merged_files
    
    # Write initial state
    with open(result_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    # Count pending files
    unchecked_files = [
        path for path, record in data['files'].items() 
        if record['result'] == 'unchecked' 
        and Path(path).exists()
    ]
    total = len(unchecked_files)
    print(LANG("files_to_verify", total=total))
    
    verify_7z_availability(seven_zip_exe)
    
    # Create a thread pool for concurrent processing
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {}
        for file_path in unchecked_files:
            if exit_flag: 
                break
            future = executor.submit(process_file, result_file, seven_zip_exe, file_path)
            futures[future] = file_path
        
        # Wait for all tasks to complete
        for future in concurrent.futures.as_completed(futures):
            if exit_flag:
                break
            file_path = futures[future]
            try:
                future.result()  # Get the result or exception
            except Exception as e:
                print(LANG("process_error", path=file_path, error=str(e)))

def main():
    """Entry point for command-line execution"""
    parser = argparse.ArgumentParser(description=LANG("argparse_description"))
    parser.add_argument("directory", help=LANG("argparse_directory_help"))
    parser.add_argument("-s", "--seven-zip", 
                      default=r"C:\Program Files\7-Zip\7z.exe",
                      help=LANG("argparse_7zip_help"))
    parser.add_argument("-e", "--exe", 
                      action="store_true",
                      help=LANG("argparse_exe_help"))
    parser.add_argument("-l", "--lang", 
                      choices=['en', 'zh'],
                      help=LANG("argparse_lang_help"))
    parser.add_argument("-o", "--output",
                      default=".",
                      help=LANG("argparse_output_help"))
    parser.add_argument("-t", "--threads",
                      type=int, 
                      default=1,
                      help=LANG("argparse_threads_help"))
    args = parser.parse_args()

    if args.lang:
        LANG.set_language(args.lang)

    target_dir = Path(args.directory).resolve()
    if not target_dir.exists():
        print(LANG("dir_not_exist", path=target_dir))
        return

    try:
        verify_7z_availability(args.seven_zip)
    except FileNotFoundError as e:
        print(str(e))
        return

    process_directory(target_dir, args.seven_zip, args.exe, args.output, args.threads)

if __name__ == "__main__":
    main()