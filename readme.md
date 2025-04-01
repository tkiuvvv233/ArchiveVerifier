📂 **Incremental Archive Verifier**
*A smart tool for verifying compressed file integrity with incremental checking*

[![Apache 2.0 License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)

---

## Features  
**Incremental Verification** - Only checks new/modified files
**Multi-format Support** - 7z/ZIP/RAR/001/EXE (multi-part RAR aware)
**Encrypted File Detection** - Auto-identify password-protected archives
**I18N Ready** - Bilingual UI (English/中文) with auto-detection
**Graceful Interruption** - Safe process termination with SIGINT handling
**State Tracking** - JSON-based verification records

---

## Notes
- **Windows Only**: Currently tested only on Windows systems
- **Rust Rewrite**: Planned translation to Rust for learning

---

## Quick Start  
### Requirements
- 7-Zip (`7z.exe` in PATH or specify path)

### Basic Usage
```bash
python ArchiveVerifier.py /path/to/your/directory
```

### Advanced Options
```bash
python ArchiveVerifier.py /scan/path \
  --seven-zip "C:\Custom\Path\7z.exe" \
  --exe \  # Include executable archive files
  --lang en  # Force English output \
  --output ~/ # Set the output directory for results
```

### Example
```bash
python.exe .\ArchiveVerifier.py D:\test\ -e
```

```json
{
  "target_directory": "D:\\test",
  "files": {
    "D:\\test\\archive1.7z": {
      "result": "success",
      "timestamp": 1662186157000000000
    },
    "D:\\test\\archive2.exe": {
      "result": "success",
      "timestamp": 1662181248000000000
    },
    "D:\\test\\archive3.7z": {
      "result": "failure",
      "timestamp": 1743493331033758600
    },
    "D:\\test\\archive4.7z": {
      "result": "deleted",
      "timestamp": 1662181197000000000
    },
    "D:\\test\\archive5.7z": {
      "result": "success",
      "timestamp": 1662181197000000000
    }
  }
}
```

---

## 📜 License  
This project is licensed under [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0).  
```text
Copyright 2024 Your Name

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
