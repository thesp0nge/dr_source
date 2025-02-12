# dr_source/core/codebase.py
import os


class FileObject:
    def __init__(self, path, content):
        self.path = path
        self.content = content


class Codebase:
    def __init__(self, root_path):
        self.root_path = root_path
        self.files = []

    def load_files(self):
        for root, _, files in os.walk(self.root_path):
            for file in files:
                if file.endswith(".java") or file.endswith(".jsp"):
                    file_path = os.path.join(root, file)
                    try:
                        with open(
                            file_path, "r", encoding="utf-8", errors="ignore"
                        ) as f:
                            content = f.read()
                        self.files.append(FileObject(file_path, content))
                    except Exception as e:
                        print(f"Error reading {file_path}: {e}")
        return self.files
