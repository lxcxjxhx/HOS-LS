import os
import subprocess
from pathlib import Path
import logging

class RepositoryManager:
    _instance = None
    _git_available = False
    _repo_root = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(RepositoryManager, cls).__new__(cls)
        return cls._instance

    def initialize(self, project_path):
        self._project_path = Path(project_path)
        self._check_git_available()
        self._detect_repo_root()

    def _check_git_available(self):
        try:
            result = subprocess.run(
                ["git", "--version"],
                capture_output=True,
                text=True
            )
            self._git_available = result.returncode == 0
        except Exception:
            self._git_available = False

    def _detect_repo_root(self):
        if not self._git_available:
            return

        try:
            result = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                cwd=self._project_path,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                self._repo_root = Path(result.stdout.strip())
        except Exception:
            pass

    def is_git_repo(self):
        return self._git_available and self._repo_root is not None

    def get_repo_root(self):
        return self._repo_root

    def initialize_repo(self):
        if not self._git_available:
            return False

        try:
            result = subprocess.run(
                ["git", "init"],
                cwd=self._project_path,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                self._detect_repo_root()
                logging.info("Initialized Git repository in test environment")
                return True
        except Exception as e:
            logging.error(f"Failed to initialize Git repository: {e}")
        return False

    def get_changed_files(self):
        if not self.is_git_repo():
            return []

        try:
            # Get modified files
            diff_result = subprocess.run(
                ["git", "diff", "--name-only"],
                cwd=self._repo_root,
                capture_output=True,
                text=True
            )
            
            # Get untracked files
            status_result = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=self._repo_root,
                capture_output=True,
                text=True
            )

            changed_files = set()
            
            # Process diff output
            if diff_result.returncode == 0:
                for line in diff_result.stdout.strip().split('\n'):
                    if line:
                        changed_files.add(str(self._repo_root / line))
            
            # Process status output for untracked files
            if status_result.returncode == 0:
                for line in status_result.stdout.strip().split('\n'):
                    if line.startswith('??'):
                        file_path = line[3:].strip()
                        changed_files.add(str(self._repo_root / file_path))
            
            return list(changed_files)
        except Exception as e:
            logging.error(f"Failed to get changed files: {e}")
            return []

    def get_all_files(self, extensions=None):
        all_files = []
        for root, dirs, files in os.walk(self._project_path):
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                if extensions:
                    if any(file.endswith(ext) for ext in extensions):
                        all_files.append(str(Path(root) / file))
                else:
                    all_files.append(str(Path(root) / file))
        return all_files

    def should_use_incremental_scan(self):
        return self.is_git_repo()

repository_manager = RepositoryManager()
