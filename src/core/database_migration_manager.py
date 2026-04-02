import os
import subprocess
from pathlib import Path

class DatabaseMigrationManager:
    _instance = None
    _alembic_dir = None
    _alembic_ini = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseMigrationManager, cls).__new__(cls)
        return cls._instance

    def initialize(self, project_root, db_url="sqlite:///provenance.db"):
        self._project_root = Path(project_root)
        self._alembic_dir = self._project_root / "alembic"
        self._alembic_ini = self._project_root / "alembic.ini"
        self._db_url = db_url
        self._setup_alembic()

    def _setup_alembic(self):
        if not self._alembic_dir.exists():
            self._init_alembic()
        self._update_alembic_ini()

    def _init_alembic(self):
        result = subprocess.run(
            ["alembic", "init", "alembic"],
            cwd=self._project_root,
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            raise Exception(f"Failed to initialize Alembic: {result.stderr}")

    def _update_alembic_ini(self):
        if self._alembic_ini.exists():
            with open(self._alembic_ini, 'r') as f:
                content = f.read()
            content = content.replace(
                "sqlalchemy.url = driver://user:pass@localhost/dbname",
                f"sqlalchemy.url = {self._db_url}"
            )
            with open(self._alembic_ini, 'w') as f:
                f.write(content)

    def create_migration(self, message):
        result = subprocess.run(
            ["alembic", "revision", "--autogenerate", "-m", message],
            cwd=self._project_root,
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            raise Exception(f"Failed to create migration: {result.stderr}")
        return result.stdout

    def run_migrations(self):
        result = subprocess.run(
            ["alembic", "upgrade", "head"],
            cwd=self._project_root,
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            raise Exception(f"Failed to run migrations: {result.stderr}")
        return result.stdout

    def get_current_revision(self):
        result = subprocess.run(
            ["alembic", "current"],
            cwd=self._project_root,
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            raise Exception(f"Failed to get current revision: {result.stderr}")
        return result.stdout.strip()

    def list_migrations(self):
        result = subprocess.run(
            ["alembic", "history"],
            cwd=self._project_root,
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            raise Exception(f"Failed to list migrations: {result.stderr}")
        return result.stdout

    def downgrade(self, revision="-1"):
        result = subprocess.run(
            ["alembic", "downgrade", revision],
            cwd=self._project_root,
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            raise Exception(f"Failed to downgrade: {result.stderr}")
        return result.stdout

database_migration_manager = DatabaseMigrationManager()
