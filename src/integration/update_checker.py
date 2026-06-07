"""漏洞库更新检查器

实现15天周期的漏洞数据库更新检查机制。
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from src.utils.logger import get_logger

logger = get_logger("hos-ls")


class UpdateChecker:
    UPDATE_CHECK_INTERVAL_DAYS = 15
    STATE_FILE_NAME = 'update_check_state.json'

    def __init__(self, config_dir: Optional[str] = None):
        if config_dir is None:
            config_dir = str(Path.home() / '.hos-ls')
        self.config_dir = Path(config_dir)
        self.state_file = self.config_dir / self.STATE_FILE_NAME
        self.state = self._load_state()

    def _load_state(self) -> Dict:
        state_file_str = str(self.state_file)
        try:
            if self.state_file.exists():
                with open(state_file_str, 'r', encoding='utf-8') as f:
                    state = json.load(f)
                logger.debug(f"Loaded update check state from {state_file_str}")
                return state
            else:
                logger.debug("No existing state file found, initializing default state")
                return self._default_state()
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load state file: {e}, using default state")
            return self._default_state()

    def _default_state(self) -> Dict:
        return {
            "last_sync_time": None,
            "last_check_time": None,
            "last_user_response": None,
            "skip_count": 0,
            "total_cves": 0
        }

    def _save_state(self) -> None:
        state_file_str = str(self.state_file)
        try:
            self.config_dir.mkdir(parents=True, exist_ok=True)
            with open(state_file_str, 'w', encoding='utf-8') as f:
                json.dump(self.state, f, indent=4, ensure_ascii=False)
            logger.debug(f"Saved update check state to {state_file_str}")
        except IOError as e:
            logger.error(f"Failed to save state file: {e}")

    def check_update_needed(self) -> bool:
        last_sync_str = self.state.get("last_sync_time")
        if last_sync_str is None:
            logger.info("No previous sync recorded, update needed")
            return True

        try:
            last_sync_time = datetime.fromisoformat(last_sync_str)
            now = datetime.now()
            days_since = (now - last_sync_time).days
            needed = days_since >= self.UPDATE_CHECK_INTERVAL_DAYS
            logger.debug(f"Days since last sync: {days_since}, update needed: {needed}")
            return needed
        except (ValueError, TypeError) as e:
            logger.warning(f"Invalid last_sync_time format: {e}, assuming update needed")
            return True

    def prompt_user_for_update(self) -> str:
        last_sync_str = self.state.get("last_sync_time")
        days_since = 0

        if last_sync_str is not None:
            try:
                last_sync_time = datetime.fromisoformat(last_sync_str)
                days_since = (datetime.now() - last_sync_time).days
            except (ValueError, TypeError):
                pass

        message = f"漏洞库已 {days_since} 天未更新，是否立即更新？(y/n/skip): "

        if not self.is_interactive_mode():
            logger.info("Non-interactive mode detected, skipping user prompt")
            return 'skip'

        try:
            response = input(message).strip().lower()
            if response in ('y', 'yes'):
                logger.info("User chose to update")
                return 'yes'
            elif response in ('n', 'no'):
                logger.info("User chose not to update")
                return 'no'
            elif response == 'skip':
                logger.info("User chose to skip update check")
                return 'skip'
            else:
                logger.warning(f"Unrecognized response: {response}, defaulting to 'no'")
                return 'no'
        except (EOFError, KeyboardInterrupt):
            logger.warning("Input interrupted, defaulting to 'no'")
            return 'no'

    def get_last_sync_info(self) -> Dict:
        last_sync_str = self.state.get("last_sync_time")
        days_since_sync = 0

        if last_sync_str is not None:
            try:
                last_sync_time = datetime.fromisoformat(last_sync_str)
                days_since_sync = (datetime.now() - last_sync_time).days
            except (ValueError, TypeError):
                pass

        return {
            "last_sync_time": last_sync_str,
            "days_since_sync": days_since_sync,
            "cve_count": self.state.get("total_cves", 0)
        }

    def mark_checked(self, skip: bool = False) -> None:
        now_str = datetime.now().isoformat()
        self.state["last_check_time"] = now_str

        if skip:
            self.state["skip_count"] = self.state.get("skip_count", 0) + 1
            self.state["last_user_response"] = 'skip'
            logger.info("Marked update check as skipped")
        else:
            self.state["last_check_time"] = now_str
            self.state["last_sync_time"] = now_str
            self.state["last_user_response"] = 'yes'
            logger.info("Marked update check as completed")

        self._save_state()

    def is_interactive_mode(self) -> bool:
        ci_env_vars = ['CI', 'GITHUB_ACTIONS', 'JENKINS_URL']
        for env_var in ci_env_vars:
            if os.environ.get(env_var):
                logger.debug(f"CI environment detected: {env_var}")
                return False

        is_tty = sys.stdin.isatty()
        logger.debug(f"Interactive mode (stdin.isatty()): {is_tty}")
        return is_tty
