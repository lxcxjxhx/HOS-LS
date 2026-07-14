#!/usr/bin/env python3
"""修复F541: f-string无占位符问题"""
import os
import re
from pathlib import Path


def fix_f541_in_file(filepath):
    """修复单个文件中的f-string问题"""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        # 匹配f"..."或f'...'，检查是否包含{...}
        def replace_fstring(match):
            quote = match.group(1)
            content = match.group(2)
            # 如果内容中没有{...}占位符，移除f前缀
            if "{" not in content or re.search(r"\{\s*\}", content):
                return f"{quote}{content}{quote}"
            return match.group(0)

        # 匹配f"..."或f'...'
        pattern = r'f(["\'])(.*?)\1'
        new_content = re.sub(pattern, replace_fstring, content)

        if new_content != content:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(new_content)
            return True
        return False
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False


def main():
    """主函数"""
    src_dir = Path("src")
    fixed_count = 0

    for py_file in src_dir.rglob("*.py"):
        if fix_f541_in_file(py_file):
            fixed_count += 1
            print(f"Fixed: {py_file}")

    print(f"\nTotal files fixed: {fixed_count}")


if __name__ == "__main__":
    main()
