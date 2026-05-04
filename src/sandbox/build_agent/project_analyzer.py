"""
ProjectAnalyzer Agent - 项目分析器

分析项目类型，决定构建策略。
"""

import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum


class ProjectType(Enum):
    """项目类型"""
    JAVA_MAVEN = "java_maven"
    JAVA_GRADLE = "java_gradle"
    NODE_JS = "node_js"
    PYTHON = "python"
    UNKNOWN = "unknown"


@dataclass
class ProjectInfo:
    """项目信息"""
    project_type: ProjectType
    root_dir: str
    build_file: str
    build_command: List[str]
    run_command: List[str]
    port: Optional[int] = None
    main_class: Optional[str] = None
    package_name: Optional[str] = None


class ProjectAnalyzer:
    """项目分析器

    自动检测项目类型并生成构建和运行命令。
    """

    PROJECT_CONFIGS = {
        ProjectType.JAVA_MAVEN: {
            "detect_files": ["pom.xml"],
            "build_command": ["mvn", "clean", "package", "-DskipTests"],
            "run_pattern": "target/*.jar",
            "default_port": 8080,
        },
        ProjectType.JAVA_GRADLE: {
            "detect_files": ["build.gradle", "build.gradle.kts"],
            "build_command": ["gradle", "build", "-x", "test"],
            "run_pattern": "build/libs/*.jar",
            "default_port": 8080,
        },
        ProjectType.NODE_JS: {
            "detect_files": ["package.json"],
            "build_command": ["npm", "install"],
            "run_command": ["npm", "start"],
            "detect_script": "scripts.start",
            "default_port": 3000,
        },
        ProjectType.PYTHON: {
            "detect_files": ["requirements.txt", "setup.py", "pyproject.toml"],
            "build_command": ["pip", "install", "-r", "requirements.txt"],
            "detect_framework": ["Django", "Flask", "FastAPI"],
            "default_port": 8000,
        },
    }

    def __init__(self, project_root: str):
        """初始化项目分析器

        Args:
            project_root: 项目根目录
        """
        self.project_root = Path(project_root)
        self.project_info: Optional[ProjectInfo] = None

    def analyze(self) -> ProjectInfo:
        """分析项目

        Returns:
            ProjectInfo对象
        """
        print(f"[ProjectAnalyzer] Analyzing project at: {self.project_root}")

        for project_type, config in self.PROJECT_CONFIGS.items():
            for detect_file in config["detect_files"]:
                if (self.project_root / detect_file).exists():
                    print(f"[ProjectAnalyzer] Detected {project_type.value}")
                    return self._analyze_specific(project_type, config, detect_file)

        print("[ProjectAnalyzer] Unknown project type")
        return ProjectInfo(
            project_type=ProjectType.UNKNOWN,
            root_dir=str(self.project_root),
            build_file="",
            build_command=[],
            run_command=[],
        )

    def _analyze_specific(self, project_type: ProjectType, config: Dict, detect_file: str) -> ProjectInfo:
        """分析特定类型项目

        Args:
            project_type: 项目类型
            config: 配置
            detect_file: 检测文件

        Returns:
            ProjectInfo对象
        """
        root_dir = str(self.project_root)
        build_file = str(self.project_root / detect_file)

        if project_type == ProjectType.JAVA_MAVEN:
            return self._analyze_java_maven(config, build_file)
        elif project_type == ProjectType.JAVA_GRADLE:
            return self._analyze_java_gradle(config, build_file)
        elif project_type == ProjectType.NODE_JS:
            return self._analyze_node_js(config, build_file)
        elif project_type == ProjectType.PYTHON:
            return self._analyze_python(config, build_file)

        return ProjectInfo(
            project_type=project_type,
            root_dir=root_dir,
            build_file=build_file,
            build_command=config["build_command"],
            run_command=[],
        )

    def _analyze_java_maven(self, config: Dict, build_file: str) -> ProjectInfo:
        """分析Java Maven项目"""
        try:
            import shlex
            result = subprocess.run(
                f"mvn -f {shlex.quote(build_file)} help:effective-pom",
                cwd=self.project_root,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60,
            )

            main_class = self._extract_main_class(build_file)
            jar_pattern = config["run_pattern"]

            return ProjectInfo(
                project_type=ProjectType.JAVA_MAVEN,
                root_dir=str(self.project_root),
                build_file=build_file,
                build_command=config["build_command"],
                run_command=["java", "-jar", f"target/{self._find_jar(jar_pattern)}"],
                port=config["default_port"],
                main_class=main_class,
            )
        except Exception as e:
            print(f"[ProjectAnalyzer] Maven analysis error: {e}")
            return ProjectInfo(
                project_type=ProjectType.JAVA_MAVEN,
                root_dir=str(self.project_root),
                build_file=build_file,
                build_command=config["build_command"],
                run_command=["java", "-jar", "target/*.jar"],
                port=config["default_port"],
            )

    def _analyze_java_gradle(self, config: Dict, build_file: str) -> ProjectInfo:
        """分析Java Gradle项目"""
        jar_pattern = config["run_pattern"]

        return ProjectInfo(
            project_type=ProjectType.JAVA_GRADLE,
            root_dir=str(self.project_root),
            build_file=build_file,
            build_command=config["build_command"],
            run_command=["java", "-jar", f"build/libs/{self._find_jar(jar_pattern)}"],
            port=config["default_port"],
        )

    def _analyze_node_js(self, config: Dict, build_file: str) -> ProjectInfo:
        """分析Node.js项目"""
        import json

        try:
            with open(self.project_root / "package.json", "r") as f:
                pkg = json.load(f)

            start_script = pkg.get("scripts", {}).get("start", "")
            port = config["default_port"]

            env = pkg.get("env", {})
            if "PORT" in env:
                port = int(env["PORT"])

            run_command = start_script.split() if start_script else config.get("run_command", ["npm", "start"])

            return ProjectInfo(
                project_type=ProjectType.NODE_JS,
                root_dir=str(self.project_root),
                build_file=build_file,
                build_command=config["build_command"],
                run_command=run_command,
                port=port,
            )
        except Exception as e:
            print(f"[ProjectAnalyzer] Node.js analysis error: {e}")
            return ProjectInfo(
                project_type=ProjectType.NODE_JS,
                root_dir=str(self.project_root),
                build_file=build_file,
                build_command=config["build_command"],
                run_command=["npm", "start"],
                port=config["default_port"],
            )

    def _analyze_python(self, config: Dict, build_file: str) -> ProjectInfo:
        """分析Python项目"""
        port = config["default_port"]
        run_command = ["python", "-m", "uvicorn", "app:app"]

        requirements_file = self.project_root / "requirements.txt"
        if requirements_file.exists():
            try:
                content = requirements_file.read_text()
                if "django" in content.lower():
                    run_command = ["python", "manage.py", "runserver", f"0.0.0.0:{port}"]
                elif "fastapi" in content.lower() or "uvicorn" in content.lower():
                    run_command = ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", str(port)]
                elif "flask" in content.lower():
                    run_command = ["flask", "run", "--host", "0.0.0.0", "--port", str(port)]
            except Exception as e:
                print(f"[ProjectAnalyzer] Python analysis error: {e}")

        return ProjectInfo(
            project_type=ProjectType.PYTHON,
            root_dir=str(self.project_root),
            build_file=build_file,
            build_command=config["build_command"],
            run_command=run_command,
            port=port,
        )

    def _extract_main_class(self, pom_file: str) -> Optional[str]:
        """从pom.xml提取main class"""
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(pom_file)
            root = tree.getroot()

            ns = {"m": "http://maven.apache.org/POM/4.0.0"}
            main_class = root.find(".//m:mainClass", ns)
            if main_class is not None:
                return main_class.text

            properties = root.find(".//m:properties", ns)
            if properties is not None:
                for prop in properties:
                    if "main.class" in prop.tag.lower():
                        return prop.text

        except Exception:
            pass

        return None

    def _find_jar(self, pattern: str) -> str:
        """查找JAR文件"""
        pattern_path = Path(pattern)

        if pattern_path.parts:
            first_part = pattern_path.parts[0]
            if first_part in ("target", "build"):
                base_dir = self.project_root / first_part
                remaining_pattern = str(Path(*pattern_path.parts[1:]))
                if remaining_pattern.startswith("*"):
                    remaining_pattern = remaining_pattern[1:]
                for jar_file in base_dir.glob(f"*{remaining_pattern}"):
                    if jar_file.is_file():
                        return jar_file.name

        for jar_file in self.project_root.glob(f"*{pattern}"):
            if jar_file.is_file():
                return jar_file.name

        return "app.jar"

    def get_project_type(self) -> ProjectType:
        """获取项目类型"""
        if self.project_info is None:
            self.project_info = self.analyze()
        return self.project_info.project_type

    def get_build_command(self) -> List[str]:
        """获取构建命令"""
        if self.project_info is None:
            self.project_info = self.analyze()
        return self.project_info.build_command

    def get_run_command(self) -> List[str]:
        """获取运行命令"""
        if self.project_info is None:
            self.project_info = self.analyze()
        return self.project_info.run_command

    def is_supported(self) -> bool:
        """检查是否支持"""
        return self.get_project_type() != ProjectType.UNKNOWN
