"""Import API — file upload and project import."""
import os
import uuid
import zipfile
import tempfile
import shutil
import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, UploadFile, File, HTTPException, Form
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/import", tags=["import"])

# Directory for imported projects
IMPORT_DIR = Path(__file__).parent.parent.parent.parent / "imports"
IMPORT_DIR.mkdir(exist_ok=True)


def _count_files(directory: Path) -> int:
    """Count non-hidden, non-symlink files in a directory tree."""
    count = 0
    for root, dirs, files in os.walk(directory):
        # Skip hidden and common non-project dirs
        dirs[:] = [
            d for d in dirs
            if not d.startswith('.') and d not in ('node_modules', '__pycache__', '.git', 'dist', 'build')
        ]
        for f in files:
            if not f.startswith('.'):
                count += 1
    return count


def _get_file_extensions(directory: Path) -> dict[str, int]:
    """Count files by extension."""
    exts: dict[str, int] = {}
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('node_modules', '__pycache__', '.git')]
        for f in files:
            if not f.startswith('.'):
                ext = os.path.splitext(f)[1].lower() or '(no ext)'
                exts[ext] = exts.get(ext, 0) + 1
    return dict(sorted(exts.items(), key=lambda x: -x[1])[:10])


@router.post("/upload")
async def upload_project(
    file: UploadFile = File(...),
    project_name: Optional[str] = Form(default=None),
):
    """上传项目文件 (ZIP/TAR.GZ)，自动解压并返回项目信息。

    Supported formats: .zip, .tar.gz, .tgz
    """
    # Validate file type
    filename = file.filename or "upload"
    ext = filename.lower()
    is_zip = ext.endswith('.zip')
    is_targz = ext.endswith('.tar.gz') or ext.endswith('.tgz')

    if not (is_zip or is_targz):
        raise HTTPException(
            status_code=400,
            detail=f"不支持的文件格式: {ext}。支持: .zip, .tar.gz, .tgz"
        )

    # Create project directory
    project_id = str(uuid.uuid4())[:8]
    name = project_name or Path(filename).stem
    project_dir = IMPORT_DIR / f"{project_id}-{name}"
    project_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Save uploaded file
        temp_path = project_dir / filename
        content = await file.read()
        temp_path.write_bytes(content)

        logger.info(f"Uploaded {filename} ({len(content)} bytes) -> {project_dir}")

        # Extract
        if is_zip:
            with zipfile.ZipFile(temp_path, 'r') as zf:
                # Security: prevent path traversal
                for info in zf.infolist():
                    if info.filename.startswith('/') or '..' in info.filename:
                        raise HTTPException(status_code=400, detail="压缩包包含不安全路径")
                zf.extractall(project_dir)
            temp_path.unlink()  # Remove zip after extraction
        elif is_targz:
            import tarfile
            with tarfile.open(temp_path, 'r:gz') as tf:
                for member in tf.getmembers():
                    if member.name.startswith('/') or '..' in member.name:
                        raise HTTPException(status_code=400, detail="压缩包包含不安全路径")
                tf.extractall(project_dir)
            temp_path.unlink()

        # Count files and analyze
        total_files = _count_files(project_dir)
        ext_stats = _get_file_extensions(project_dir)

        return JSONResponse({
            "project_id": project_id,
            "project_name": name,
            "project_path": str(project_dir),
            "total_files": total_files,
            "file_extensions": ext_stats,
            "message": f"项目导入成功: {name} ({total_files} 个文件)",
        })

    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="ZIP 文件已损坏或格式不正确")
    except Exception as exc:
        # Cleanup on error
        if project_dir.exists():
            shutil.rmtree(project_dir, ignore_errors=True)
        logger.error(f"Import failed: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"导入失败: {str(exc)}")


@router.post("/local-dir")
async def import_local_dir(path: str = Form(...)):
    """通过本地目录路径导入项目。

    Validates the path exists and is a directory, then registers it.
    """
    dir_path = Path(path)

    if not dir_path.exists():
        raise HTTPException(status_code=404, detail=f"路径不存在: {path}")
    if not dir_path.is_dir():
        raise HTTPException(status_code=400, detail=f"路径不是目录: {path}")

    # Check accessibility
    try:
        list(dir_path.iterdir())
    except PermissionError:
        raise HTTPException(status_code=403, detail=f"无权限访问: {path}")

    total_files = _count_files(dir_path)
    ext_stats = _get_file_extensions(dir_path)

    return JSONResponse({
        "project_id": str(uuid.uuid4())[:8],
        "project_name": dir_path.name,
        "project_path": str(dir_path.resolve()),
        "total_files": total_files,
        "file_extensions": ext_stats,
        "message": f"项目导入成功: {dir_path.name} ({total_files} 个文件)",
    })
