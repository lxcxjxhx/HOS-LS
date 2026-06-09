"""Star Map API — code graph and vulnerability topology visualization."""

from fastapi import APIRouter

from src.web.models import StarMapEdge, StarMapNode, StarMapResponse
from src.web.schemas import StarMapRequest
from src.web.api.tasks import list_tasks

router = APIRouter(prefix="/star-map", tags=["star-map"])


@router.get("", response_model=StarMapResponse)
@router.post("", response_model=StarMapResponse)
async def get_star_map(request: StarMapRequest = None) -> StarMapResponse:
    """获取星图数据 — 从真实扫描任务结果中生成"""
    nodes: list[StarMapNode] = []
    edges: list[StarMapEdge] = []
    seen_files: dict[str, str] = {}  # file_path -> node_id

    # Collect findings from all completed scan tasks
    all_tasks = list_tasks()
    for task in all_tasks:
        if task.status.value not in ("completed", "running"):
            continue
        if task.type != "scan" or not task.result:
            continue

        findings = task.result.get("findings", [])
        if not findings:
            continue

        task_node_id = f"task-{task.task_id[:8]}"
        nodes.append(StarMapNode(
            id=task_node_id,
            label=f"扫描任务 {task.task_id[:8]}",
            type="task",
        ))

        for i, finding in enumerate(findings):
            # File node
            file_path = finding.get("file_path", finding.get("file", "unknown"))
            if file_path not in seen_files:
                file_node_id = f"file-{len(seen_files)}"
                seen_files[file_path] = file_node_id
                nodes.append(StarMapNode(
                    id=file_node_id,
                    label=file_path,
                    type="file",
                ))
                edges.append(StarMapEdge(
                    id=f"edge-task-file-{len(edges)}",
                    source=task_node_id,
                    target=file_node_id,
                    relation="scanned",
                ))

            # Vulnerability node
            vuln_node_id = f"vuln-{len(nodes)}"
            rule_id = finding.get("rule_id", finding.get("rule", "unknown"))
            title = finding.get("title", finding.get("message", rule_id))
            severity = finding.get("severity", "info")
            nodes.append(StarMapNode(
                id=vuln_node_id,
                label=title,
                type="vulnerability",
                severity=severity,
            ))
            edges.append(StarMapEdge(
                id=f"edge-vuln-file-{len(edges)}",
                source=vuln_node_id,
                target=seen_files[file_path],
                relation="found_in",
            ))

    if not nodes:
        # No scan results yet
        return StarMapResponse(nodes=[], edges=[])

    return StarMapResponse(
        nodes=nodes,
        edges=edges,
        total_nodes=len(nodes),
        total_edges=len(edges),
    )
