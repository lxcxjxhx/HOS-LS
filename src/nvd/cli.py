import click
from .db.connection import NVDConnection
from .db.schema import NVDSche
from .downloader import DownloadManager
from .sync import NVDDataSync
from .query.engine import NVDQueryEngine

@click.group()
def cli():
    """NVD漏洞数据库管理系统"""
    pass

@cli.command()
def init_db():
    """初始化数据库Schema"""
    click.echo("初始化数据库...")

    try:
        conn = NVDConnection.get_instance()
        schema = NVDSche(conn)

        click.echo("创建数据库表...")
        schema.create_all_tables()

        click.echo("创建索引...")
        schema.create_all_indexes()

        click.echo("创建物化视图...")
        schema.create_materialized_view()

        click.echo("数据库初始化完成!")
    except Exception as e:
        click.echo(f"错误: {e}", err=True)
        raise

@cli.command()
@click.option('--source', type=click.Choice(['all', 'cvelistV5', 'nvd', 'cwe', 'kev', 'exploitdb', 'poc']), default='all')
@click.option('--year', type=int, help='指定年份 (用于cvelistV5)')
def download(source, year):
    """下载漏洞数据"""
    click.echo(f"下载数据源: {source}")

    manager = DownloadManager()

    if source == 'all':
        results = manager.download_all()
        for src, success in results.items():
            status = "成功" if success else "失败"
            click.echo(f"  {src}: {status}")
    else:
        success = manager.download(source)
        status = "成功" if success else "失败"
        click.echo(f"  {source}: {status}")

@cli.command()
@click.option('--source', type=click.Choice(['all', 'cvelistV5', 'nvd', 'cwe', 'kev', 'exploitdb', 'poc']), default='all')
def etl(source):
    """运行ETL处理"""
    click.echo(f"运行ETL: {source}")

    sync = NVDDataSync()

    if source == 'all':
        results = sync.sync_all()
    else:
        results = sync.sync_source(source)

    if results:
        click.echo("ETL处理完成!")
    else:
        click.echo("ETL处理失败!", err=True)

@cli.command()
@click.option('--vendor', help='厂商名称')
@click.option('--product', required=True, help='产品名称')
@click.option('--version', help='产品版本')
@click.option('--min-score', type=float, default=0.0, help='最低CVSS评分')
@click.option('--limit', type=int, default=100, help='返回结果数量')
def query(vendor, product, version, min_score, limit):
    """查询漏洞"""
    click.echo(f"查询漏洞: {product}")

    try:
        engine = NVDQueryEngine()

        if version:
            click.echo(f"  精确版本: {version}")

        results = engine.scan_product(
            vendor=vendor or '',
            product=product,
            version=version,
            min_score=min_score,
            limit=limit
        )

        if not results:
            click.echo("未找到漏洞")
            return

        click.echo(f"\n找到 {len(results)} 个漏洞:")
        click.echo("-" * 80)

        for hit in results:
            severity = hit.cvss_severity or 'N/A'
            score = f"{hit.cvss_score:.1f}" if hit.cvss_score else 'N/A'
            exploited = "[KEV]" if hit.kev_exploited else ""

            click.echo(f"{hit.cve_id} | CVSS: {score} ({severity}) {exploited}")
            click.echo(f"  描述: {hit.description[:100]}...")
            click.echo(f"  Exploits: {hit.exploit_count} | PoC Stars: {hit.max_poc_stars}")
            click.echo("-" * 80)

    except Exception as e:
        click.echo(f"查询错误: {e}", err=True)

@cli.command()
@click.option('--source', type=click.Choice(['all', 'cvelistV5', 'nvd', 'cwe', 'kev', 'exploitdb', 'poc']), default='all')
def sync(source):
    """同步数据（下载+ETL）"""
    click.echo(f"同步数据源: {source}")

    sync_manager = NVDDataSync()

    if source == 'all':
        sync_manager.sync_all()
    else:
        sync_manager.sync_source(source)

    click.echo("同步完成!")

@cli.command()
@click.option('--cve-id', required=True, help='CVE ID')
def detail(cve_id):
    """获取CVE详细信息"""
    click.echo(f"获取CVE详情: {cve_id}")

    try:
        engine = NVDQueryEngine()
        detail = engine.get_cve_detail(cve_id)

        if not detail:
            click.echo(f"未找到CVE: {cve_id}")
            return

        click.echo("\n" + "=" * 60)
        click.echo(f"CVE ID: {detail.cve_id}")
        click.echo("=" * 60)
        click.echo(f"CVSS评分: {detail.cvss_score or 'N/A'} ({detail.cvss_severity or 'N/A'})")
        click.echo(f"公开日期: {detail.published_date or 'N/A'}")
        click.echo(f"KEV已利用: {'是' if detail.kev_exploited else '否'}")
        click.echo(f"Exploit数量: {detail.exploit_count}")
        click.echo(f"PoC数量: {detail.poc_count}")

        if detail.cwe_ids:
            click.echo(f"\n关联CWE:")
            for cwe_id, cwe_name in zip(detail.cwe_ids, detail.cwe_names):
                click.echo(f"  - {cwe_id}: {cwe_name}")

        click.echo(f"\n描述:\n{detail.description}")

        exploits = engine.get_exploits(cve_id)
        if exploits:
            click.echo(f"\nExploits:")
            for exp in exploits[:5]:
                click.echo(f"  - [{exp['source']}] {exp['description'][:60]}...")

        pocs = engine.get_pocs(cve_id)
        if pocs:
            click.echo(f"\nPoCs:")
            for poc in pocs[:5]:
                click.echo(f"  - {poc['repo_url']} (★{poc['stars']})")

    except Exception as e:
        click.echo(f"错误: {e}", err=True)

if __name__ == '__main__':
    cli()
