import asyncio
from pathlib import Path
from bounty.db import init_db, apply_migrations, get_conn
from bounty.targets.manual import load_scope
from bounty.recon import recon_pipeline
from bounty.models import Target
from bounty.ulid import make_ulid

async def main() -> None:
    db_path = Path("data/bounty.db")
    init_db(db_path)
    apply_migrations(db_path)

    scope_yaml = Path("data/test_scope.yaml")
    scope_yaml.parent.mkdir(exist_ok=True)
    scope_yaml.write_text("""
in_scope:
  - "hackerone.com"
  - "*.hackerone.com"
out_of_scope: []
wildcards_resolve: true
""")

    rules = load_scope(scope_yaml)
    print(f"Loaded scope: {list(rules.all_domains())}")

    with get_conn(db_path) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO programs (id, name, platform, handle, created_at) "
            "VALUES ('test-prog-001', 'HackerOne Self', 'manual', 'hackerone', datetime('now'))"
        )
        conn.commit()

    targets = [
        Target(
            program_id="test-prog-001",
            scope_type="in_scope",
            asset_type="wildcard",
            value=d,
        )
        for d in rules.all_domains()
    ]
    print(f"Targets: {[t.value for t in targets]}")

    # scan_id is a ULID (TEXT); the pipeline creates the scan row automatically
    scan_id = make_ulid()
    print(f"scan_id: {scan_id}")

    print("Starting recon pipeline (gentle intensity, ~2-3 min)...")
    result = await recon_pipeline(
        program_id="test-prog-001",
        targets=targets,
        intensity="gentle",
        db_path=db_path,
        scan_id=scan_id,
    )

    # Verify DB state
    with get_conn(db_path) as conn:
        asset_count = conn.execute(
            "SELECT COUNT(*) FROM assets WHERE program_id='test-prog-001'"
        ).fetchone()[0]
        scan_status = conn.execute(
            "SELECT status FROM scans WHERE id=?", (scan_id,)
        ).fetchone()

    print(f"Pipeline returned {len(result['assets'])} asset IDs.")
    print(f"Assets in DB: {asset_count}")
    print(f"Scan status: {scan_status['status'] if scan_status else 'NOT FOUND'}")

asyncio.run(main())