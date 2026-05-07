import asyncio
from pathlib import Path
from bounty.db import init_db, get_conn
from bounty.targets.manual import load_scope
from bounty.recon import recon_pipeline
from bounty.models import Target

async def main():
    db_path = Path("data/bounty.db")
    init_db(db_path)

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

    print("Starting recon pipeline (gentle intensity, ~2-3 min)...")
    await recon_pipeline(
        program_id="test-prog-001",
        targets=targets,
        intensity="gentle",
        db_path=db_path,
        scan_id="phase2-check-001",
    )
    print("Done. Check the DB now.")

asyncio.run(main())