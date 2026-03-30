import sqlite3, glob, os

dbs = sorted(glob.glob('state_prod_*.db'), key=os.path.getmtime, reverse=True)[:4]
for db in dbs:
    con = sqlite3.connect(db)
    tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    size = os.path.getsize(db)
    print(f'{db} ({size}b): {tables}')
    if tables:
        for t in tables:
            try:
                rows = con.execute(f'SELECT * FROM {t} LIMIT 2').fetchall()
                cols = [d[0] for d in con.execute(f'SELECT * FROM {t} LIMIT 1').description or []]
                print(f'  Table {t}: cols={cols}')
                for r in rows[:1]:
                    print(f'    Row: {str(r)[:200]}')
            except Exception as e:
                print(f'  Table {t}: err={e}')
    con.close()
