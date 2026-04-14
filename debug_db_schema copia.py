import sqlite3
from pathlib import Path

DB_PATH = Path("database.db")

def row_to_dict(r):
    return {k: r[k] for k in r.keys()}

def print_header(title: str):
    print("\n" + "=" * 90)
    print(title)
    print("=" * 90)

def main():
    if not DB_PATH.exists():
        print(f"❌ DB non trovato: {DB_PATH.resolve()}")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    print_header(f"SQLite DB: {DB_PATH.resolve()}")

    # Elenco tabelle (escludo tabelle interne sqlite_*)
    cur.execute("""
        SELECT name, sql
        FROM sqlite_master
        WHERE type='table'
          AND name NOT LIKE 'sqlite_%'
        ORDER BY name;
    """)
    tables = cur.fetchall()

    if not tables:
        print("⚠️ Nessuna tabella trovata.")
        return

    print("📌 Tabelle trovate:")
    for t in tables:
        print(f" - {t['name']}")

    for t in tables:
        table = t["name"]
        print_header(f"TABELLA: {table}")

        # CREATE SQL
        print("🧱 CREATE TABLE:")
        print(t["sql"] or "(sql non disponibile)")

        # Colonne
        print("\n🧾 PRAGMA table_info:")
        cur.execute(f"PRAGMA table_info({table});")
        cols = [row_to_dict(r) for r in cur.fetchall()]
        if not cols:
            print("  (nessuna colonna?)")
        else:
            # table_info: cid, name, type, notnull, dflt_value, pk
            for c in cols:
                print(
                    f"  - {c['name']:<24} {c['type']:<12} "
                    f"NOTNULL={c['notnull']} DEFAULT={c['dflt_value']} PK={c['pk']}"
                )

        # Foreign keys
        print("\n🔗 PRAGMA foreign_key_list:")
        cur.execute(f"PRAGMA foreign_key_list({table});")
        fks = [row_to_dict(r) for r in cur.fetchall()]
        if not fks:
            print("  (nessuna foreign key)")
        else:
            for fk in fks:
                # fk: id, seq, table, from, to, on_update, on_delete, match
                print(
                    f"  - from '{fk['from']}' -> {fk['table']}('{fk['to']}') "
                    f"ON UPDATE {fk['on_update']} ON DELETE {fk['on_delete']} MATCH {fk['match']}"
                )

        # Indici
        print("\n📇 PRAGMA index_list:")
        cur.execute(f"PRAGMA index_list({table});")
        idxs = [row_to_dict(r) for r in cur.fetchall()]
        if not idxs:
            print("  (nessun indice)")
        else:
            for idx in idxs:
                # index_list: seq, name, unique, origin, partial
                idx_name = idx["name"]
                print(f"  - {idx_name} (UNIQUE={idx['unique']} ORIGIN={idx['origin']} PARTIAL={idx['partial']})")

                cur.execute(f"PRAGMA index_info({idx_name});")
                idx_cols = [row_to_dict(r) for r in cur.fetchall()]
                if idx_cols:
                    cols_str = ", ".join([ic["name"] for ic in idx_cols if ic.get("name")])
                    print(f"      colonne: {cols_str}")

        # Trigger (se presenti)
        print("\n⚙️ Trigger collegati:")
        cur.execute("""
            SELECT name, sql
            FROM sqlite_master
            WHERE type='trigger'
              AND tbl_name = ?
            ORDER BY name;
        """, (table,))
        triggers = cur.fetchall()
        if not triggers:
            print("  (nessun trigger)")
        else:
            for tr in triggers:
                print(f"  - {tr['name']}")
                print(f"    {tr['sql']}")

    conn.close()
    print_header("FINE")

if __name__ == "__main__":
    main()
