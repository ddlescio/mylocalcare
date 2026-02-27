from flask import current_app

def get_db_connection():
    return current_app.config["DB_CONN_FACTORY"]()

def get_cursor(conn):
    return conn.cursor()

def sql(query):
    return query

def is_postgres():
    return current_app.config.get("IS_POSTGRES", False)

def dt_sql(field):
    if is_postgres():
        return field
    return field

def insert_and_get_id(cursor, query, params):
    """
    Esegue INSERT compatibile SQLite + PostgreSQL
    e ritorna sempre l'id inserito.
    """
    from flask import current_app
    from db import sql  # se in db.py sei già dentro db, togli questa riga

    if current_app.config.get("IS_POSTGRES"):
        q = query.strip().rstrip(";") + " RETURNING id"
        cursor.execute(sql(q), params)
        row = cursor.fetchone()
        if not row:
            return None
        if isinstance(row, dict):
            return row.get("id")
        return row[0]
    else:
        cursor.execute(sql(query), params)
        return cursor.lastrowid
