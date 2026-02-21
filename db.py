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
