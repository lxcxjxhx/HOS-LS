from flask import request


def vulnerable_query(cursor):
    query = "SELECT * FROM users WHERE id=" + request.args.get("id")
    return cursor.execute(query)
