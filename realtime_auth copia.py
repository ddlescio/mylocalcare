from flask import current_app
from itsdangerous import URLSafeSerializer


def get_realtime_serializer():
    return URLSafeSerializer(
        current_app.config["SECRET_KEY"],
        salt="realtime-socket-auth"
    )


def build_realtime_token(user_id):
    return get_realtime_serializer().dumps({
        "utente_id": int(user_id)
    })


def parse_realtime_token(token):
    try:
        data = get_realtime_serializer().loads(token)
        user_id = int(data.get("utente_id"))
        return user_id
    except Exception:
        return None
