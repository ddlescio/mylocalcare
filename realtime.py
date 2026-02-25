# realtime.py
_socketio = None

def init_realtime(socketio_instance):
    global _socketio
    _socketio = socketio_instance

def emit_update_notifications(user_id: int):
    if not _socketio:
        return

    # import locale per evitare circular
    from app import conta_non_lette

    count = conta_non_lette(user_id)

    _socketio.emit(
        "update_notifications",
        {"count": count},
        room=f"user_{user_id}"
    )
