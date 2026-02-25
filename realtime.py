# realtime.py

_socketio = None

def init_realtime(socketio_instance):
    global _socketio
    _socketio = socketio_instance

def emit_update_notifications(user_id: int):
    if not _socketio:
        return

    _socketio.emit(
        "update_notifications",
        {},  # payload non necessario perché il frontend fa fetch
        room=f"user_{user_id}"
    )
