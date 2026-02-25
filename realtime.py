# realtime.py
from app import socketio, count_notifiche_non_lette

def emit_update_notifications(user_id: int):
    count = count_notifiche_non_lette(user_id)

    socketio.emit(
        "update_notifications",
        {"count": count},
        room=f"user_{user_id}"
    )
