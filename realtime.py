# realtime.py

def emit_update_notifications(user_id: int):
    # Import locale per evitare circular import
    from app import socketio
    from models import count_notifiche_non_lette

    count = count_notifiche_non_lette(user_id)

    socketio.emit(
        "update_notifications",
        {"count": count},
        room=f"user_{user_id}"
    )
