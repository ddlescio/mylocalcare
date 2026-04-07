from flask import session, request
from flask_socketio import join_room, leave_room

from socket_registry import (
    _bump_offline_token,
    _touch_socket_sid,
    _cleanup_user_socket_set,
    _get_user_id_from_sid,
    _remove_socket_sid,
    _get_offline_token,
    _socket_user_set_key,
    _decode_redis_value,
)

offline_watchdogs = {}

from realtime_auth import parse_realtime_token

def register_socket_lifecycle_handlers(socketio, redis_client, chat_count_unread):
    @socketio.on("connect")
    def handle_connect(auth=None):
        user_id = session.get("utente_id")

        token_user_id = None
        token = None

        if isinstance(auth, dict):
            token = (auth.get("token") or "").strip() or None
            if token:
                token_user_id = parse_realtime_token(token)

        if not user_id and token_user_id:
            user_id = token_user_id

        try:
            print("🧪 [SOCKET CONNECT DEBUG] START")
            print(f"🧪 sid={request.sid}")
            print(f"🧪 host={request.host}")
            print(f"🧪 origin={request.headers.get('Origin')}")
            print(f"🧪 referer={request.headers.get('Referer')}")
            print(f"🧪 cookie_header_present={bool(request.headers.get('Cookie'))}")
            print(f"🧪 cookie_header={request.headers.get('Cookie')}")
            print(f"🧪 session_keys={list(session.keys())}")
            print(f"🧪 session_utente_id={session.get('utente_id')}")
            print(f"🧪 token_user_id={token_user_id}")
            print(f"🧪 auth={auth}")
        except Exception as e:
            print(f"❌ [SOCKET CONNECT DEBUG] errore debug iniziale: {e}")

        if not user_id:
            print("❌ [SOCKET CONNECT DEBUG] connect rifiutato: nessuna auth valida")
            return False

        sid = request.sid
        room = f"user_{user_id}"
        client_id = None
        if isinstance(auth, dict):
            client_id = (auth.get("client_id") or "").strip() or None

        _bump_offline_token(user_id)
        redis_client.sadd("online_users", str(user_id))
        _touch_socket_sid(user_id, sid, client_id=client_id)

        join_room(room, sid=sid)

        count = _cleanup_user_socket_set(user_id)

        print(f"🟢 Socket connesso utente {user_id} SID {sid} | socket attivi reali: {count}")

        try:
            unread = chat_count_unread(user_id)

            socketio.emit(
                "update_unread_count",
                {"count": unread},
                to=sid,
                namespace="/"
            )

            print(
                f"📨 unread iniziale inviato solo al SID corrente "
                f"user={user_id} sid={sid} count={unread}"
            )

        except Exception as e:
            print("Errore invio unread count al SID corrente:", e)

    @socketio.on("socket_heartbeat")
    def handle_socket_heartbeat():
        user_id = session.get("utente_id")
        sid = request.sid

        if not user_id or not sid:
            return

        now_ts = __import__("time").time()
        now_ts = int(now_ts)

        from socket_registry import (
            _socket_sid_key,
            _get_client_id_from_sid,
            _socket_client_key,
        )

        sid_key = _socket_sid_key(sid)

        if not redis_client.exists(sid_key):
            return

        client_id = _get_client_id_from_sid(sid)

        pipe = redis_client.pipeline()

        pipe.hset(sid_key, mapping={
            "user_id": str(user_id),
            "client_id": client_id or "__NONE__",
            "last_seen": str(now_ts)
        })
        pipe.expire(sid_key, 75)

        if client_id:
            client_key = _socket_client_key(user_id, client_id)
            mapped_sid_raw = redis_client.get(client_key)
            mapped_sid = _decode_redis_value(mapped_sid_raw) if mapped_sid_raw else None

            if mapped_sid == sid:
                pipe.expire(client_key, 75)

        pipe.execute()

    @socketio.on("disconnect")
    def handle_disconnect():
        sid = request.sid

        user_id = _get_user_id_from_sid(sid)

        if not user_id:
            user_id = session.get("utente_id")

        if not user_id:
            print(f"⚠️ Disconnect senza user_id per SID {sid}")
            return

        try:
            leave_room(f"user_{user_id}", sid=sid)
        except Exception:
            pass

        try:
            _remove_socket_sid(user_id, sid)

            remaining = _cleanup_user_socket_set(user_id)

            print(f"🔌 Socket chiusa utente {user_id} SID {sid} | rimaste reali: {remaining}")

            if remaining <= 0:
                print(f"🕐 Utente {user_id} senza socket → delay check")
                _bump_offline_token(user_id)
                ensure_offline_watchdog(socketio, redis_client, user_id)

        except Exception as e:
            print("Errore disconnect:", e)


def ensure_offline_watchdog(socketio, redis_client, user_id):
    if user_id in offline_watchdogs:
        return

    task = socketio.start_background_task(_offline_watchdog_loop, socketio, redis_client, user_id)
    offline_watchdogs[user_id] = task


def _offline_watchdog_loop(socketio, redis_client, user_id):
    try:
        while True:
            token_before_sleep = _get_offline_token(user_id)

            socketio.sleep(30)

            token_after_sleep = _get_offline_token(user_id)
            if token_after_sleep != token_before_sleep:
                print(f"⏭️ Skip offline stale per utente {user_id} (token cambiato durante attesa)")
                continue

            remaining = _cleanup_user_socket_set(user_id)

            token_after_cleanup = _get_offline_token(user_id)
            if token_after_cleanup != token_before_sleep:
                print(f"⏭️ Skip offline stale post-cleanup per utente {user_id}")
                continue

            if remaining == 0:
                redis_client.delete(_socket_user_set_key(user_id))
                redis_client.srem("online_users", str(user_id))
                print(f"🔴 Utente {user_id} OFFLINE (cleanup delayed)")
            else:
                print(f"⏭️ Utente {user_id} ancora attivo ({remaining} socket reali)")

            break

    finally:
        offline_watchdogs.pop(user_id, None)
