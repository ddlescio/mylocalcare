import time

redis_client = None
socketio = None

SOCKET_TTL_SECONDS = 75   # heartbeat ogni 20s -> TTL largo e sicuro


def configure_socket_registry(redis_instance, socketio_instance):
    global redis_client, socketio
    redis_client = redis_instance
    socketio = socketio_instance


def _ensure_ready():
    if redis_client is None:
        raise RuntimeError("socket_registry: redis_client non configurato")
    if socketio is None:
        raise RuntimeError("socket_registry: socketio non configurato")


def _socket_user_set_key(user_id):
    return f"user_sockets:{user_id}"


def _socket_sid_key(sid):
    return f"socket_sid:{sid}"


def _socket_room_name(sid):
    return f"sock:{sid}"


def _socket_client_key(user_id, client_id):
    return f"user_socket_client:{user_id}:{client_id}"


def _socket_offline_token_key(user_id):
    return f"user_offline_token:{user_id}"


def _chat_open_key(user_id):
    return f"chat_open:{user_id}"


def set_open_chat(user_id, other_id, ttl=300):
    _ensure_ready()
    redis_client.set(_chat_open_key(user_id), str(other_id), ex=ttl)


def get_open_chat(user_id):
    _ensure_ready()
    raw = redis_client.get(_chat_open_key(user_id))
    if not raw:
        return None
    try:
        return int(_decode_redis_value(raw))
    except Exception:
        return None


def clear_open_chat(user_id):
    _ensure_ready()
    redis_client.delete(_chat_open_key(user_id))


def _bump_offline_token(user_id):
    _ensure_ready()
    return int(redis_client.incr(_socket_offline_token_key(user_id)))


def _get_offline_token(user_id):
    _ensure_ready()
    raw = redis_client.get(_socket_offline_token_key(user_id))
    if not raw:
        return 0
    try:
        return int(_decode_redis_value(raw))
    except Exception:
        return 0


def _decode_redis_value(value):
    if isinstance(value, bytes):
        return value.decode()
    return value


def _get_user_id_from_sid(sid):
    _ensure_ready()
    raw = redis_client.hget(_socket_sid_key(sid), "user_id")
    if not raw:
        return None
    try:
        return int(_decode_redis_value(raw))
    except Exception:
        return None


def _get_client_id_from_sid(sid):
    _ensure_ready()
    raw = redis_client.hget(_socket_sid_key(sid), "client_id")
    if not raw:
        return None

    value = _decode_redis_value(raw).strip()

    if not value or value == "__NONE__":
        return None

    return value


def _touch_socket_sid(user_id, sid, client_id=None):
    _ensure_ready()

    now_ts = int(time.time())
    user_set_key = _socket_user_set_key(user_id)

    pipe = redis_client.pipeline()

    if client_id:
        client_key = _socket_client_key(user_id, client_id)
        old_sid_raw = redis_client.get(client_key)
        old_sid = _decode_redis_value(old_sid_raw) if old_sid_raw else None

        if old_sid and old_sid != sid:
            print(f"♻️ Mapping client aggiornato: {old_sid} -> {sid} (client {client_id})")

        pipe.set(client_key, sid, ex=SOCKET_TTL_SECONDS)

    pipe.sadd(user_set_key, sid)

    pipe.hset(_socket_sid_key(sid), mapping={
        "user_id": str(user_id),
        "client_id": client_id if client_id else "__NONE__",
        "last_seen": str(now_ts)
    })

    pipe.expire(_socket_sid_key(sid), SOCKET_TTL_SECONDS)

    pipe.execute()


def _remove_socket_sid(user_id, sid):
    _ensure_ready()
    pipe = redis_client.pipeline()
    pipe.srem(_socket_user_set_key(user_id), sid)
    pipe.delete(_socket_sid_key(sid))
    pipe.execute()


def _cleanup_user_socket_set(user_id):
    _ensure_ready()

    key = _socket_user_set_key(user_id)
    raw_sids = redis_client.smembers(key)

    alive = 0

    for raw_sid in raw_sids:
        sid = _decode_redis_value(raw_sid)

        ttl = redis_client.ttl(_socket_sid_key(sid))

        if ttl and ttl > 0:
            alive += 1
        else:
            redis_client.srem(key, sid)
            print(f"🧹 Rimosso SID zombie {sid} da utente {user_id}")

    return alive


def _get_live_user_sids(user_id):
    _ensure_ready()

    key = _socket_user_set_key(user_id)
    raw_sids = redis_client.smembers(key)

    live_sids = []
    seen_client_ids = set()

    for raw_sid in raw_sids:
        sid = _decode_redis_value(raw_sid)
        sid_key = _socket_sid_key(sid)

        ttl = redis_client.ttl(sid_key)
        if not ttl or ttl <= 0:
            redis_client.srem(key, sid)
            print(f"🧹 Rimosso SID zombie {sid} da utente {user_id}")
            continue

        client_id = _get_client_id_from_sid(sid)

        if not client_id:
            live_sids.append(sid)
            continue

        client_key = _socket_client_key(user_id, client_id)
        mapped_sid_raw = redis_client.get(client_key)
        mapped_sid = _decode_redis_value(mapped_sid_raw) if mapped_sid_raw else None

        if mapped_sid != sid:
            print(f"⏭️ Skip SID stale {sid} per utente {user_id} (client {client_id}, corrente={mapped_sid})")
            continue

        if client_id in seen_client_ids:
            continue

        seen_client_ids.add(client_id)
        live_sids.append(sid)

    return live_sids


def emit_to_user_sids(user_id, event_name, payload, skip_sid=None):
    _ensure_ready()

    live_sids = _get_live_user_sids(user_id)

    print(
        f"📡 emit_to_user_sids -> user={user_id} "
        f"event={event_name} skip_sid={skip_sid} live_sids={live_sids}"
    )

    delivered = 0

    for sid in live_sids:
        if skip_sid and sid == skip_sid:
            print(f"⏭️ Skip SID {sid} per event={event_name}")
            continue

        try:
            socketio.emit(
                event_name,
                payload,
                to=sid,
                namespace="/"
            )
            delivered += 1
            print(f"➡️ Emit diretto via SID user={user_id} sid={sid} event={event_name}")
        except Exception as e:
            print(f"❌ Errore emit diretto user={user_id} sid={sid} event={event_name}: {e}")

    if delivered == 0:
        room_name = f"user_{user_id}"
        print(
            f"⚠️ Nessun SID vivo disponibile per user={user_id} "
            f"event={event_name} -> fallback room {room_name}"
        )

        try:
            socketio.emit(
                event_name,
                payload,
                room=room_name,
                namespace="/",
                skip_sid=skip_sid
            )
            print(f"➡️ Emit fallback su room {room_name} event={event_name}")
        except Exception as e:
            print(f"❌ Errore fallback room user={user_id} room={room_name} event={event_name}: {e}")

def emit_to_user_room(user_id, event_name, payload, skip_sid=None):
    _ensure_ready()

    room_name = f"user_{user_id}"

    socketio.emit(
        event_name,
        payload,
        room=room_name,
        namespace="/",
        skip_sid=skip_sid
    )


def is_user_online(user_id):
    _ensure_ready()
    return redis_client.sismember("online_users", str(user_id))
