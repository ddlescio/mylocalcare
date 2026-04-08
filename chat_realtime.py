from flask import session, request, g, has_request_context
from zoneinfo import ZoneInfo
from datetime import datetime
import traceback

from socket_registry import _get_user_id_from_sid

typing_state = {}
pagina_attiva = {}

def _resolve_socket_user_id():
    user_id = session.get("utente_id")

    if user_id:
        try:
            return int(user_id)
        except Exception:
            return user_id

    sid = getattr(request, "sid", None)
    if not sid:
        return None

    try:
        fallback_user_id = _get_user_id_from_sid(sid)
        if fallback_user_id:
            return int(fallback_user_id)
    except Exception as e:
        print(f"❌ [_resolve_socket_user_id] errore sid->user per sid={sid}: {e}", flush=True)

    return None


def register_chat_socket_handlers(
    socketio,
    app,
    *,
    get_db_connection,
    get_cursor,
    sql,
    chat_invia,
    chat_segna_letti,
    emit_to_user_sids,
    chat_count_unread,
    set_open_chat,
    get_open_chat,
    clear_open_chat,
    invia_push,
    recently_read_timers,
):
    def clear_recently_read(user_id, delay=None):
        if delay is None:
            delay = app.config.get("CHAT_RECENTLY_READ_TTL", 5)

        if user_id in recently_read_timers:
            return

        task = socketio.start_background_task(_delayed_clear_recently_read, user_id, delay)
        recently_read_timers[user_id] = task

    def _delayed_clear_recently_read(user_id, delay):
        socketio.sleep(delay)

        if "CHAT_ULTIMA_LETTA" in app.config:
            app.config["CHAT_ULTIMA_LETTA"].pop(user_id, None)
            print(f"🧹 Pulita ultima chat letta per utente {user_id}")

        recently_read_timers.pop(user_id, None)

    @socketio.on("send_message")
    def handle_send_message(data):
        print("🚨 ENTER handle_send_message", flush=True)
        resolved_user_id = _resolve_socket_user_id()
        print(
            f"🚨 SID={request.sid} session_user={session.get('utente_id')} "
            f"resolved_user={resolved_user_id} data={data}",
            flush=True
        )

        mittente_id = resolved_user_id
        print(f"📨 [send_message] START mittente={mittente_id} data={data}", flush=True)

        try:
            destinatario_id = int(data.get("destinatario_id"))
        except (TypeError, ValueError):
            print("❌ [send_message] destinatario_id non valido")
            return {"ok": False, "error": "destinatario_id non valido"}

        testo = (data.get("testo") or "").strip()

        if not mittente_id or not destinatario_id or not testo:
            print(f"❌ [send_message] dati mancanti mittente={mittente_id} destinatario={destinatario_id} testo='{testo}'")
            return {"ok": False, "error": "Dati mancanti o sessione non valida"}

        conn = None
        c = None

        try:
            print("📨 [send_message] apro connessione DB")
            conn = get_db_connection()

            print("📨 [send_message] ottengo cursore")
            c = get_cursor(conn)

            print("📨 [send_message] verifico foto profilo")
            c.execute(sql("SELECT foto_profilo FROM utenti WHERE id = ?"), (mittente_id,))
            row = c.fetchone()

            if not row or not row["foto_profilo"]:
                print("❌ [send_message] foto profilo mancante")
                return {
                    "ok": False,
                    "error": "Per inviare messaggi devi prima caricare una foto profilo."
                }

            print("📨 [send_message] prima di chat_invia")
            msg_id = chat_invia(mittente_id, destinatario_id, testo)
            print(f"📨 [send_message] dopo chat_invia msg_id={msg_id}")

            print("📨 [send_message] aggiorno visibile_in_chat")
            conn.execute(sql(
                "UPDATE utenti SET visibile_in_chat = 1 WHERE id = ?"
            ), (mittente_id,))

            print("📨 [send_message] commit")
            conn.commit()
            print("📨 [send_message] commit OK")

        except Exception as e:
            print("❌ [send_message] ECCEZIONE")
            traceback.print_exc()
            return {"ok": False, "error": str(e)}

        finally:
            print("📨 [send_message] finally chiusura risorse")

            try:
                if c:
                    c.close()
            except Exception as e:
                print("⚠️ [send_message] errore chiusura cursore:", e)

            if conn:
                try:
                    if has_request_context() and getattr(g, "db_conn", None) is conn:
                        g.db_conn = None
                        print("📨 [send_message] sganciato g.db_conn prima della close", flush=True)

                    conn.close()
                    print("📨 [send_message] conn.close() OK", flush=True)

                except Exception as e:
                    print("⚠️ [send_message] errore chiusura conn:", e)

        messaggio = {
            "id": msg_id,
            "mittente_id": mittente_id,
            "destinatario_id": destinatario_id,
            "testo": testo,
            "created_at": datetime.now(ZoneInfo("Europe/Rome")).isoformat(),
            "consegnato": True,
            "letto": False
        }

        try:
            print("📨 [send_message] emit new_message mittente")
            emit_to_user_sids(mittente_id, "new_message", messaggio)

            print("📨 [send_message] emit new_message destinatario")
            emit_to_user_sids(destinatario_id, "new_message", messaggio)

            print("📨 [send_message] emit message_delivered")
            emit_to_user_sids(mittente_id, "message_delivered", {
                "id": msg_id,
                "mittente_id": mittente_id,
                "destinatario_id": destinatario_id
            })

            print("📨 [send_message] calcolo unread destinatario")
            count_destinatario = chat_count_unread(destinatario_id)

            print(f"📨 [send_message] emit unread destinatario count={count_destinatario}")
            emit_to_user_sids(
                destinatario_id,
                "update_unread_count",
                {"count": count_destinatario}
            )

            print("📨 [send_message] emit chat_threads_update mittente")
            emit_to_user_sids(mittente_id, "chat_threads_update", {"from": mittente_id})

            print("📨 [send_message] emit chat_threads_update destinatario")
            emit_to_user_sids(destinatario_id, "chat_threads_update", {"from": mittente_id})

            chat_aperta = get_open_chat(destinatario_id)
            pagina_visibile = bool(pagina_attiva.get(destinatario_id, False))

            print(f"📨 [send_message] stato push chat_aperta={chat_aperta} pagina_visibile={pagina_visibile}")

            if chat_aperta != mittente_id and not pagina_visibile:
                print(f"🔔 [send_message] Push INVIO DIRETTO per {destinatario_id}", flush=True)

                try:
                    invia_push(
                        destinatario_id,
                        "Nuovo messaggio su LocalCare",
                        testo[:100]
                    )
                    print(f"✅ [send_message] invia_push completata per {destinatario_id}", flush=True)
                except Exception as e:
                    print(f"❌ [send_message] errore invia_push per {destinatario_id}: {e}", flush=True)
            else:
                print(
                    f"⏭️ [send_message] push saltata "
                    f"chat_aperta={chat_aperta} pagina_visibile={pagina_visibile}",
                    flush=True
                )

            print(f"✅ [send_message] END ok msg_id={msg_id}")
            return {
                "ok": True,
                "id": msg_id
            }

        except Exception as e:
            print("❌ [send_message] ECCEZIONE DURANTE EMIT")
            traceback.print_exc()
            return {"ok": False, "error": str(e)}

    @socketio.on("chat_aperta")
    def handle_chat_aperta(data):
        user_id = _resolve_socket_user_id()
        other_id = data.get("other_id")

        if not user_id or not other_id:
            return

        try:
            set_open_chat(user_id, int(other_id), ttl=300)
        except Exception as e:
            print(f"❌ Errore salvataggio chat_aperta Redis user={user_id} other={other_id}: {e}")

    @socketio.on("page_visible")
    def handle_page_visible(data):
        user_id = _resolve_socket_user_id()
        if not user_id:
            return

        visible = bool(data.get("visible"))
        pagina_attiva[user_id] = visible

    @socketio.on("mark_as_read")
    def handle_mark_as_read(data):
        user_id = _resolve_socket_user_id()
        other_id = data.get("other_id")

        if not user_id or not other_id:
            return

        try:
            chat_segna_letti(user_id, other_id)

            emit_to_user_sids(
                other_id,
                "messages_read",
                {"from": user_id}
            )

            unread_count = chat_count_unread(user_id)

            emit_to_user_sids(
                user_id,
                "update_unread_count",
                {"count": unread_count}
            )

            emit_to_user_sids(
                user_id,
                "chat_threads_update",
                {"from": other_id}
            )

            print(f"✅ Messaggi da {other_id} segnati come letti da {user_id}")

        except Exception:
            print("❌ Errore mark_as_read:")
            traceback.print_exc()

    @socketio.on("chat_chiusa")
    def handle_chat_chiusa(data):
        user_id = _resolve_socket_user_id()
        other_id = data.get("other_id")
        if not user_id or not other_id:
            return

        clear_open_chat(user_id)

        if "CHAT_ULTIMA_LETTA" not in app.config:
            app.config["CHAT_ULTIMA_LETTA"] = {}

        app.config["CHAT_ULTIMA_LETTA"][user_id] = int(other_id)

        clear_recently_read(user_id)

        emit_to_user_sids(user_id, "chat_threads_update", {})

    @socketio.on("refresh_threads")
    def handle_refresh_threads(data):
        user_id = _resolve_socket_user_id()
        if not user_id:
            return

        emit_to_user_sids(user_id, "chat_threads_update", {})

    @socketio.on("typing")
    def handle_typing(data):
        mittente_id = _resolve_socket_user_id()
        destinatario_id = data.get("to")
        typing = data.get("typing", False)

        if not mittente_id or not destinatario_id:
            return

        typing_state[(mittente_id, destinatario_id)] = typing

        emit_to_user_sids(
            destinatario_id,
            "user_typing",
            {
                "from": mittente_id,
                "typing": typing
            }
        )

    @socketio.on("chat_debug")
    def handle_chat_debug(data):
        try:
            print(
                "🧪 [CHATDBG] "
                f"user={_resolve_socket_user_id()} "
                f"sid={request.sid} "
                f"page_id={data.get('page_id')} "
                f"event={data.get('event')} "
                f"page_url={data.get('page_url')} "
                f"socket_id={data.get('socket_id')} "
                f"me_id={data.get('me_id')} "
                f"dest_id={data.get('dest_id')} "
                f"extra={data}"
            )
        except Exception as e:
            print("❌ Errore handle_chat_debug:", e)
