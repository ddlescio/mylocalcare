(function (root, factory) {
  "use strict";

  const api = factory();

  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }

  if (root) {
    root.MyLocalCareOwnerAvailabilityRequests = api;
    if (root.document) {
      if (root.document.readyState === "loading") {
        root.document.addEventListener("DOMContentLoaded", function () {
          api.init(root.document, root);
        }, { once: true });
      } else {
        api.init(root.document, root);
      }
    }
  }
})(typeof window !== "undefined" ? window : null, function () {
  "use strict";

  const ALLOWED_STATES = [
    "in_attesa",
    "disponibile",
    "non_disponibile",
    "informazioni",
    "scaduta"
  ];
  const RESPONSE_STATES = [
    "disponibile",
    "non_disponibile",
    "informazioni"
  ];

  function buildResponsePayload(state, version) {
    return {
      stato: String(state || ""),
      versione: Number(version)
    };
  }

  function cleanDeepLinkUrl(urlValue) {
    const url = new URL(String(urlValue || ""), "https://mylocalcare.invalid");
    url.searchParams.delete("richiesta_disponibilita");
    const query = url.searchParams.toString();
    return url.pathname + (query ? "?" + query : "") + url.hash;
  }

  function init(documentRef, windowRef) {
    if (!documentRef || !windowRef || documentRef.__ownerAvailabilityRequestsReady) {
      return;
    }

    const rootElement = documentRef.querySelector(
      "[data-owner-availability-requests]"
    );
    const copyNode = documentRef.getElementById(
      "owner-availability-request-copy"
    );
    if (!rootElement || !copyNode) return;
    documentRef.__ownerAvailabilityRequestsReady = true;

    let copy = {};
    try {
      copy = JSON.parse(copyNode.textContent || "{}");
    } catch (error) {
      copy = {};
    }

    const csrfToken = rootElement.dataset.csrfToken || "";
    const stateLabels = copy.stateLabels || {};
    const timelineRoot = documentRef.getElementById("msgWrap") || rootElement;
    const pendingRealtimeEvents = new Map();
    let boundRealtimeSocket = null;
    let visibleFlushPromise = null;

    function parseDate(rawValue) {
      const raw = String(rawValue || "").trim();
      if (!raw) return null;
      const normalized = /^\d{4}-\d{2}-\d{2}\s/.test(raw)
        ? raw.replace(" ", "T")
        : raw;
      const value = new Date(normalized);
      return Number.isNaN(value.getTime()) ? null : value;
    }

    function formatDates() {
      const language = documentRef.documentElement.lang || "it";
      let formatter = null;
      try {
        formatter = new Intl.DateTimeFormat(language, {
          dateStyle: "short",
          timeStyle: "short"
        });
      } catch (error) {
        formatter = null;
      }

      timelineRoot.querySelectorAll("[data-owner-availability-date]")
        .forEach(function (timeElement) {
          const value = parseDate(
            timeElement.getAttribute("datetime") || timeElement.textContent
          );
          if (value && formatter) timeElement.textContent = formatter.format(value);
        });
    }

    function clearError(card) {
      const errorBox = card.querySelector("[data-owner-availability-error]");
      if (!errorBox) return;
      errorBox.hidden = true;
      errorBox.textContent = "";
    }

    function showError(card, message) {
      const errorBox = card.querySelector("[data-owner-availability-error]");
      if (!errorBox) return;
      errorBox.textContent = message || copy.errorGeneric || "";
      errorBox.hidden = false;
      errorBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
      errorBox.focus({ preventScroll: true });
    }

    function setBusy(card, activeButton, isBusy) {
      card.setAttribute("aria-busy", isBusy ? "true" : "false");
      card.querySelectorAll("[data-owner-availability-response]")
        .forEach(function (button) {
          button.disabled = isBusy;
          const label = button.querySelector(
            "[data-owner-availability-response-label]"
          );
          if (!label) return;

          if (!label.dataset.originalLabel) {
            label.dataset.originalLabel = label.textContent.trim();
          }
          label.textContent = isBusy && button === activeButton
            ? (copy.sending || label.dataset.originalLabel)
            : label.dataset.originalLabel;
        });
    }

    function updateState(card, state, version) {
      const normalizedState = ALLOWED_STATES.includes(state)
        ? state
        : card.dataset.state;
      card.dataset.state = normalizedState;
      if (Number.isInteger(Number(version)) && Number(version) > 0) {
        card.dataset.version = String(Number(version));
      }

      const status = card.querySelector("[data-owner-availability-status]");
      if (status) {
        ALLOWED_STATES.forEach(function (knownState) {
          status.classList.remove("is-" + knownState);
        });
        status.classList.add("is-" + normalizedState);
        status.textContent = stateLabels[normalizedState] || normalizedState;
      }

      const actions = card.querySelector("[data-owner-availability-actions]");
      if (actions && normalizedState !== "in_attesa") actions.hidden = true;

      const waiting = card.querySelector("[data-owner-availability-waiting]");
      if (waiting && normalizedState !== "in_attesa") waiting.hidden = true;

      const result = card.querySelector("[data-owner-availability-result]");
      if (result) {
        const label = stateLabels[normalizedState] || normalizedState;
        result.textContent = (copy.answerRecorded || "") + ": " + label;
        result.hidden = false;
      }
    }

    function markOriginalRequestAnswered(card, state, version) {
      if (!card) return;
      card.dataset.state = state;
      if (Number.isInteger(Number(version)) && Number(version) > 0) {
        card.dataset.version = String(Number(version));
      }

      const status = card.querySelector("[data-owner-availability-status]");
      if (status) {
        ALLOWED_STATES.concat(["inviata"]).forEach(function (knownState) {
          status.classList.remove("is-" + knownState);
        });
        status.classList.add("is-inviata");
        status.textContent = copy.requestSent || stateLabels.in_attesa || "";
      }

      const waiting = card.querySelector("[data-owner-availability-waiting]");
      if (waiting) waiting.hidden = true;
    }

    function responseMessage(state) {
      const messages = copy.responseMessages || {};
      return messages[state] || stateLabels[state] || state;
    }

    function renderResponseEvent(card, payload) {
      if (!card || !payload || !RESPONSE_STATES.includes(payload.stato)) {
        return null;
      }

      const requestId = Number(payload.richiesta_id);
      if (!Number.isInteger(requestId) || requestId <= 0) return null;

      let eventCard = timelineRoot.querySelector(
        "[data-owner-availability-response-event][data-request-id='" + requestId + "']"
      );
      if (!eventCard) {
        eventCard = documentRef.createElement("article");
        eventCard.id = "risposta-disponibilita-" + requestId;
        eventCard.setAttribute("data-owner-availability-response-event", "");
        eventCard.dataset.requestId = String(requestId);
        eventCard.setAttribute(
          "aria-label",
          copy.responseReceived || ""
        );

        const icon = documentRef.createElement("span");
        icon.className = "owner-availability-response-event-icon";
        icon.setAttribute("aria-hidden", "true");

        const content = documentRef.createElement("span");
        content.className = "owner-availability-response-event-content";

        const eyebrow = documentRef.createElement("span");
        eyebrow.className = "owner-availability-response-event-eyebrow";
        eyebrow.textContent = copy.responseReceived || "";

        const title = documentRef.createElement("strong");
        title.setAttribute("data-owner-availability-response-title", "");

        const message = documentRef.createElement("span");
        message.className = "owner-availability-response-event-message";
        message.setAttribute("data-owner-availability-response-message", "");

        const listing = documentRef.createElement("small");
        listing.className = "ugc-text";
        const listingTitle = card.querySelector(
          ".owner-availability-request-person strong"
        )?.textContent?.trim() || "";
        listing.textContent = String(copy.responseForListing || "{listing}")
          .replace("{listing}", listingTitle);

        const time = documentRef.createElement("time");
        time.className = "owner-availability-response-event-time";
        time.setAttribute("data-owner-availability-date", "");

        content.append(eyebrow, title, message, listing);
        eventCard.append(icon, content, time);
        card.insertAdjacentElement("afterend", eventCard);
      }

      RESPONSE_STATES.forEach(function (knownState) {
        eventCard.classList.remove("is-" + knownState);
      });
      eventCard.classList.add(
        "owner-availability-response-event",
        "is-" + payload.stato
      );
      eventCard.dataset.responseState = payload.stato;

      const icon = eventCard.querySelector(
        ".owner-availability-response-event-icon"
      );
      if (icon) {
        icon.textContent = payload.stato === "disponibile"
          ? "✓"
          : (payload.stato === "non_disponibile" ? "×" : "💬");
      }
      const title = eventCard.querySelector(
        "[data-owner-availability-response-title]"
      );
      if (title) title.textContent = stateLabels[payload.stato] || payload.stato;
      const message = eventCard.querySelector(
        "[data-owner-availability-response-message]"
      );
      if (message) message.textContent = responseMessage(payload.stato);
      const time = eventCard.querySelector("[data-owner-availability-date]");
      if (time) {
        const responseAt = String(payload.risposta_at || "");
        time.setAttribute("datetime", responseAt);
        time.textContent = responseAt || "—";
        eventCard.dataset.chatTimelineAt = responseAt;
      }

      formatDates();
      return eventCard;
    }

    function pageIsActivelyViewed() {
      const isVisible = documentRef.visibilityState === "visible";
      const hasFocus = typeof documentRef.hasFocus !== "function"
        || documentRef.hasFocus();
      return isVisible && hasFocus;
    }

    function activeConversationId() {
      const value = Number(windowRef.__activeChat);
      if (Number.isInteger(value) && value > 0) return value;
      const recipient = documentRef.getElementById("destinatario_id");
      const fallback = Number(recipient && recipient.value);
      return Number.isInteger(fallback) && fallback > 0 ? fallback : 0;
    }

    function eventKey(type, payload) {
      return String(type || "event") + ":" + String(
        Number(payload && payload.richiesta_id) || 0
      );
    }

    function targetForEvent(type, payload) {
      const requestId = Number(payload && payload.richiesta_id);
      if (!Number.isInteger(requestId) || requestId <= 0) return null;
      const selector = type === "response"
        ? "[data-owner-availability-response-event][data-request-id='" + requestId + "']"
        : "[data-owner-availability-request][data-request-id='" + requestId + "']";
      return timelineRoot.querySelector(selector);
    }

    async function refreshAvailabilityCards(context) {
      const refreshUrl = String(rootElement.dataset.refreshUrl || "").trim();
      if (!refreshUrl) return null;

      try {
        const response = await windowRef.fetch(refreshUrl, {
          method: "GET",
          credentials: "same-origin",
          cache: "no-store",
          headers: {
            "Accept": "application/json",
            "X-Requested-With": "XMLHttpRequest"
          }
        });
        const data = await parseResponse(response);
        if (!response.ok || data.ok === false || typeof data.html !== "string") {
          return null;
        }

        const shell = documentRef.createElement("div");
        shell.innerHTML = data.html;
        const nextRoot = shell.querySelector(
          "[data-owner-availability-requests]"
        );
        const nextList = nextRoot && nextRoot.querySelector(
          ".owner-availability-request-list"
        );
        const currentList = rootElement.querySelector(
          ".owner-availability-request-list"
        );
        if (!nextList || !currentList) return null;

        const openRequestIds = new Set(
          Array.from(timelineRoot.querySelectorAll(
            "[data-owner-availability-request-details][open]"
          )).map(function (details) {
            const card = details.closest("[data-owner-availability-request]");
            return card ? String(card.dataset.requestId || "") : "";
          }).filter(Boolean)
        );

        timelineRoot.querySelectorAll(
          "[data-owner-availability-request], "
          + "[data-owner-availability-response-event]"
        ).forEach(function (card) {
          card.remove();
        });

        const incomingCards = Array.from(nextList.children).filter(
          function (element) {
            return element.matches(
              "[data-owner-availability-request], "
              + "[data-owner-availability-response-event]"
            );
          }
        );
        incomingCards.forEach(function (card) {
          currentList.appendChild(card.cloneNode(true));
        });
        rootElement.hidden = incomingCards.length === 0;

        openRequestIds.forEach(function (requestId) {
          const details = timelineRoot.querySelector(
            "[data-owner-availability-request][data-request-id='"
            + requestId
            + "'] [data-owner-availability-request-details]"
          );
          if (details) details.open = true;
        });

        formatDates();
        syncChatBlockStatus(Boolean(
          windowRef.__chatBlockStatus
          && windowRef.__chatBlockStatus.bloccata === true
        ));
        documentRef.dispatchEvent(new windowRef.CustomEvent(
          "localcare:availability-cards-refreshed",
          {
            detail: {
              tipoEvento: context ? context.type : "refresh",
              richiestaId: Number(
                context && context.payload
                && context.payload.richiesta_id
              ) || 0
            }
          }
        ));
        return true;
      } catch (error) {
        return null;
      }
    }

    function markConversationReadIfVisible(otherId) {
      const normalizedId = Number(otherId);
      const socket = boundRealtimeSocket || windowRef.socket;
      if (
        !pageIsActivelyViewed()
        || normalizedId <= 0
        || normalizedId !== activeConversationId()
        || !socket
        || !socket.connected
        || typeof socket.emit !== "function"
      ) {
        return false;
      }
      socket.emit("mark_as_read", { other_id: normalizedId });
      return true;
    }

    async function flushVisibleRealtimeEvents(forceRefresh) {
      if (!pageIsActivelyViewed() || !activeConversationId()) return false;
      if (visibleFlushPromise) return visibleFlushPromise;

      const snapshot = Array.from(pendingRealtimeEvents.entries());
      if (!snapshot.length && !forceRefresh) return false;
      const latest = snapshot.length
        ? snapshot[snapshot.length - 1][1]
        : null;

      visibleFlushPromise = (async function () {
        let refreshed = await refreshAvailabilityCards(latest);

        // La risposta contiene abbastanza dati per un fallback locale. La
        // nuova richiesta, invece, viene mostrata solo dopo avere recuperato
        // dal server giorni e orari completi.
        if (!refreshed && latest && latest.type === "response") {
          const requestId = Number(latest.payload.richiesta_id);
          const card = timelineRoot.querySelector(
            "[data-owner-availability-request][data-request-id='"
            + requestId
            + "']"
          );
          if (card) {
            markOriginalRequestAnswered(
              card,
              latest.payload.stato,
              latest.payload.versione
            );
            refreshed = Boolean(renderResponseEvent(card, latest.payload));
          }
        }

        if (!refreshed || !pageIsActivelyViewed()) return false;
        snapshot.forEach(function (entry) {
          pendingRealtimeEvents.delete(entry[0]);
        });

        if (latest) {
          const target = targetForEvent(latest.type, latest.payload);
          if (target) scrollToRequest(target);
        }
        markConversationReadIfVisible(activeConversationId());
        return true;
      })();

      try {
        return await visibleFlushPromise;
      } finally {
        visibleFlushPromise = null;
        if (pendingRealtimeEvents.size && pageIsActivelyViewed()) {
          windowRef.Promise.resolve().then(function () {
            flushVisibleRealtimeEvents(false);
          });
        }
      }
    }

    function queueRealtimeEvent(type, payload) {
      const from = Number(payload && payload.from);
      if (!payload || from !== activeConversationId()) return;
      const context = { type: type, payload: payload };
      pendingRealtimeEvents.set(eventKey(type, payload), context);
      if (pageIsActivelyViewed()) flushVisibleRealtimeEvents(false);
    }

    function unbindRealtimeSocket(socket) {
      if (!socket || typeof socket.off !== "function") return;
      if (windowRef.__ownerAvailabilityResponseHandler) {
        socket.off(
          "availability_request_response",
          windowRef.__ownerAvailabilityResponseHandler
        );
      }
      if (windowRef.__ownerAvailabilityCreatedHandler) {
        socket.off(
          "availability_request_created",
          windowRef.__ownerAvailabilityCreatedHandler
        );
      }
    }

    function bindRealtimeSocket(socket) {
      if (!socket || typeof socket.on !== "function") return;
      if (boundRealtimeSocket && boundRealtimeSocket !== socket) {
        unbindRealtimeSocket(boundRealtimeSocket);
      }
      unbindRealtimeSocket(socket);

      windowRef.__ownerAvailabilityResponseHandler = function (payload) {
        queueRealtimeEvent("response", payload);
      };
      windowRef.__ownerAvailabilityCreatedHandler = function (payload) {
        queueRealtimeEvent("request", payload);
      };
      socket.on(
        "availability_request_response",
        windowRef.__ownerAvailabilityResponseHandler
      );
      socket.on(
        "availability_request_created",
        windowRef.__ownerAvailabilityCreatedHandler
      );
      boundRealtimeSocket = socket;

      // Anche dopo una riconnessione recupera gli eventi eventualmente persi.
      if (pageIsActivelyViewed()) flushVisibleRealtimeEvents(true);
    }

    function bindWhenSocketIsReady() {
      if (typeof windowRef.whenSocketReady === "function") {
        windowRef.whenSocketReady(bindRealtimeSocket);
      } else if (windowRef.socket) {
        bindRealtimeSocket(windowRef.socket);
      }
    }

    function syncChatBlockStatus(isBlocked) {
      timelineRoot.querySelectorAll("[data-owner-availability-request]")
        .forEach(function (card) {
          const blocked = isBlocked === true;
          const pending = card.dataset.state === "in_attesa";
          const canRespond = card.dataset.canRespond === "1";
          const actions = card.querySelector(
            "[data-owner-availability-actions]"
          );
          const waiting = card.querySelector(
            "[data-owner-availability-waiting]"
          );

          card.dataset.chatBlocked = blocked ? "1" : "0";
          if (actions) actions.hidden = !pending || !canRespond || blocked;
          if (waiting) {
            waiting.hidden = !pending || (canRespond && !blocked);
            if (!waiting.hidden) {
              waiting.textContent = blocked
                ? (copy.blocked || "")
                : (copy.awaitingReply || "");
            }
          }
        });
    }

    async function parseResponse(response) {
      const text = await response.text();
      if (!text) return {};
      try {
        return JSON.parse(text);
      } catch (error) {
        return {};
      }
    }

    function redirectForMissingProfilePhoto(data) {
      if (
        !data
        || !["foto_profilo_richiesta", "profile_photo_required"].includes(
          data.code
        )
      ) {
        return false;
      }

      if (typeof windowRef.alert === "function") {
        windowRef.alert(data.error || copy.errorGeneric || "");
      }
      if (windowRef.location) {
        windowRef.location.assign(data.action_url || "/utente/dashboard");
      }
      return true;
    }

    async function sendResponse(card, button) {
      if (!card || !button || card.getAttribute("aria-busy") === "true") return;

      const requestedState = button.dataset.ownerAvailabilityResponse || "";
      const version = Number(card.dataset.version);
      if (!RESPONSE_STATES.includes(requestedState) || !Number.isInteger(version)) {
        showError(card, copy.errorGeneric);
        return;
      }

      clearError(card);
      setBusy(card, button, true);

      try {
        const response = await windowRef.fetch(card.dataset.endpoint || "", {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken,
            "X-Requested-With": "XMLHttpRequest"
          },
          body: JSON.stringify(buildResponsePayload(requestedState, version))
        });
        const data = await parseResponse(response);

        if (redirectForMissingProfilePhoto(data)) {
          return;
        }

        if (!response.ok || data.ok === false) {
          const backendError = typeof data.error === "string"
            ? data.error.trim()
            : "";
          const message = backendError || (response.status === 409
            ? copy.errorConflict
            : copy.errorGeneric);
          throw Object.assign(new Error("availability_response_failed"), {
            userMessage: message
          });
        }

        const nextState = RESPONSE_STATES.includes(data.stato)
          ? data.stato
          : requestedState;
        updateState(card, nextState, data.version);

        documentRef.dispatchEvent(new windowRef.CustomEvent(
          "localcare:richiesta-disponibilita-risposta",
          {
            detail: {
              richiestaId: Number(card.dataset.requestId),
              stato: nextState,
              versione: Number(card.dataset.version)
            }
          }
        ));

      } catch (error) {
        showError(card, error.userMessage || copy.errorGeneric);
      } finally {
        setBusy(card, button, false);
      }
    }

    function cleanCurrentDeepLink() {
      const nextUrl = cleanDeepLinkUrl(windowRef.location.href);
      windowRef.history.replaceState(windowRef.history.state, "", nextUrl);
    }

    function scrollToRequest(card) {
      const messageWrap = documentRef.getElementById("msgWrap");
      if (!messageWrap || !messageWrap.contains(card)) {
        card.scrollIntoView({ behavior: "smooth", block: "center" });
        return;
      }

      const wrapBox = messageWrap.getBoundingClientRect();
      const cardBox = card.getBoundingClientRect();
      const centeredOffset = Math.max(
        12,
        (messageWrap.clientHeight - cardBox.height) / 2
      );
      const top = messageWrap.scrollTop
        + cardBox.top
        - wrapBox.top
        - centeredOffset;

      if (typeof messageWrap.scrollTo === "function") {
        messageWrap.scrollTo({ top: Math.max(0, top), behavior: "smooth" });
      } else {
        messageWrap.scrollTop = Math.max(0, top);
      }
    }

    function openDeepLinkedRequest() {
      const params = new URLSearchParams(windowRef.location.search);
      const rawId = params.get("richiesta_disponibilita");
      if (!rawId) return;

      if (!/^\d+$/.test(rawId)) {
        cleanCurrentDeepLink();
        return;
      }

      const responseEvent = timelineRoot.querySelector(
        "[data-owner-availability-response-event][data-request-id='" + rawId + "']"
      );
      const card = responseEvent || timelineRoot.querySelector(
        "[data-owner-availability-request][data-request-id='" + rawId + "']"
      );
      if (!card) {
        cleanCurrentDeepLink();
        return;
      }

      const details = card.querySelector(
        "[data-owner-availability-request-details]"
      );
      if (details) details.open = true;

      windowRef.requestAnimationFrame(function () {
        windowRef.requestAnimationFrame(function () {
          windowRef.setTimeout(function () {
            scrollToRequest(card);
            cleanCurrentDeepLink();
            const summary = details?.querySelector("summary");
            summary?.focus({ preventScroll: true });
          }, 80);
        });
      });
    }

    timelineRoot.addEventListener("click", function (event) {
      const button = event.target.closest(
        "[data-owner-availability-response]"
      );
      if (!button) return;
      const card = button.closest("[data-owner-availability-request]");
      sendResponse(card, button);
    });

    documentRef.addEventListener(
      "localcare:chat-block-status",
      function (event) {
        const detail = event && event.detail ? event.detail : {};
        syncChatBlockStatus(detail.bloccata === true);
      }
    );
    windowRef.addEventListener("socket_ready", function () {
      bindRealtimeSocket(windowRef.socket);
    });
    documentRef.addEventListener("visibilitychange", function () {
      if (pageIsActivelyViewed()) flushVisibleRealtimeEvents(true);
    });
    windowRef.addEventListener("focus", function () {
      if (pageIsActivelyViewed()) flushVisibleRealtimeEvents(true);
    });

    formatDates();
    syncChatBlockStatus(Boolean(
      windowRef.__chatBlockStatus
      && windowRef.__chatBlockStatus.bloccata === true
    ));
    openDeepLinkedRequest();
    bindWhenSocketIsReady();
  }

  return {
    ALLOWED_STATES: ALLOWED_STATES.slice(),
    RESPONSE_STATES: RESPONSE_STATES.slice(),
    buildResponsePayload: buildResponsePayload,
    cleanDeepLinkUrl: cleanDeepLinkUrl,
    init: init
  };
});
