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

      rootElement.querySelectorAll("[data-owner-availability-date]")
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

    function syncChatBlockStatus(isBlocked) {
      rootElement.querySelectorAll("[data-owner-availability-request]")
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

        if (nextState === "informazioni") {
          windowRef.setTimeout(function () {
            const messageInput = documentRef.getElementById("msgInput");
            messageInput?.focus({ preventScroll: true });
          }, 80);
        }
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

      const card = rootElement.querySelector(
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

    rootElement.addEventListener("click", function (event) {
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

    formatDates();
    syncChatBlockStatus(Boolean(
      windowRef.__chatBlockStatus
      && windowRef.__chatBlockStatus.bloccata === true
    ));
    openDeepLinkedRequest();
  }

  return {
    ALLOWED_STATES: ALLOWED_STATES.slice(),
    RESPONSE_STATES: RESPONSE_STATES.slice(),
    buildResponsePayload: buildResponsePayload,
    cleanDeepLinkUrl: cleanDeepLinkUrl,
    init: init
  };
});
