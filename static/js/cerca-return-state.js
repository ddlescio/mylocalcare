(function (windowRef, documentRef) {
  "use strict";

  if (windowRef.__cercaReturnStateInit) return;
  windowRef.__cercaReturnStateInit = true;

  const STATE_PREFIX = "lc_cerca_return_state_v1:";
  const PENDING_KEY = "lc_cerca_pending_return_v1";
  const MAX_AGE_MS = 30 * 60 * 1000;

  function currentSearchUrl() {
    return `${windowRef.location.pathname}${windowRef.location.search}`;
  }

  function stateKey(url) {
    return `${STATE_PREFIX}${url}`;
  }

  function safeParse(raw) {
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch (_) {
      return null;
    }
  }

  function isFresh(state) {
    return !!(
      state &&
      Number.isFinite(Number(state.savedAt)) &&
      Date.now() - Number(state.savedAt) <= MAX_AGE_MS
    );
  }

  function pendingReturnForCurrentSearch() {
    try {
      const pending = safeParse(windowRef.sessionStorage.getItem(PENDING_KEY));
      if (!isFresh(pending) || pending.searchUrl !== currentSearchUrl()) {
        return null;
      }
      return pending;
    } catch (_) {
      return null;
    }
  }

  function isReturnNavigation(event) {
    if (event && event.persisted === true) return true;
    try {
      const entry = windowRef.performance.getEntriesByType("navigation")[0];
      if (entry && entry.type === "back_forward") return true;
    } catch (_) {}
    try {
      const referrer = new URL(documentRef.referrer || "", windowRef.location.origin);
      return /^\/annuncio\/\d+\/?$/.test(referrer.pathname);
    } catch (_) {
      return false;
    }
  }

  function getHorizontalScrolls() {
    return Array.from(
      documentRef.querySelectorAll(".vetrina-mobile-scroll")
    ).map((element, index) => ({
      index,
      left: Math.max(0, Number(element.scrollLeft) || 0),
    }));
  }

  function saveSearchState(card) {
    const url = currentSearchUrl();
    const cardRect = card && typeof card.getBoundingClientRect === "function"
      ? card.getBoundingClientRect()
      : null;
    const filterPanel = documentRef.getElementById("filtri-container");
    const annuncioId = card ? String(card.dataset.annuncioId || "") : "";
    const cardKind = card ? String(card.dataset.cercaCardKind || "") : "";

    const state = {
      url,
      savedAt: Date.now(),
      scrollY: Math.max(0, Number(windowRef.scrollY) || 0),
      annuncioId,
      cardKind,
      cardViewportTop: cardRect ? Number(cardRect.top) : null,
      filtersOpen: !!(filterPanel && !filterPanel.classList.contains("hidden")),
      horizontalScrolls: getHorizontalScrolls(),
    };

    try {
      windowRef.sessionStorage.setItem(stateKey(url), JSON.stringify(state));
      windowRef.sessionStorage.setItem(PENDING_KEY, JSON.stringify({
        searchUrl: url,
        annuncioId,
        cardKind,
        savedAt: state.savedAt,
      }));
    } catch (_) {
      // La navigazione deve restare disponibile anche con storage disabilitato.
    }

    try {
      const historyState = Object.assign({}, windowRef.history.state || {}, {
        lcSearchReturnUrl: url,
        lcSearchScrollY: state.scrollY,
      });
      windowRef.history.replaceState(historyState, "", windowRef.location.href);
    } catch (_) {}
  }

  function restoreHorizontalScrolls(state) {
    if (!Array.isArray(state.horizontalScrolls)) return;
    const elements = documentRef.querySelectorAll(".vetrina-mobile-scroll");
    state.horizontalScrolls.forEach((item) => {
      const element = elements[Number(item.index)];
      if (element) element.scrollLeft = Math.max(0, Number(item.left) || 0);
    });
  }

  function restoreSearchState() {
    let state;
    const url = currentSearchUrl();
    try {
      state = safeParse(windowRef.sessionStorage.getItem(stateKey(url)));
    } catch (_) {
      return;
    }

    if (!isFresh(state) || state.url !== url) return;

    const filterPanel = documentRef.getElementById("filtri-container");
    const filterToggle = documentRef.getElementById("toggle-filtri");
    if (state.filtersOpen && filterPanel) {
      filterPanel.classList.remove("hidden");
      if (filterToggle) filterToggle.setAttribute("aria-expanded", "true");
    }

    let restoredByCard = false;
    if (state.annuncioId && Number.isFinite(Number(state.cardViewportTop))) {
      const kindSelector = state.cardKind
        ? `[data-cerca-card-kind="${CSS.escape(state.cardKind)}"]`
        : "";
      const selector = `.js-open-annuncio[data-annuncio-id="${CSS.escape(state.annuncioId)}"]${kindSelector}`;
      const card = documentRef.querySelector(selector);
      if (card) {
        const targetY = windowRef.scrollY
          + card.getBoundingClientRect().top
          - Number(state.cardViewportTop);
        windowRef.scrollTo(0, Math.max(0, targetY));
        restoredByCard = true;
      }
    }

    if (!restoredByCard) {
      windowRef.scrollTo(0, Math.max(0, Number(state.scrollY) || 0));
    }
    restoreHorizontalScrolls(state);
  }

  function scheduleRestore(event) {
    if (!pendingReturnForCurrentSearch() || !isReturnNavigation(event)) return;
    windowRef.requestAnimationFrame(() => {
      windowRef.requestAnimationFrame(() => {
        restoreSearchState();
        try {
          windowRef.sessionStorage.removeItem(PENDING_KEY);
        } catch (_) {}
      });
    });
  }

  documentRef.addEventListener("click", (event) => {
    const card = event.target.closest(".js-open-annuncio[data-url]");
    if (!card) return;
    if (event.target.closest("a, button, input, textarea, select, label, form")) {
      return;
    }
    saveSearchState(card);
  }, true);

  windowRef.addEventListener("pagehide", () => {
    const pending = safeParse(
      (() => {
        try {
          return windowRef.sessionStorage.getItem(PENDING_KEY);
        } catch (_) {
          return null;
        }
      })()
    );
    if (pending && pending.searchUrl === currentSearchUrl()) {
      const card = pending.annuncioId
        ? documentRef.querySelector(
            `.js-open-annuncio[data-annuncio-id="${CSS.escape(String(pending.annuncioId))}"]${pending.cardKind ? `[data-cerca-card-kind="${CSS.escape(String(pending.cardKind))}"]` : ""}`
          )
        : null;
      saveSearchState(card);
    }
  });

  windowRef.addEventListener("pageshow", scheduleRestore);
  windowRef.addEventListener("load", scheduleRestore, { once: true });
})(window, document);
