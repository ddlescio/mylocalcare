(function (root, factory) {
  "use strict";

  const api = factory();

  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }

  if (root) {
    root.MyLocalCareChatTimeline = api;
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

  const EVENT_SELECTORS = [
    ".msg-line",
    "[data-owner-availability-request]",
    "[data-owner-availability-response-event]"
  ];

  function parseTimelineTimestamp(value) {
    const raw = String(value || "").trim();
    if (!raw) return Number.POSITIVE_INFINITY;

    const normalized = /^\d{4}-\d{2}-\d{2}\s/.test(raw)
      ? raw.replace(" ", "T")
      : raw;
    const timestamp = Date.parse(normalized);
    return Number.isFinite(timestamp)
      ? timestamp
      : Number.POSITIVE_INFINITY;
  }

  function sortTimelineEntries(entries) {
    return Array.from(entries || [])
      .map(function (entry, index) {
        return {
          entry: entry,
          index: index,
          timestamp: parseTimelineTimestamp(entry && entry.timestamp)
        };
      })
      .sort(function (left, right) {
        if (left.timestamp !== right.timestamp) {
          return left.timestamp - right.timestamp;
        }
        return left.index - right.index;
      })
      .map(function (item) { return item.entry; });
  }

  function isTimelineEvent(node) {
    return Boolean(
      node
      && node.nodeType === 1
      && typeof node.matches === "function"
      && node.matches(EVENT_SELECTORS.join(","))
    );
  }

  function timelineTimestamp(node) {
    if (!node || node.nodeType !== 1) return "";
    if (node.dataset && node.dataset.chatTimelineAt) {
      return node.dataset.chatTimelineAt;
    }

    const message = node.querySelector("[data-created-at]");
    if (message) return message.getAttribute("data-created-at") || "";

    const time = node.querySelector("time[datetime]");
    return time ? (time.getAttribute("datetime") || "") : "";
  }

  function timelineKey(node) {
    if (!node || node.nodeType !== 1) return "";
    if (node.matches("[data-owner-availability-request]")) {
      return "request:" + String(node.dataset.requestId || "");
    }
    if (node.matches("[data-owner-availability-response-event]")) {
      return "response:" + String(node.dataset.requestId || "");
    }
    const message = node.querySelector("[data-mid]");
    return message ? "message:" + String(message.dataset.mid || "") : "";
  }

  function dayKey(rawValue) {
    const raw = String(rawValue || "").trim();
    const timestamp = parseTimelineTimestamp(raw);
    if (!Number.isFinite(timestamp)) return "";
    const date = new Date(timestamp);
    return [
      date.getFullYear(),
      String(date.getMonth() + 1).padStart(2, "0"),
      String(date.getDate()).padStart(2, "0")
    ].join("-");
  }

  function dateLabel(day, documentRef) {
    if (!day) return "";
    const parts = day.split("-").map(Number);
    if (parts.length !== 3 || parts.some(Number.isNaN)) return "";

    const date = new Date(parts[0], parts[1] - 1, parts[2]);
    const today = new Date();
    if (
      date.getFullYear() === today.getFullYear()
      && date.getMonth() === today.getMonth()
      && date.getDate() === today.getDate()
    ) {
      try {
        return new Intl.RelativeTimeFormat(
          documentRef.documentElement.lang || "it",
          { numeric: "auto" }
        ).format(0, "day");
      } catch (error) {
        return "Oggi";
      }
    }

    try {
      return new Intl.DateTimeFormat(documentRef.documentElement.lang || "it", {
        day: "2-digit",
        month: "long",
        year: "numeric"
      }).format(date);
    } catch (error) {
      return day;
    }
  }

  function createDateHeader(day, documentRef) {
    const header = documentRef.createElement("div");
    header.className = "text-center text-xs text-gray-400 my-2 date-header";
    header.dataset.day = day;
    header.dataset.chatTimelineDate = "1";
    header.textContent = dateLabel(day, documentRef);
    return header;
  }

  function findDirectEvent(wrap, key) {
    if (!key) return null;
    return Array.from(wrap.children).find(function (node) {
      return isTimelineEvent(node) && timelineKey(node) === key;
    }) || null;
  }

  function reconcileTimeline(wrap, documentRef) {
    if (!wrap || !documentRef) return [];

    const host = Array.from(wrap.children).find(function (node) {
      return node.nodeType === 1
        && node.matches("[data-owner-availability-requests]");
    }) || null;
    const staging = host
      ? host.querySelector(".owner-availability-request-list")
      : null;

    if (staging) {
      Array.from(staging.children)
        .filter(isTimelineEvent)
        .forEach(function (node) {
          const key = timelineKey(node);
          const oldNode = findDirectEvent(wrap, key);
          if (oldNode && oldNode !== node) oldNode.remove();
          wrap.insertBefore(node, host);
        });
      // Il section resta nel DOM come host tecnico per CSRF e refresh, ma
      // non deve lasciare uno spazio vuoto dopo che gli eventi sono entrati
      // nella cronologia comune.
      host.hidden = true;
    }

    wrap.querySelectorAll(":scope > .date-header").forEach(function (header) {
      header.remove();
    });

    const entries = Array.from(wrap.children)
      .filter(isTimelineEvent)
      .map(function (node) {
        return {
          node: node,
          timestamp: timelineTimestamp(node)
        };
      });
    const ordered = sortTimelineEntries(entries);

    ordered.forEach(function (entry) {
      if (host) wrap.insertBefore(entry.node, host);
      else wrap.appendChild(entry.node);
    });

    let previousDay = null;
    ordered.forEach(function (entry) {
      const day = dayKey(entry.timestamp);
      if (!day || day === previousDay) return;
      wrap.insertBefore(createDateHeader(day, documentRef), entry.node);
      previousDay = day;
    });

    return ordered.map(function (entry) {
      return timelineKey(entry.node);
    });
  }

  function init(documentRef, windowRef) {
    const wrap = documentRef && documentRef.getElementById("msgWrap");
    if (!wrap || wrap.dataset.chatTimelineReady === "1") return;
    wrap.dataset.chatTimelineReady = "1";

    let scheduled = false;
    let observer = null;

    function run() {
      scheduled = false;
      const nearBottom = (
        wrap.scrollHeight - wrap.scrollTop - wrap.clientHeight
      ) < 120;

      if (observer) observer.disconnect();
      reconcileTimeline(wrap, documentRef);
      if (observer) {
        observer.observe(wrap, { childList: true });
      }

      if (nearBottom) wrap.scrollTop = wrap.scrollHeight;
    }

    function schedule() {
      if (scheduled) return;
      scheduled = true;
      windowRef.requestAnimationFrame(run);
    }

    if (typeof windowRef.MutationObserver === "function") {
      observer = new windowRef.MutationObserver(schedule);
      observer.observe(wrap, { childList: true });
    }

    documentRef.addEventListener(
      "localcare:availability-cards-refreshed",
      schedule
    );
    documentRef.addEventListener(
      "localcare:richiesta-disponibilita-risposta",
      schedule
    );

    run();
  }

  return {
    parseTimelineTimestamp: parseTimelineTimestamp,
    sortTimelineEntries: sortTimelineEntries,
    reconcileTimeline: reconcileTimeline,
    dayKey: dayKey,
    timelineTimestamp: timelineTimestamp,
    timelineKey: timelineKey,
    init: init
  };
});
