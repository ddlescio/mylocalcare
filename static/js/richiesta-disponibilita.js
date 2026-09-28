(function (root, factory) {
  "use strict";

  const api = factory();

  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }

  if (root) {
    root.MyLocalCareAvailabilityRequest = api;

    if (root.document) {
      if (root.document.readyState === "loading") {
        root.document.addEventListener("DOMContentLoaded", function () {
          api.init(root.document);
        }, { once: true });
      } else {
        api.init(root.document);
      }
    }
  }
})(typeof window !== "undefined" ? window : null, function () {
  "use strict";

  const SLOT_ORDER = ["mattina", "pomeriggio", "sera", "notte"];
  const TIME_PATTERN = /^(?:[01]\d|2[0-3]):[0-5]\d$/;
  const NIGHT_START = 18 * 60;
  const NIGHT_END = 8 * 60;
  const MAX_INTERVALS_PER_DAY = 8;
  const MAX_INTERVALS_TOTAL = 28;

  function intervalLimitCode(dayCount, totalCount) {
    if (Number(dayCount) >= MAX_INTERVALS_PER_DAY) return "limit_per_day";
    if (Number(totalCount) >= MAX_INTERVALS_TOTAL) return "limit_total";
    return null;
  }

  function timeToMinutes(value) {
    if (typeof value !== "string" || !TIME_PATTERN.test(value)) return null;
    const parts = value.split(":").map(Number);
    return (parts[0] * 60) + parts[1];
  }

  function buildPayload(dayStates, onCall) {
    const states = Array.isArray(dayStates) ? dayStates : [];
    const days = states
      .filter(function (day) { return day && day.selected === true; })
      .map(function (day) {
        const selectedSlots = new Set(
          Array.isArray(day.fasce) ? day.fasce : []
        );

        return {
          giorno_settimana: Number(day.giorno_settimana),
          fasce: SLOT_ORDER.filter(function (slot) {
            return selectedSlots.has(slot);
          }),
          intervalli: (Array.isArray(day.intervalli) ? day.intervalli : [])
            .map(function (interval) {
              return {
                ora_inizio: String(interval && interval.ora_inizio || ""),
                ora_fine: String(interval && interval.ora_fine || ""),
                giorno_successivo: Boolean(
                  interval && interval.giorno_successivo
                )
              };
            })
        };
      })
      .sort(function (left, right) {
        return left.giorno_settimana - right.giorno_settimana;
      });

    return {
      a_chiamata: onCall === true,
      giorni: days
    };
  }

  function buildSharedPayload(dayNumbers, slots, start, end, onCall) {
    const normalizedStart = String(start || "");
    const normalizedEnd = String(end || "");
    const startMinutes = timeToMinutes(normalizedStart);
    const endMinutes = timeToMinutes(normalizedEnd);
    const hasAnyTime = Boolean(normalizedStart || normalizedEnd);
    const crossesMidnight = (
      startMinutes !== null
      && endMinutes !== null
      && endMinutes < startMinutes
    );
    const sharedIntervals = hasAnyTime
      ? [{
          ora_inizio: normalizedStart,
          ora_fine: normalizedEnd,
          giorno_successivo: crossesMidnight
        }]
      : [];
    const sharedSlots = Array.isArray(slots) ? slots.slice() : [];
    const states = (Array.isArray(dayNumbers) ? dayNumbers : []).map(
      function (dayNumber) {
        return {
          selected: true,
          giorno_settimana: Number(dayNumber),
          fasce: sharedSlots,
          intervalli: sharedIntervals
        };
      }
    );

    return buildPayload(states, onCall);
  }

  function validatePayload(payload) {
    if (
      !payload
      || (
        Object.prototype.hasOwnProperty.call(payload, "a_chiamata")
        && typeof payload.a_chiamata !== "boolean"
      )
    ) {
      return { code: "invalid_on_call" };
    }

    const days = payload && Array.isArray(payload.giorni)
      ? payload.giorni
      : [];

    if (!days.length && payload.a_chiamata !== true) {
      return { code: "select_day" };
    }

    const seenDays = new Set();
    let totalIntervals = 0;

    for (let dayIndex = 0; dayIndex < days.length; dayIndex += 1) {
      const day = days[dayIndex] || {};
      const dayNumber = day.giorno_settimana;

      if (
        !Number.isInteger(dayNumber)
        || dayNumber < 1
        || dayNumber > 7
        || seenDays.has(dayNumber)
      ) {
        return { code: "invalid_day", dayNumber: dayNumber };
      }

      seenDays.add(dayNumber);

      const slots = Array.isArray(day.fasce) ? day.fasce : [];
      const intervals = Array.isArray(day.intervalli) ? day.intervalli : [];

      if (intervals.length > MAX_INTERVALS_PER_DAY) {
        return { code: "limit_per_day", dayNumber: dayNumber };
      }

      totalIntervals += intervals.length;
      if (totalIntervals > MAX_INTERVALS_TOTAL) {
        return { code: "limit_total", dayNumber: dayNumber };
      }

      if (!slots.length && !intervals.length) {
        return { code: "empty_day", dayNumber: dayNumber };
      }

      for (let intervalIndex = 0; intervalIndex < intervals.length; intervalIndex += 1) {
        const interval = intervals[intervalIndex] || {};
        const start = interval.ora_inizio;
        const end = interval.ora_fine;

        if (!start || !end) {
          return {
            code: "incomplete_interval",
            dayNumber: dayNumber,
            intervalIndex: intervalIndex
          };
        }

        const startMinutes = timeToMinutes(start);
        const endMinutes = timeToMinutes(end);

        if (startMinutes === null || endMinutes === null) {
          return {
            code: "incomplete_interval",
            dayNumber: dayNumber,
            intervalIndex: intervalIndex
          };
        }

        if (interval.giorno_successivo === true) {
          if (!(
            startMinutes > endMinutes
            && startMinutes >= NIGHT_START
            && endMinutes <= NIGHT_END
          )) {
            return {
              code: "invalid_night_interval",
              dayNumber: dayNumber,
              intervalIndex: intervalIndex
            };
          }
        } else if (endMinutes <= startMinutes) {
          return {
            code: "invalid_interval",
            dayNumber: dayNumber,
            intervalIndex: intervalIndex
          };
        }
      }
    }

    return null;
  }

  function init(documentRef) {
    if (!documentRef || documentRef.__availabilityRequestReady) return;

    const dialog = documentRef.getElementById("availability-request-dialog");
    const form = documentRef.getElementById("availability-request-form");
    const copyNode = documentRef.getElementById("availability-request-copy");
    const openButtons = Array.from(
      documentRef.querySelectorAll("[data-availability-request-open]")
    );

    if (!dialog || !form || !copyNode || !openButtons.length) return;
    documentRef.__availabilityRequestReady = true;

    let copy = {};
    try {
      copy = JSON.parse(copyNode.textContent || "{}");
    } catch (error) {
      copy = {};
    }

    const sheet = dialog.querySelector(".availability-request-sheet");
    const submitButton = dialog.querySelector("#availability-request-submit");
    const submitLabel = dialog.querySelector(
      "[data-availability-request-submit-label]"
    );
    const spinner = dialog.querySelector(".availability-request-spinner");
    const errorBox = dialog.querySelector("#availability-request-error");
    const successBox = dialog.querySelector("#availability-request-success");
    const closeButtons = Array.from(
      dialog.querySelectorAll("[data-availability-request-close]")
    );
    const dayInputs = Array.from(dialog.querySelectorAll(
      "[data-availability-request-day-toggle]"
    ));
    const slotInputs = Array.from(dialog.querySelectorAll(
      "[data-availability-request-slot]"
    ));
    const onCallInput = dialog.querySelector(
      "[data-availability-request-on-call]"
    );
    const startInput = dialog.querySelector(
      "[data-availability-request-time-start]"
    );
    const endInput = dialog.querySelector(
      "[data-availability-request-time-end]"
    );
    const nextDayNote = dialog.querySelector(
      "[data-availability-request-next-day-note]"
    );

    let previousFocus = null;
    let bodyWasOverflowHidden = false;
    let bodyWasModalOpen = false;
    let requestController = null;
    let busy = false;
    let completed = false;

    function getFocusableElements() {
      if (!sheet) return [];
      return Array.from(sheet.querySelectorAll(
        "button:not([disabled]), input:not([disabled]), "
        + "select:not([disabled]), textarea:not([disabled]), "
        + "[href], [tabindex]:not([tabindex='-1'])"
      )).filter(function (element) {
        return !element.hidden
          && element.getAttribute("aria-hidden") !== "true"
          && element.getClientRects().length > 0;
      });
    }

    function setOpenButtonsExpanded(expanded) {
      openButtons.forEach(function (button) {
        button.setAttribute("aria-expanded", expanded ? "true" : "false");
      });
    }

    function clearError() {
      if (!errorBox) return;
      errorBox.hidden = true;
      errorBox.textContent = "";
      [startInput, endInput].forEach(function (input) {
        if (!input) return;
        input.setCustomValidity("");
        input.removeAttribute("aria-invalid");
      });
    }

    function showError(message, target) {
      if (!errorBox) return;
      errorBox.textContent = message || copy.errorGeneric || "";
      errorBox.hidden = false;
      errorBox.scrollIntoView({ behavior: "smooth", block: "nearest" });

      if (target && typeof target.focus === "function") {
        target.focus({ preventScroll: true });
      } else {
        errorBox.focus({ preventScroll: true });
      }
    }

    function setBusy(nextBusy) {
      busy = Boolean(nextBusy);
      form.setAttribute("aria-busy", busy ? "true" : "false");
      form.querySelectorAll("input, button").forEach(function (control) {
        if (!control.hasAttribute("data-availability-request-close")) {
          control.disabled = busy;
        }
      });

      if (submitButton) submitButton.disabled = busy;
      if (submitLabel) {
        submitLabel.textContent = busy
          ? (copy.submitting || "")
          : (copy.submit || "");
      }
      if (spinner) spinner.hidden = !busy;
    }

    function syncChipState(input) {
      const label = input && input.closest(".availability-request-chip");
      if (!label) return;
      label.classList.toggle("is-selected", Boolean(input.checked));
    }

    function syncOnCallVisualState() {
      const label = onCallInput && onCallInput.closest(
        ".availability-request-on-call"
      );
      if (!label) return;
      label.classList.toggle("is-selected", Boolean(onCallInput.checked));
    }

    function selectedDayNumbers() {
      return dayInputs
        .filter(function (input) { return input.checked; })
        .map(function (input) { return Number(input.value); });
    }

    function selectedSlots() {
      return slotInputs
        .filter(function (input) { return input.checked; })
        .map(function (input) { return input.value; });
    }

    function sharedTimeValues() {
      return {
        start: startInput ? startInput.value.trim() : "",
        end: endInput ? endInput.value.trim() : ""
      };
    }

    function updateNextDayNote() {
      if (!nextDayNote) return;
      const times = sharedTimeValues();
      const startMinutes = timeToMinutes(times.start);
      const endMinutes = timeToMinutes(times.end);
      nextDayNote.hidden = !(
        startMinutes !== null
        && endMinutes !== null
        && endMinutes < startMinutes
      );
    }

    function collectSharedPayload() {
      const times = sharedTimeValues();
      return buildSharedPayload(
        selectedDayNumbers(),
        selectedSlots(),
        times.start,
        times.end,
        Boolean(onCallInput && onCallInput.checked)
      );
    }

    function targetForValidation(validation) {
      if (!validation) return null;
      if (validation.code === "select_day") {
        return dayInputs[0] || onCallInput;
      }
      if (validation.code === "empty_day") {
        return slotInputs[0] || startInput;
      }
      if (
        validation.code === "incomplete_interval"
        || validation.code === "invalid_interval"
        || validation.code === "invalid_night_interval"
      ) {
        return (!startInput?.value ? startInput : endInput) || startInput;
      }
      return dayInputs[0] || onCallInput;
    }

    function messageForValidation(validation) {
      if (!validation) return "";
      const messages = {
        select_day: copy.errorSelectDay,
        invalid_day: copy.errorSelectDay,
        empty_day: copy.errorEmptyDay,
        limit_per_day: copy.errorLimitPerDay,
        limit_total: copy.errorLimitTotal,
        incomplete_interval: copy.errorIncompleteInterval,
        invalid_interval: copy.errorInvalidInterval,
        invalid_night_interval: copy.errorInvalidNightInterval
      };
      return messages[validation.code] || copy.errorGeneric || "";
    }

    function validateSharedSelection(payload) {
      const times = sharedTimeValues();
      const hasScheduleCriteria = Boolean(
        selectedSlots().length || times.start || times.end
      );
      if (!selectedDayNumbers().length && hasScheduleCriteria) {
        return { code: "select_day" };
      }
      return validatePayload(payload);
    }

    function resetForm() {
      form.reset();
      dayInputs.concat(slotInputs).forEach(syncChipState);
      syncOnCallVisualState();
      updateNextDayNote();
      clearError();
      form.hidden = false;
      if (successBox) successBox.hidden = true;
      completed = false;
    }

    function lockBody() {
      const body = documentRef.body;
      bodyWasOverflowHidden = body.classList.contains("overflow-hidden");
      bodyWasModalOpen = body.classList.contains("modal-open");
      body.classList.add("overflow-hidden", "modal-open");
    }

    function unlockBody() {
      const body = documentRef.body;
      if (!bodyWasOverflowHidden) body.classList.remove("overflow-hidden");
      if (!bodyWasModalOpen) body.classList.remove("modal-open");
    }

    function rootRequestAnimationFrame(callback) {
      const view = documentRef.defaultView;
      if (view && typeof view.requestAnimationFrame === "function") {
        view.requestAnimationFrame(callback);
      } else {
        callback();
      }
    }

    function openDialog(trigger) {
      if (dialog.dataset.profilePhotoMissing === "1") {
        const view = documentRef.defaultView;
        if (view && typeof view.alert === "function") {
          view.alert(dialog.dataset.profilePhotoError || copy.errorGeneric || "");
        }
        if (view && view.location && dialog.dataset.profilePhotoUrl) {
          view.location.assign(dialog.dataset.profilePhotoUrl);
        }
        return;
      }
      if (completed) resetForm();
      previousFocus = trigger || documentRef.activeElement;
      dialog.hidden = false;
      dialog.setAttribute("aria-hidden", "false");
      setOpenButtonsExpanded(true);
      lockBody();
      documentRef.addEventListener("keydown", handleKeydown);

      rootRequestAnimationFrame(function () {
        (dayInputs[0] || sheet)?.focus({ preventScroll: true });
      });
    }

    function closeDialog() {
      if (dialog.hidden) return;
      requestController?.abort();
      requestController = null;
      setBusy(false);
      dialog.hidden = true;
      dialog.setAttribute("aria-hidden", "true");
      setOpenButtonsExpanded(false);
      unlockBody();
      documentRef.removeEventListener("keydown", handleKeydown);

      if (previousFocus && documentRef.contains(previousFocus)) {
        previousFocus.focus({ preventScroll: true });
      }
      previousFocus = null;
    }

    function handleKeydown(event) {
      if (dialog.hidden) return;

      if (event.key === "Escape") {
        event.preventDefault();
        closeDialog();
        return;
      }

      if (event.key !== "Tab") return;
      const focusable = getFocusableElements();
      if (!focusable.length) {
        event.preventDefault();
        sheet?.focus();
        return;
      }

      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && documentRef.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && documentRef.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
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

    async function submitRequest(event) {
      event.preventDefault();
      if (busy) return;
      clearError();

      const payload = collectSharedPayload();
      const validation = validateSharedSelection(payload);
      if (validation) {
        const target = targetForValidation(validation);
        const message = messageForValidation(validation);
        if (
          target
          && (target === startInput || target === endInput)
          && typeof target.setCustomValidity === "function"
        ) {
          target.setCustomValidity(message);
          target.setAttribute("aria-invalid", "true");
        }
        showError(message, target);
        return;
      }

      const endpoint = dialog.dataset.endpoint || "";
      const csrfToken = dialog.dataset.csrfToken || "";
      requestController = new AbortController();
      setBusy(true);

      try {
        const response = await fetch(endpoint, {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-CSRF-Token": csrfToken,
            "X-Requested-With": "XMLHttpRequest"
          },
          body: JSON.stringify(payload),
          signal: requestController.signal
        });
        const data = await parseResponse(response);

        if (
          data.code === "foto_profilo_richiesta"
          && typeof data.action_url === "string"
          && data.action_url
        ) {
          const view = documentRef.defaultView;
          if (view && typeof view.alert === "function") {
            view.alert(data.error || copy.errorGeneric || "");
          }
          if (view && view.location) {
            view.location.assign(data.action_url);
          }
          return;
        }

        if (!response.ok || data.ok === false) {
          const backendError = typeof data.error === "string"
            ? data.error.trim()
            : "";
          throw Object.assign(new Error("availability_request_failed"), {
            userMessage: backendError || copy.errorGeneric || ""
          });
        }

        completed = true;
        form.hidden = true;
        if (successBox) {
          successBox.hidden = false;
          successBox.tabIndex = -1;
          successBox.focus({ preventScroll: true });
        }

        documentRef.dispatchEvent(new CustomEvent(
          "localcare:richiesta-disponibilita-inviata",
          { detail: { payload: payload, response: data } }
        ));
      } catch (error) {
        if (error && error.name === "AbortError") return;
        showError(error.userMessage || copy.errorGeneric || "");
      } finally {
        requestController = null;
        setBusy(false);
      }
    }

    openButtons.forEach(function (button) {
      button.addEventListener("click", function () { openDialog(button); });
    });

    closeButtons.forEach(function (button) {
      button.addEventListener("click", closeDialog);
    });

    dialog.addEventListener("click", function (event) {
      if (event.target === dialog) closeDialog();
    });

    dayInputs.concat(slotInputs).forEach(function (input) {
      input.addEventListener("change", function () {
        syncChipState(input);
        clearError();
      });
    });

    onCallInput?.addEventListener("change", function () {
      syncOnCallVisualState();
      clearError();
    });

    [startInput, endInput].forEach(function (input) {
      input?.addEventListener("input", function () {
        clearError();
        updateNextDayNote();
      });
      input?.addEventListener("change", updateNextDayNote);
    });

    dayInputs.concat(slotInputs).forEach(syncChipState);
    syncOnCallVisualState();
    updateNextDayNote();
    form.addEventListener("submit", submitRequest);
  }

  return {
    SLOT_ORDER: SLOT_ORDER.slice(),
    MAX_INTERVALS_PER_DAY: MAX_INTERVALS_PER_DAY,
    MAX_INTERVALS_TOTAL: MAX_INTERVALS_TOTAL,
    intervalLimitCode: intervalLimitCode,
    buildPayload: buildPayload,
    buildSharedPayload: buildSharedPayload,
    validatePayload: validatePayload,
    timeToMinutes: timeToMinutes,
    init: init
  };
});
