(function (root) {
  "use strict";

  function validateSharedSelection(api, dayNumbers, slots, start, end, onCall) {
    const selectedDays = Array.isArray(dayNumbers) ? dayNumbers : [];
    const selectedSlots = Array.isArray(slots) ? slots : [];
    const normalizedStart = String(start || "");
    const normalizedEnd = String(end || "");

    // Fasce e intervalli appartengono sempre a uno o piu giorni. Senza
    // questo controllo buildSharedPayload li scarterebbe e, in presenza di
    // "A chiamata", il payload ridotto risulterebbe comunque valido.
    if (
      !selectedDays.length
      && (selectedSlots.length || normalizedStart || normalizedEnd)
    ) {
      return { code: "select_day" };
    }

    return api.validatePayload(api.buildSharedPayload(
      selectedDays,
      selectedSlots,
      normalizedStart,
      normalizedEnd,
      onCall === true
    ));
  }

  root.MyLocalCareListingAvailabilityRules = {
    validateSharedSelection: validateSharedSelection
  };

  function init() {
    const container = document.querySelector("[data-listing-availability]");
    const api = root.MyLocalCareAvailabilityRequest;
    if (!container || !api) return;

    const hidden = container.querySelector("[data-listing-availability-json]");
    const days = Array.from(container.querySelectorAll("[data-listing-availability-day]"));
    const slots = Array.from(container.querySelectorAll("[data-listing-availability-slot]"));
    const onCall = container.querySelector("[data-listing-availability-on-call]");
    const start = container.querySelector("[data-listing-availability-start]");
    const end = container.querySelector("[data-listing-availability-end]");
    const reset = container.querySelector("[data-listing-availability-reset]");
    const errorBox = container.querySelector("[data-listing-availability-error]");
    const nextDay = container.querySelector("[data-listing-availability-next-day]");
    const title = container.querySelector("[data-listing-availability-title]");
    const hint = container.querySelector("[data-listing-availability-hint]");
    const summary = container.querySelector("[data-listing-availability-summary]");
    const initialNode = container.querySelector(
      "[data-listing-availability-initial]"
    );
    const soughtOnly = Boolean(
      container.dataset
      && container.dataset.listingAvailabilitySoughtOnly === "true"
    );
    const typeInputs = Array.from(document.querySelectorAll('input[name="tipo_annuncio"]'));
    const copyNode = document.getElementById("listing-availability-copy");
    let copy = {};
    let initialPayload = null;
    let initialPristine = false;
    try { copy = JSON.parse(copyNode ? copyNode.textContent : "{}"); } catch (error) {}

    function selectedValues(inputs) {
      return inputs.filter(function (input) { return input.checked; })
        .map(function (input) { return input.value; });
    }

    function isCompletelyEmpty() {
      return !selectedValues(days).length
        && !selectedValues(slots).length
        && !Boolean(onCall && onCall.checked)
        && !String(start && start.value || "")
        && !String(end && end.value || "");
    }

    function payload() {
      return api.buildSharedPayload(
        selectedValues(days).map(Number),
        selectedValues(slots),
        start ? start.value : "",
        end ? end.value : "",
        Boolean(onCall && onCall.checked)
      );
    }

    function hydrateInitial() {
      let parsed = null;
      try {
        parsed = JSON.parse(initialNode ? initialNode.textContent : "null");
      } catch (error) {
        parsed = null;
      }
      if (!parsed || api.validatePayload(parsed)) return false;

      const initialDays = Array.isArray(parsed.giorni) ? parsed.giorni : [];
      const selectedDays = new Set(initialDays.map(function (day) {
        return Number(day && day.giorno_settimana);
      }));
      days.forEach(function (input) {
        input.checked = selectedDays.has(Number(input.value));
      });

      // Il selettore compatto applica fasce e intervallo a tutti i giorni.
      // Mostriamo quindi soltanto i valori realmente comuni, conservando nel
      // campo nascosto il payload canonico completo finche l'utente non edita.
      slots.forEach(function (input) {
        input.checked = Boolean(initialDays.length) && initialDays.every(
          function (day) {
            return Array.isArray(day.fasce) && day.fasce.includes(input.value);
          }
        );
      });

      const commonInterval = initialDays.length
        && initialDays.every(function (day) {
          return Array.isArray(day.intervalli) && day.intervalli.length === 1;
        })
        ? initialDays[0].intervalli[0]
        : null;
      const sameInterval = commonInterval && initialDays.every(function (day) {
        const interval = day.intervalli[0];
        return interval.ora_inizio === commonInterval.ora_inizio
          && interval.ora_fine === commonInterval.ora_fine
          && Boolean(interval.giorno_successivo)
            === Boolean(commonInterval.giorno_successivo);
      });
      if (start) start.value = sameInterval ? commonInterval.ora_inizio : "";
      if (end) end.value = sameInterval ? commonInterval.ora_fine : "";
      if (onCall) onCall.checked = parsed.a_chiamata === true;

      initialPayload = parsed;
      initialPristine = true;
      if (hidden) hidden.value = JSON.stringify(parsed);
      updateNextDay();
      return true;
    }

    function messageFor(validation) {
      const code = validation && validation.code;
      if (code === "select_day") return copy.selectDay;
      if (code === "empty_day") return copy.emptyDay;
      if (code === "incomplete_interval") return copy.incompleteInterval;
      if (code === "invalid_interval") return copy.invalidInterval;
      if (code === "invalid_night_interval") return copy.invalidNightInterval;
      return copy.generic;
    }

    function clearError() {
      if (!errorBox) return;
      errorBox.hidden = true;
      errorBox.textContent = "";
    }

    function updateNextDay() {
      if (!nextDay) return;
      const startMinutes = api.timeToMinutes(start ? start.value : "");
      const endMinutes = api.timeToMinutes(end ? end.value : "");
      nextDay.hidden = !(
        startMinutes !== null && endMinutes !== null && endMinutes < startMinutes
      );
    }

    function sync() {
      initialPristine = false;
      clearError();
      updateNextDay();
      if (!hidden) return;
      hidden.value = isCompletelyEmpty() ? "" : JSON.stringify(payload());
    }

    function updateCopy() {
      const selected = document.querySelector('input[name="tipo_annuncio"]:checked');
      const isOffer = selected && selected.value === "offro";
      if (soughtOnly) container.hidden = Boolean(isOffer);
      const nextTitle = isOffer ? copy.offerTitle : copy.seekTitle;
      const nextHint = isOffer ? copy.offerHint : copy.seekHint;
      if (title) title.textContent = nextTitle || "";
      if (hint) hint.textContent = nextHint || "";
      if (summary) summary.textContent = nextHint || "";
    }

    function validateBeforeSubmit() {
      const selected = document.querySelector('input[name="tipo_annuncio"]:checked');
      if (soughtOnly && selected && selected.value === "offro") {
        clearError();
        return true;
      }
      if (initialPristine && initialPayload) {
        clearError();
        updateNextDay();
        if (hidden) hidden.value = JSON.stringify(initialPayload);
        const initialValidation = api.validatePayload(initialPayload);
        if (!initialValidation) return true;
        const initialMessage = messageFor(initialValidation) || copy.generic || "";
        if (errorBox) {
          errorBox.textContent = initialMessage;
          errorBox.hidden = false;
        }
        container.open = true;
        return false;
      }
      sync();
      if (isCompletelyEmpty()) return true;
      const validation = validateSharedSelection(
        api,
        selectedValues(days).map(Number),
        selectedValues(slots),
        start ? start.value : "",
        end ? end.value : "",
        Boolean(onCall && onCall.checked)
      );
      if (!validation) return true;
      const message = messageFor(validation) || copy.generic || "";
      if (errorBox) {
        errorBox.textContent = message;
        errorBox.hidden = false;
      }
      container.open = true;
      container.scrollIntoView({ behavior: "smooth", block: "center" });
      return false;
    }

    days.concat(slots).forEach(function (input) {
      input.addEventListener("change", sync);
    });
    [onCall, start, end].forEach(function (input) {
      if (!input) return;
      input.addEventListener("change", sync);
      input.addEventListener("input", sync);
    });
    typeInputs.forEach(function (input) {
      input.addEventListener("change", updateCopy);
    });

    if (reset) {
      reset.addEventListener("click", function () {
        initialPayload = null;
        initialPristine = false;
        days.concat(slots).forEach(function (input) { input.checked = false; });
        if (onCall) onCall.checked = false;
        if (start) start.value = "";
        if (end) end.value = "";
        sync();
      });
    }

    root.MyLocalCareListingAvailability = {
      sync: sync,
      validateBeforeSubmit: validateBeforeSubmit
    };
    updateCopy();
    if (!hydrateInitial()) sync();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})(window);
