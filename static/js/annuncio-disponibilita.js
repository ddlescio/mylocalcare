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
    const action = container.querySelector("[data-listing-availability-action]");
    const days = Array.from(container.querySelectorAll("[data-listing-availability-day]"));
    const slots = Array.from(container.querySelectorAll("[data-listing-availability-slot]"));
    const statusInputs = Array.from(
      container.querySelectorAll("[data-listing-availability-status]")
    );
    const onCall = container.querySelector("[data-listing-availability-on-call]");
    const start = container.querySelector("[data-listing-availability-start]");
    const end = container.querySelector("[data-listing-availability-end]");
    const reset = container.querySelector("[data-listing-availability-reset]");
    const errorBox = container.querySelector("[data-listing-availability-error]");
    const nextDay = container.querySelector("[data-listing-availability-next-day]");
    const title = container.querySelector("[data-listing-availability-title]");
    const hint = container.querySelector("[data-listing-availability-hint]");
    const summary = container.querySelector("[data-listing-availability-summary]");
    const summaryTitle = container.querySelector(
      "[data-listing-availability-summary-title]"
    );
    const statusGroup = container.querySelector(
      "[data-listing-availability-status-group]"
    );
    const positiveDetails = container.querySelector(
      "[data-listing-availability-positive-details]"
    );
    const unavailableNote = container.querySelector(
      "[data-listing-availability-unavailable-note]"
    );
    const optionalHeading = container.querySelector(
      "[data-listing-availability-optional-heading]"
    );
    const initialNode = container.querySelector(
      "[data-listing-availability-initial]"
    );
    const soughtOnly = Boolean(
      container.dataset
      && container.dataset.listingAvailabilitySoughtOnly === "true"
    );
    const typeInputs = Array.from(document.querySelectorAll('input[name="tipo_annuncio"]'));
    const categoryInput = document.querySelector('select[name="categoria"]');
    let currentTypeValue = (typeInputs.find(function (input) {
      return input.checked;
    }) || {}).value || "";
    let currentCategoryValue = categoryInput ? categoryInput.value : "";
    const copyNode = document.getElementById("listing-availability-copy");
    let copy = {};
    let initialPayload = null;
    let initialPristine = false;
    let userChanged = false;
    const initialAction = action && action.value ? action.value : "keep";
    try { copy = JSON.parse(copyNode ? copyNode.textContent : "{}"); } catch (error) {}

    function selectedValues(inputs) {
      return inputs.filter(function (input) { return input.checked; })
        .map(function (input) { return input.value; });
    }

    function setAction(value) {
      if (action) action.value = value;
    }

    function selectedTypeValue() {
      const selected = document.querySelector('input[name="tipo_annuncio"]:checked');
      return selected ? selected.value : "";
    }

    function isOffer() {
      return selectedTypeValue() === "offro";
    }

    function selectedStatus() {
      const selected = statusInputs.find(function (input) {
        return input.checked;
      });
      // Compatibilita prudente con pagine in cache che non hanno ancora i
      // nuovi controlli: una nuova offerta nasce comunque disponibile.
      return selected ? selected.value : "disponibile";
    }

    function selectAvailableStatus() {
      statusInputs.forEach(function (input) {
        input.checked = input.value === "disponibile";
      });
    }

    function updateStatusChoices() {
      statusInputs.forEach(function (input) {
        const option = typeof input.closest === "function"
          ? input.closest(".listing-availability__status-option")
          : null;
        if (option && option.classList) {
          option.classList.toggle("is-selected", Boolean(input.checked));
        }
      });
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
      setAction(initialAction);
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

    function sync(markAsChanged) {
      initialPristine = false;
      if (markAsChanged !== false) {
        userChanged = true;
        setAction("update");
      }
      clearError();
      updateNextDay();
      if (!hidden) return;
      hidden.value = isCompletelyEmpty() ? "" : JSON.stringify(payload());
    }

    function clearOptionalDetails() {
      initialPayload = null;
      initialPristine = false;
      days.concat(slots).forEach(function (input) { input.checked = false; });
      if (onCall) onCall.checked = false;
      if (start) start.value = "";
      if (end) end.value = "";
      if (hidden) hidden.value = "";
      updateNextDay();
    }

    function clearSelection(nextAction, resetStatus) {
      clearOptionalDetails();
      if (resetStatus !== false) selectAvailableStatus();
      setAction(nextAction || "clear");
      clearError();
    }

    function updateCopy() {
      const offerMode = isOffer();
      if (soughtOnly) container.hidden = offerMode;
      const nextTitle = offerMode ? copy.offerTitle : copy.seekTitle;
      const nextHint = offerMode ? copy.offerHint : copy.seekHint;
      if (title) title.textContent = nextTitle || "";
      if (hint) hint.textContent = nextHint || "";
      if (summaryTitle) {
        summaryTitle.textContent = (
          offerMode ? copy.offerSummaryTitle : copy.seekSummaryTitle
        ) || "";
      }
      if (summary) {
        if (offerMode) {
          const statusLabels = {
            disponibile: copy.availableLabel,
            limitata: copy.limitedLabel,
            non_disponibile: copy.unavailableLabel
          };
          const label = statusLabels[selectedStatus()] || copy.availableLabel || "";
          summary.textContent = [label, copy.offerSummary]
            .filter(Boolean)
            .join(" · ");
        } else {
          summary.textContent = nextHint || "";
        }
      }
      if (statusGroup) statusGroup.hidden = !offerMode;
      if (optionalHeading) {
        optionalHeading.textContent = (
          offerMode ? copy.offerDetails : copy.seekDetails
        ) || "";
      }
      const unavailable = offerMode && selectedStatus() === "non_disponibile";
      if (positiveDetails) positiveDetails.hidden = unavailable;
      if (unavailableNote) unavailableNote.hidden = !unavailable;
      if (unavailable && onCall) onCall.checked = false;
      updateStatusChoices();
      if (offerMode) container.open = true;
    }

    function validateBeforeSubmit() {
      const selected = document.querySelector('input[name="tipo_annuncio"]:checked');
      if (soughtOnly && selected && selected.value === "offro") {
        clearError();
        return true;
      }
      if (isOffer() && selectedStatus() === "non_disponibile") {
        clearOptionalDetails();
        clearError();
        return true;
      }
      // Una disponibilita puo essere composta dal solo stato generale, senza
      // giorni, fasce o orari. In quel caso non esiste un payload iniziale da
      // idratare: una normale modifica di titolo, foto o descrizione deve
      // comunque lasciare l'azione su ``keep`` e non riconfermare la data.
      if (
        !userChanged
        && action
        && action.value === "keep"
      ) {
        clearError();
        updateNextDay();
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
    statusInputs.forEach(function (input) {
      input.addEventListener("change", function () {
        if (input.checked && input.value === "non_disponibile") {
          clearOptionalDetails();
        }
        sync();
        updateCopy();
      });
    });
    [onCall, start, end].forEach(function (input) {
      if (!input) return;
      input.addEventListener("change", sync);
      input.addEventListener("input", sync);
    });
    typeInputs.forEach(function (input) {
      input.addEventListener("change", function () {
        // Giorni e orari di un'offerta non devono diventare per errore i
        // requisiti di una ricerca (o viceversa).
        if (input.value !== currentTypeValue) {
          clearSelection(input.value === "offro" ? "update" : "clear");
          currentTypeValue = input.value;
        }
        updateCopy();
      });
    });
    if (categoryInput) {
      categoryInput.addEventListener("change", function () {
        // La disponibilita appartiene alla categoria: cambiandola si parte
        // da una selezione vuota, senza copiare l'agenda precedente.
        if (categoryInput.value !== currentCategoryValue) {
          clearSelection(isOffer() ? "ensure" : "clear");
          currentCategoryValue = categoryInput.value;
          updateCopy();
        }
      });
    }

    if (reset) {
      reset.addEventListener("click", function () {
        clearSelection(isOffer() ? "update" : "clear");
        updateCopy();
      });
    }

    root.MyLocalCareListingAvailability = {
      sync: sync,
      validateBeforeSubmit: validateBeforeSubmit
    };
    updateCopy();
    if (!hydrateInitial()) sync(false);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})(window);
