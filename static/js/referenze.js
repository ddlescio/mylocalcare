(function referenceUiBootstrap(global) {
  "use strict";

  if (global.__mlcReferencesUiLoaded) return;
  global.__mlcReferencesUiLoaded = true;

  const FOCUSABLE_SELECTOR = [
    "a[href]",
    "button:not([disabled])",
    "input:not([disabled]):not([type='hidden'])",
    "select:not([disabled])",
    "textarea:not([disabled])",
    "[tabindex]:not([tabindex='-1'])"
  ].join(",");

  let activeDialog = null;
  let returnFocusTo = null;

  function translate(value) {
    return typeof global.mlcTr === "function" ? global.mlcTr(value) : value;
  }

  function visibleFocusable(dialog) {
    return Array.from(dialog.querySelectorAll(FOCUSABLE_SELECTOR)).filter((element) => {
      return !element.hidden && element.getAttribute("aria-hidden") !== "true";
    });
  }

  function openDialog(dialog, trigger) {
    if (!dialog) return;
    activeDialog = dialog;
    returnFocusTo = trigger || document.activeElement;
    dialog.classList.remove("hidden");
    dialog.setAttribute("aria-hidden", "false");
    document.body.classList.add("reference-dialog-open");

    global.requestAnimationFrame(() => {
      const preferred = dialog.querySelector("[data-reference-dialog-close], [data-reference-public-close]");
      const first = preferred || visibleFocusable(dialog)[0];
      if (first) first.focus({ preventScroll: true });
    });
  }

  function closeDialog(dialog) {
    const target = dialog || activeDialog;
    if (!target) return;
    target.classList.add("hidden");
    target.setAttribute("aria-hidden", "true");
    document.body.classList.remove("reference-dialog-open");
    activeDialog = null;

    if (returnFocusTo && document.contains(returnFocusTo)) {
      returnFocusTo.focus({ preventScroll: true });
    }
    returnFocusTo = null;
  }

  function trapFocus(event) {
    if (!activeDialog || event.key !== "Tab") return;
    const focusable = visibleFocusable(activeDialog);
    if (!focusable.length) {
      event.preventDefault();
      return;
    }

    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  function csrfToken() {
    return document.querySelector("input[name='csrf_token']")?.value || "";
  }

  async function parseResponse(response) {
    const type = response.headers.get("content-type") || "";
    if (type.includes("application/json")) return response.json();
    return { ok: response.ok, error: response.ok ? "" : translate("Operazione non riuscita.") };
  }

  function setMessage(element, text) {
    if (!element) return;
    element.textContent = text || "";
    element.classList.toggle("hidden", !text);
  }

  function responseError(data, fallback) {
    if (data && typeof data.error === "string" && data.error.trim()) return translate(data.error.trim());
    if (data && typeof data.message === "string" && data.message.trim()) return translate(data.message.trim());
    return translate(fallback);
  }

  async function submitInvite(form) {
    if (form.dataset.referenceSubmitting === "1") return;
    form.dataset.referenceSubmitting = "1";

    const button = form.querySelector("[data-reference-submit]");
    const error = document.getElementById("reference-form-error");
    const success = document.getElementById("reference-form-success");
    const endpoint = form.dataset.referenceCreateEndpoint || form.action;

    setMessage(error, "");
    setMessage(success, "");
    if (button) {
      button.disabled = true;
      button.dataset.originalLabel = button.textContent;
      button.textContent = translate("Invio in corso…");
    }

    try {
      const response = await fetch(endpoint, {
        method: "POST",
        body: new FormData(form),
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          "X-Requested-With": "XMLHttpRequest",
          "X-CSRF-Token": csrfToken()
        }
      });
      const data = await parseResponse(response);
      if (!response.ok || data.ok === false) {
        throw new Error(responseError(data, "Non è stato possibile inviare la richiesta."));
      }
      setMessage(success, translate(data.message || "Richiesta inviata. Il referente riceverà un link personale."));
      form.reset();
      updateCounters(form);
      global.setTimeout(() => global.location.reload(), 800);
    } catch (requestError) {
      setMessage(error, translate(requestError.message || "Non è stato possibile inviare la richiesta."));
      error?.focus?.();
    } finally {
      delete form.dataset.referenceSubmitting;
      if (button) {
        button.disabled = false;
        button.textContent = button.dataset.originalLabel || translate("Invia la richiesta");
      }
    }
  }

  async function postReferenceAction(button, action) {
    const endpoint = button.dataset.endpoint;
    if (!endpoint) return;
    const confirmations = {
      resend: "Confermi di poter ancora usare il recapito del referente e di inviare un nuovo link? Quello precedente non sarà più utilizzabile.",
      revoke: "Vuoi revocare questo invito? Il link non sarà più utilizzabile.",
      restore: "Confermi di poter ancora usare il recapito del referente, ripristinare la richiesta e inviare un nuovo link?",
      delete: "Eliminare definitivamente questa richiesta? I recapiti salvati saranno rimossi e non potrai ripristinarla."
    };
    const confirmation = confirmations[action];
    if (confirmation && !global.confirm(translate(confirmation))) {
      return;
    }

    button.disabled = true;
    const original = button.textContent;
    const progressLabels = {
      resend: "Invio del nuovo link…",
      revoke: "Revoca…",
      restore: "Ripristino e invio…",
      delete: "Eliminazione…"
    };
    button.textContent = translate(progressLabels[action] || "Operazione in corso…");

    try {
      const response = await fetch(endpoint, {
        method: "POST",
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          "X-Requested-With": "XMLHttpRequest",
          "X-CSRF-Token": csrfToken()
        },
        body: JSON.stringify(
          action === "resend" || action === "restore"
            ? { conferma_condivisione_recapito: true }
            : {}
        )
      });
      const data = await parseResponse(response);
      if (!response.ok || data.ok === false) {
        throw new Error(responseError(data, translate("Operazione non riuscita.")));
      }
      global.location.reload();
    } catch (requestError) {
      global.alert(translate(requestError.message || "Operazione non riuscita."));
      button.disabled = false;
      button.textContent = original;
    }
  }

  async function postReferenceVisibility(button) {
    const endpoint = button.dataset.endpoint;
    const version = Number.parseInt(button.dataset.version || "0", 10);
    const currentlyVisible = button.dataset.visible === "1";
    if (!endpoint || !version) return;

    const confirmation = currentlyVisible
      ? "Vuoi nascondere questa referenza dal profilo pubblico?"
      : "Vuoi mostrare questa referenza nel profilo pubblico?";
    if (!global.confirm(translate(confirmation))) return;

    button.disabled = true;
    const original = button.textContent;
    button.textContent = translate("Aggiornamento…");
    try {
      const response = await fetch(endpoint, {
        method: "POST",
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          "X-Requested-With": "XMLHttpRequest",
          "X-CSRF-Token": csrfToken()
        },
        body: JSON.stringify({
          versione: version,
          visibile_profilo: currentlyVisible ? 0 : 1
        })
      });
      const data = await parseResponse(response);
      if (!response.ok || data.ok === false) {
        throw new Error(responseError(data, "Operazione non riuscita."));
      }
      global.location.reload();
    } catch (requestError) {
      global.alert(translate(requestError.message || "Operazione non riuscita."));
      button.disabled = false;
      button.textContent = original;
    }
  }

  function openPublicDetails(trigger) {
    const dialog = document.getElementById("reference-public-dialog");
    const content = document.getElementById("reference-public-dialog-content");
    const template = document.getElementById(trigger.dataset.referencePublicOpen || "");
    if (!dialog || !content || !template || template.tagName !== "TEMPLATE") return;

    content.replaceChildren(template.content.cloneNode(true));
    openDialog(dialog, trigger);
  }

  function updateCounters(root) {
    root.querySelectorAll("[data-reference-counted]").forEach((field) => {
      const counter = field.parentElement?.querySelector("[data-reference-character-count]");
      if (counter) counter.textContent = String(field.value.length);
    });
  }

  function updateDirectExperienceState(form) {
    const selected = form?.querySelector("input[name='esperienza_diretta']:checked")?.value;
    const publication = form?.querySelector("input[name='autorizza_pubblicazione']");
    if (!publication) return;

    const cannotConfirm = selected === "0";
    publication.disabled = cannotConfirm;
    if (cannotConfirm) {
      publication.checked = false;
    }
    updateContactConsentState(form);
  }

  function enabledConsentOptions(form) {
    return Array.from(
      form?.querySelectorAll("[data-reference-consent-option]") || []
    ).filter((input) => !input.disabled);
  }

  function acceptAllConsents(form) {
    enabledConsentOptions(form).forEach((input) => {
      input.checked = true;
    });
    updateContactConsentState(form);

    const phone = form?.querySelector("input[name='referente_telefono']");
    if (phone?.required && !phone.value.trim()) {
      phone.focus({ preventScroll: false });
    }
  }

  function updateContactConsentState(form) {
    const consent = form?.querySelector("[data-reference-contact-consent]");
    const details = form?.querySelector("[data-reference-contact-details]");
    const phone = details?.querySelector("input[name='referente_telefono']");
    if (!consent || !details || !phone) return;

    const cannotConfirm = (
      form?.querySelector("input[name='esperienza_diretta']:checked")?.value === "0"
    );
    if (cannotConfirm) {
      phone.value = "";
      consent.checked = false;
    }
    phone.disabled = cannotConfirm;
    consent.disabled = cannotConfirm;
    const hasPhone = Boolean(phone.value.trim());
    // Il telefono e il consenso sono facoltativi come coppia: se viene
    // compilato uno dei due, il browser richiede anche l'altro.
    consent.required = hasPhone;
    phone.required = consent.checked;
    consent.setAttribute("aria-required", hasPhone ? "true" : "false");
    phone.setAttribute("aria-required", consent.checked ? "true" : "false");
  }

  document.addEventListener("click", (event) => {
    const acceptAll = event.target.closest("[data-reference-accept-all]");
    if (acceptAll) {
      event.preventDefault();
      acceptAllConsents(acceptAll.closest("form"));
      return;
    }

    const publicTrigger = event.target.closest("[data-reference-public-open]");
    if (publicTrigger) {
      event.preventDefault();
      openPublicDetails(publicTrigger);
      return;
    }

    const publicClose = event.target.closest("[data-reference-public-close]");
    if (publicClose) {
      event.preventDefault();
      closeDialog(publicClose.closest(".reference-dialog"));
      return;
    }

    const resend = event.target.closest("[data-reference-resend]");
    if (resend) {
      event.preventDefault();
      postReferenceAction(resend, "resend");
      return;
    }

    const revoke = event.target.closest("[data-reference-revoke]");
    if (revoke) {
      event.preventDefault();
      postReferenceAction(revoke, "revoke");
      return;
    }

    const restore = event.target.closest("[data-reference-restore]");
    if (restore) {
      event.preventDefault();
      postReferenceAction(restore, "restore");
      return;
    }

    const remove = event.target.closest("[data-reference-delete]");
    if (remove) {
      event.preventDefault();
      postReferenceAction(remove, "delete");
      return;
    }

    const visibility = event.target.closest("[data-reference-visibility]");
    if (visibility) {
      event.preventDefault();
      postReferenceVisibility(visibility);
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && activeDialog) {
      event.preventDefault();
      closeDialog(activeDialog);
      return;
    }
    trapFocus(event);
  });

  document.addEventListener("submit", (event) => {
    const responseForm = event.target.closest("[data-reference-response-form]");
    if (responseForm) {
      const missingConsent = enabledConsentOptions(responseForm).some(
        (input) => !input.checked
      );
      if (missingConsent) {
        const message = responseForm.dataset.referenceIncompleteConfirm || "";
        if (!global.confirm(message)) {
          event.preventDefault();
        }
      }
      return;
    }

    const form = event.target.closest("#reference-invite-form");
    if (!form || !global.fetch || !global.FormData) return;
    event.preventDefault();
    if (form.dataset.referenceSubmitting === "1") return;
    submitInvite(form);
  });

  document.addEventListener("input", (event) => {
    if (event.target.matches("[data-reference-counted]")) {
      updateCounters(event.target.parentElement);
    }
    if (event.target.matches("input[name='referente_telefono']")) {
      updateContactConsentState(event.target.closest("form"));
    }
  });

  document.addEventListener("change", (event) => {
    if (event.target.matches(
      "input[name='esperienza_diretta']"
    )) {
      updateDirectExperienceState(event.target.closest("form"));
    }
    if (event.target.matches("[data-reference-contact-consent]")) {
      updateContactConsentState(event.target.closest("form"));
    }
  });

  document.addEventListener("DOMContentLoaded", () => {
    updateCounters(document);
    const responseForm = document.querySelector("[data-reference-response-form]");
    updateDirectExperienceState(responseForm);
    updateContactConsentState(responseForm);
  });

  global.MyLocalCareReferences = {
    openDialog,
    closeDialog,
    updateDirectExperienceState,
    updateContactConsentState,
    acceptAllConsents
  };
})(window);
