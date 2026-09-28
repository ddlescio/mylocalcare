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
      if (button) {
        button.disabled = false;
        button.textContent = button.dataset.originalLabel || translate("Invia la richiesta");
      }
    }
  }

  async function postReferenceAction(button, action) {
    const endpoint = button.dataset.endpoint;
    if (!endpoint) return;
    if (action === "revoke" && !global.confirm(translate("Vuoi revocare questo invito? Il link non sarà più utilizzabile."))) {
      return;
    }

    button.disabled = true;
    const original = button.textContent;
    button.textContent = action === "revoke" ? translate("Revoca…") : translate("Invio…");

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
        body: JSON.stringify({})
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
    const publicText = form?.querySelector("input[name='autorizza_testo_pubblico']");
    const statement = form?.querySelector("textarea[name='testo_referente']");
    if (!publication || !publicText) return;

    const cannotConfirm = selected === "0";
    publication.disabled = cannotConfirm;
    if (cannotConfirm) {
      publication.checked = false;
    }

    const publicTextAllowed = (
      !cannotConfirm
      && publication.checked
      && Boolean(statement?.value.trim())
    );
    publicText.disabled = !publicTextAllowed;
    if (!publicTextAllowed) {
      publicText.checked = false;
    }
  }

  document.addEventListener("click", (event) => {
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
    const form = event.target.closest("#reference-invite-form");
    if (!form || !global.fetch || !global.FormData) return;
    event.preventDefault();
    submitInvite(form);
  });

  document.addEventListener("input", (event) => {
    if (event.target.matches("[data-reference-counted]")) {
      updateCounters(event.target.parentElement);
      if (event.target.matches("textarea[name='testo_referente']")) {
        updateDirectExperienceState(event.target.closest("form"));
      }
    }
  });

  document.addEventListener("change", (event) => {
    if (event.target.matches(
      "input[name='esperienza_diretta'], input[name='autorizza_pubblicazione']"
    )) {
      updateDirectExperienceState(event.target.closest("form"));
    }
  });

  document.addEventListener("DOMContentLoaded", () => {
    updateCounters(document);
    updateDirectExperienceState(document.querySelector("[data-reference-response-form]"));
  });

  global.MyLocalCareReferences = {
    openDialog,
    closeDialog,
    updateDirectExperienceState
  };
})(window);
