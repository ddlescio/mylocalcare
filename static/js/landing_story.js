document.documentElement.classList.add('lc-story-motion');

document.addEventListener('DOMContentLoaded', () => {
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const elements = document.querySelectorAll('#mylocalcare-story .lc-reveal');

  if (reducedMotion || !('IntersectionObserver' in window)) {
    elements.forEach((element) => element.classList.add('is-visible'));
  } else {
    const observer = new IntersectionObserver((entries, currentObserver) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add('is-visible');
        currentObserver.unobserve(entry.target);
      });
    }, {
      threshold: 0.12,
      rootMargin: '0px 0px -7% 0px'
    });

    elements.forEach((element) => observer.observe(element));
  }

  document.querySelectorAll('[data-lc-scroll-zone]').forEach((link) => {
    link.addEventListener('click', (event) => {
      const zoneInput = document.getElementById('macro-autocomplete');
      if (!zoneInput) return;

      event.preventDefault();
      zoneInput.scrollIntoView({
        behavior: reducedMotion ? 'auto' : 'smooth',
        block: 'center'
      });

      window.setTimeout(
        () => zoneInput.focus({ preventScroll: true }),
        reducedMotion ? 0 : 650
      );
    });
  });
});
