const filterForms = document.querySelectorAll(".log-controls form, .tail-controls form");

function filtersKey(path) {
  return `esphome-log-collector:filters:${path}`;
}

function updateTabLinks() {
  for (const path of ["/logs", "/tail"]) {
    const query = sessionStorage.getItem(filtersKey(path));
    const link = document.querySelector(`nav a[href^="${path}"]`);
    if (query !== null && link) {
      link.href = query ? `${path}?${query}` : path;
    }
  }
}

for (const form of filterForms) {
  const path = new URL(form.action).pathname;
  const saveFilters = () => {
    const params = new URLSearchParams();
    for (const [key, value] of new FormData(form)) {
      if (typeof value === "string" && value) params.append(key, value);
    }
    sessionStorage.setItem(filtersKey(path), params.toString());
    updateTabLinks();
  };

  form.addEventListener("input", saveFilters);
  form.addEventListener("change", saveFilters);
  form.addEventListener("submit", saveFilters);

  if (location.pathname === path && location.search) {
    saveFilters();
  }
}

const fontSettings = {
  logs: { selector: ".logs-terminal", property: "--log-font-size", min: 10, max: 24 },
  tail: { selector: "#tail-rows", property: "--tail-font-size", min: 10, max: 24 },
};

for (const [target, setting] of Object.entries(fontSettings)) {
  const element = document.querySelector(setting.selector);
  if (!element) continue;

  const key = `esphome-log-collector:font:${target}`;
  const savedSize = Number(sessionStorage.getItem(key));
  if (Number.isFinite(savedSize) && savedSize >= setting.min && savedSize <= setting.max) {
    element.style.setProperty(setting.property, `${savedSize}px`);
  }

  for (const button of document.querySelectorAll(`[data-font-target="${target}"]`)) {
    button.addEventListener("click", () => {
      const current = Number.parseFloat(getComputedStyle(element).fontSize);
      const step = Number(button.dataset.fontStep);
      const size = Math.min(setting.max, Math.max(setting.min, current + step));
      element.style.setProperty(setting.property, `${size}px`);
      sessionStorage.setItem(key, String(size));
    });
  }
}

updateTabLinks();
