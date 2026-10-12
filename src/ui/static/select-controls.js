/* Independent EngineAccounts enhancement. Native controls remain the form source. */
(() => {
  'use strict';
  const controls = new Map();
  let serial = 0;
  let current = null;
  let sheet;
  const eligible = select => !select.multiple && select.size <= 1;
  const optionsOf = select => Array.from(select.options, (option, index) => {
    const group = option.parentElement?.tagName === 'OPTGROUP' ? option.parentElement : null;
    return { index, label: option.label, disabled: option.disabled || Boolean(group?.disabled),
      hidden: option.hidden || Boolean(group?.hidden), group };
  });
  const position = (rect, viewport, desired) => {
    const { width, height, offsetLeft = 0, offsetTop = 0 } = viewport;
    const menuWidth = Math.min(Math.max(rect.width, 180), Math.max(0, width - 16));
    const below = Math.max(0, offsetTop + height - rect.bottom - 14);
    const above = Math.max(0, rect.top - offsetTop - 14);
    const flip = below < desired && above > below;
    const maxHeight = Math.min(320, flip ? above : below);
    return { width: menuWidth, maxHeight,
      left: Math.min(Math.max(offsetLeft + 8, rect.left), offsetLeft + width - 8 - menuWidth),
      top: flip ? Math.max(offsetTop + 8, rect.top - 6 - Math.min(desired, maxHeight)) : rect.bottom + 6 };
  };
  function positioningSheet() {
    if (sheet) return sheet;
    // Updating an external stylesheet via CSSOM does not create a style attribute.
    sheet = Array.from(document.styleSheets).find(item => item.href && /\/select-controls\.css(?:\?|$)/.test(item.href));
    if (!sheet && typeof CSSStyleSheet !== 'undefined' && 'adoptedStyleSheets' in document) {
      sheet = new CSSStyleSheet();
      document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
    }
    return sheet;
  }
  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function icon(className, pathData) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('class', className); svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none'); svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2'); svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round'); svg.setAttribute('aria-hidden', 'true');
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', pathData); svg.append(path); return svg;
  }
  function enhance(select) {
    if (controls.has(select) || !eligible(select) || !positioningSheet()) return;
    const id = `ea-select-${++serial}`;
    const wrap = element('span', 'ea-select-wrap');
    const trigger = element('button', 'ea-select-trigger');
    const value = element('span', 'ea-select-value');
    const arrow = icon('ea-select-chevron', 'm6 9 6 6 6-6');
    const menu = element('div', 'ea-select-popover');
    const oldTab = select.getAttribute('tabindex');
    const oldHidden = select.getAttribute('aria-hidden');
    menu.id = `${id}-listbox`; menu.setAttribute('role', 'listbox'); menu.hidden = true;
    const popover = typeof menu.showPopover === 'function';
    if (popover) menu.setAttribute('popover', 'manual');
    trigger.type = 'button'; trigger.id = `${id}-trigger`;
    trigger.setAttribute('role', 'combobox'); trigger.setAttribute('aria-haspopup', 'listbox');
    trigger.setAttribute('aria-controls', menu.id); trigger.setAttribute('aria-expanded', 'false');
    arrow.setAttribute('aria-hidden', 'true'); trigger.append(value, arrow);
    select.before(wrap); wrap.append(select, trigger);
    document.body.append(menu);
    select.classList.add('ea-select-native'); select.tabIndex = -1; select.setAttribute('aria-hidden', 'true');
    let snapshot = [], active = -1, open = false, search = '', searchTime = 0;
    let rule = null;
    let validationFailed = false;
    const nativeListeners = [];
    const listenNative = (type, listener) => {
      select.addEventListener(type, listener); nativeListeners.push([type, listener]);
    };
    const enabled = () => snapshot.filter(option => !option.disabled && !option.hidden);
    function sync() {
      snapshot = optionsOf(select);
      value.textContent = snapshot[select.selectedIndex]?.label ?? '\u00a0';
      trigger.disabled = select.matches(':disabled');
      trigger.tabIndex = oldTab === null ? 0 : Number(oldTab);
      for (const attr of ['aria-label', 'aria-labelledby', 'aria-describedby', 'aria-invalid', 'aria-errormessage', 'title', 'dir']) {
        if (select.hasAttribute(attr)) trigger.setAttribute(attr, select.getAttribute(attr));
        else trigger.removeAttribute(attr);
      }
      if (!select.hasAttribute('aria-label') && !select.hasAttribute('aria-labelledby')) {
        const labels = Array.from(select.labels ?? [], (label, index) => {
          if (!label.id) label.id = `${id}-label-${index}`;
          return label.id;
        });
        if (labels.length) trigger.setAttribute('aria-labelledby', labels.join(' '));
      }
      trigger.setAttribute('aria-required', String(select.required || select.getAttribute('aria-required') === 'true'));
      if (validationFailed && select.validity.valid) validationFailed = false;
      if (validationFailed) trigger.setAttribute('aria-invalid', 'true');
      for (const attr of ['aria-label', 'aria-labelledby', 'dir']) {
        if (trigger.hasAttribute(attr)) menu.setAttribute(attr, trigger.getAttribute(attr));
        else menu.removeAttribute(attr);
      }
      if (trigger.disabled) close();
      if (open) { render(); place(); }
    }
    function setActive(index) {
      active = index;
      if (open && active >= 0) trigger.setAttribute('aria-activedescendant', `${id}-option-${active}`);
      else trigger.removeAttribute('aria-activedescendant');
      for (const node of menu.querySelectorAll('[role="option"]')) {
        node.dataset.active = String(node.id === `${id}-option-${active}`);
        if (node.dataset.active === 'true') {
          if (node.offsetTop < menu.scrollTop) menu.scrollTop = node.offsetTop;
          else if (node.offsetTop + node.offsetHeight > menu.scrollTop + menu.clientHeight)
            menu.scrollTop = node.offsetTop + node.offsetHeight - menu.clientHeight;
        }
      }
    }
    function render() {
      menu.replaceChildren();
      const groups = new Map();
      for (const option of snapshot.filter(item => !item.hidden)) {
        let host = menu;
        if (option.group) {
          if (!groups.has(option.group)) {
            const group = element('div', 'ea-select-group');
            group.setAttribute('role', 'group'); group.setAttribute('aria-label', option.group.label);
            const label = element('div', 'ea-select-group-label', option.group.label);
            label.setAttribute('aria-hidden', 'true'); group.append(label); menu.append(group);
            groups.set(option.group, group);
          }
          host = groups.get(option.group);
        }
        const row = element('div', 'ea-select-option');
        row.id = `${id}-option-${option.index}`; row.setAttribute('role', 'option');
        row.setAttribute('aria-selected', String(option.index === select.selectedIndex));
        row.setAttribute('aria-disabled', String(option.disabled));
        row.append(element('span', '', option.label));
        if (option.index === select.selectedIndex) {
          row.append(icon('ea-select-check', 'M20 6 9 17l-5-5'));
        }
        row.addEventListener('pointermove', event => {
          if (event.pointerType !== 'touch' && !option.disabled) setActive(option.index);
        });
        row.addEventListener('click', () => choose(option.index)); host.append(row);
      }
      if (!enabled().some(option => option.index === active)) active = enabled()[0]?.index ?? -1;
      setActive(active);
    }
    function place() {
      if (!open) return;
      const rect = trigger.getBoundingClientRect();
      const viewport = window.visualViewport ?? { width: window.innerWidth, height: window.innerHeight };
      if (rect.bottom < (viewport.offsetTop ?? 0) || rect.top > (viewport.offsetTop ?? 0) + viewport.height) { close(); return; }
      if (!rule) {
        const index = sheet.insertRule(`#${menu.id} {}`, sheet.cssRules.length);
        rule = sheet.cssRules[index];
      }
      // Measure wrapping at the final width before deciding whether to flip.
      rule.style.setProperty('width', `${position(rect, viewport, 320).width}px`);
      const p = position(rect, viewport, Math.min(menu.scrollHeight + 2 || 320, 320));
      for (const [key, number] of Object.entries(p)) rule.style.setProperty(key === 'maxHeight' ? 'max-height' : key, `${number}px`);
    }
    function show(edge) {
      sync(); if (trigger.disabled) return;
      current?.close(); current = control;
      const items = enabled();
      active = edge === 'first' ? items[0]?.index ?? -1 : edge === 'last' ? items.at(-1)?.index ?? -1 :
        items.find(item => item.index === select.selectedIndex)?.index ?? items[0]?.index ?? -1;
      open = true; search = ''; searchTime = 0;
      trigger.focus({ preventScroll: true }); trigger.setAttribute('aria-expanded', 'true');
      (trigger.closest('dialog[open]') ?? document.fullscreenElement ?? document.body).append(menu);
      menu.hidden = false; render();
      if (popover) menu.showPopover();
      place(); setActive(active);
    }
    function close() {
      if (popover && open) menu.hidePopover();
      open = false; menu.hidden = true;
      trigger.setAttribute('aria-expanded', 'false'); trigger.removeAttribute('aria-activedescendant');
      if (current === control) current = null;
    }
    function choose(index) {
      const option = snapshot[index];
      if (select.matches(':disabled') || !option || option.disabled || option.hidden) return;
      if (select.selectedIndex !== index) {
        // Index preserves the correct option even when values are duplicated.
        select.selectedIndex = index;
        select.dispatchEvent(new Event('input', { bubbles: true }));
        select.dispatchEvent(new Event('change', { bubbles: true }));
      }
      close(); sync(); trigger.focus({ preventScroll: true });
    }
    function keydown(event) {
      const key = event.key;
      if (key === 'Tab') { close(); return; }
      if (key === 'Escape') { if (open) { event.preventDefault(); event.stopPropagation(); close(); } return; }
      if (event.ctrlKey || event.metaKey || (event.altKey && !['ArrowDown', 'ArrowUp'].includes(key))) return;
      if (['ArrowDown', 'ArrowUp', 'Home', 'End', 'Enter', ' '].includes(key)) {
        event.preventDefault(); event.stopPropagation();
        if (event.altKey && key === 'ArrowUp') { close(); return; }
        if (!open) { show(key === 'Home' ? 'first' : key === 'End' ? 'last' : undefined); return; }
        if (key === 'Enter' || (key === ' ' && (!search || Date.now() - searchTime >= 700))) { choose(active); return; }
        const items = enabled(), index = items.findIndex(item => item.index === active);
        if (key === 'Home') setActive(items[0]?.index ?? -1);
        else if (key === 'End') setActive(items.at(-1)?.index ?? -1);
        else if (key === 'ArrowDown') setActive(items[Math.min(index + 1, items.length - 1)]?.index ?? -1);
        else if (key === 'ArrowUp') setActive(items[Math.max(0, index - 1)]?.index ?? -1);
        if (key !== ' ') return;
      }
      if (key.length !== 1 || event.altKey) return;
      event.preventDefault();
      sync(); const now = Date.now();
      search = (now - searchTime < 700 ? search : '') + key.toLocaleLowerCase(); searchTime = now;
      const query = Array.from(search).every(letter => letter === search[0]) ? search[0] : search;
      const items = enabled(), index = items.findIndex(item => item.index === (open ? active : select.selectedIndex));
      const match = [...items.slice(index + (query.length === 1 ? 1 : 0)), ...items.slice(0, index + 1)]
        .find(item => item.label.trim().toLocaleLowerCase().startsWith(query));
      if (match) { if (open) setActive(match.index); else choose(match.index); }
    }
    const control = { select, trigger, menu, wrap, sync, close, place,
      reset() { validationFailed = false; close(); sync(); },
      destroy() {
        close(); observer.disconnect(); resize?.disconnect(); menu.remove();
        for (const [type, listener] of nativeListeners) select.removeEventListener(type, listener);
        select.classList.remove('ea-select-native');
        if (oldTab === null) select.removeAttribute('tabindex'); else select.setAttribute('tabindex', oldTab);
        if (oldHidden === null) select.removeAttribute('aria-hidden'); else select.setAttribute('aria-hidden', oldHidden);
        if (select.parentElement === wrap) wrap.before(select);
        wrap.remove(); controls.delete(select);
        for (let index = sheet.cssRules.length - 1; index >= 0; index--)
          if (sheet.cssRules[index] === rule) sheet.deleteRule(index);
      } };
    controls.set(select, control);
    trigger.addEventListener('click', () => open ? close() : show());
    trigger.addEventListener('keydown', keydown); trigger.addEventListener('focus', sync);
    menu.addEventListener('pointerdown', event => { if (event.pointerType !== 'touch') event.preventDefault(); });
    listenNative('input', sync); listenNative('change', sync);
    listenNative('focus', () => trigger.focus({ preventScroll: true }));
    listenNative('click', event => { event.preventDefault(); show(); });
    listenNative('invalid', event => {
      if (event.defaultPrevented) return;
      validationFailed = true;
      event.preventDefault(); trigger.setAttribute('aria-invalid', 'true'); trigger.focus();
      trigger.setAttribute('aria-invalid', 'true');
    });
    const observer = new MutationObserver(() => {
      if (!eligible(select)) control.destroy(); else sync();
    });
    observer.observe(select, { attributes: true, childList: true, characterData: true, subtree: true });
    const resize = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(place);
    resize?.observe(trigger); sync();
    if (select.autofocus) trigger.focus();
  }
  function scan(root) {
    if (root.matches?.('select')) enhance(root);
    root.querySelectorAll?.('select').forEach(enhance);
  }
  function start() {
    scan(document);
    new MutationObserver(records => {
      for (const record of records) {
        for (const node of record.addedNodes ?? []) scan(node);
        if (record.type === 'attributes') {
          scan(record.target);
          if (record.target.tagName === 'FIELDSET')
            record.target.querySelectorAll('select').forEach(select => controls.get(select)?.sync());
        }
      }
      for (const [select, control] of controls) {
        if (!select.isConnected) control.destroy();
        else if (select.parentElement !== control.wrap) { control.destroy(); enhance(select); }
      }
    }).observe(document.documentElement, { childList: true, subtree: true, attributes: true,
      attributeFilter: ['disabled', 'multiple', 'size'] });
    document.addEventListener('reset', event => {
      // Native reset is a default action: a microtask can run before it completes.
      setTimeout(() => {
        for (const control of controls.values()) if (control.select.form === event.target) {
          if (event.defaultPrevented) control.sync(); else control.reset();
        }
      }, 0);
    }, true);
    for (const type of ['pointerdown', 'focusin']) document.addEventListener(type, event => {
      if (current && !current.trigger.contains(event.target) && !current.menu.contains(event.target)) current.close();
    }, true);
    document.addEventListener('fullscreenchange', () => current?.close());
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape' && current) { event.preventDefault(); event.stopPropagation(); current.close(); }
    }, true);
    window.addEventListener('resize', () => current?.place());
    window.addEventListener('scroll', () => current?.place(), true);
    window.visualViewport?.addEventListener('resize', () => current?.place());
    window.visualViewport?.addEventListener('scroll', () => current?.place());
  }
  // Explicit sync is available for callers assigning .value without dispatching events.
  globalThis.EngineSelectControls = { enhance, sync: select => controls.get(select)?.sync(), optionsOf, position };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true });
  else start();
})();
