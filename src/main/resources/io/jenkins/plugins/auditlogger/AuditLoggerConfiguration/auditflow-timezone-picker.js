(function() {
    function parseOptions(id) {
        var script = document.getElementById(id);
        if (!script) {
            return [];
        }

        try {
            var parsed = JSON.parse(script.textContent || '[]');
            return Array.isArray(parsed) ? parsed : [];
        } catch (ignored) {
            return [];
        }
    }

    function setHidden(element, hidden) {
        if (element) {
            element.classList.toggle('jenkins-hidden', hidden);
        }
    }

    function initTimezonePicker() {
        var picker = document.getElementById('auditflowTimezonePicker');
        if (!picker || picker.dataset.initialized === 'true') {
            return;
        }
        picker.dataset.initialized = 'true';

        var hiddenInput = document.getElementById('auditflowDisplayTimeZoneId');
        var textInput = document.getElementById('auditflowTimezoneInput');
        var toggle = document.getElementById('auditflowTimezoneToggle');
        var menu = document.getElementById('auditflowTimezoneMenu');
        var listbox = document.getElementById('auditflowTimezoneListbox');
        var emptyState = document.getElementById('auditflowTimezoneEmpty');
        var availableOptions = parseOptions('auditflowTimezoneOptions');
        var optionsById = {};
        var filteredOptions = availableOptions.slice();
        var highlightedIndex = -1;

        for (var i = 0; i < availableOptions.length; i++) {
            optionsById[availableOptions[i].id] = availableOptions[i];
        }

        function getSelectedValue() {
            return hiddenInput && hiddenInput.value ? hiddenInput.value : 'UTC';
        }

        function getOption(value) {
            return optionsById[value] || optionsById.UTC || availableOptions[0] || {
                id: 'UTC',
                label: 'UTC',
                offset: 'UTC+00:00'
            };
        }

        function getNormalizedQuery() {
            return (textInput.value || '').trim().toLowerCase();
        }

        function filterOptions(query) {
            if (!query) {
                return availableOptions.slice();
            }

            return availableOptions.filter(function(option) {
                var id = (option.id || '').toLowerCase();
                var offset = (option.offset || '').toLowerCase();
                return id.indexOf(query) !== -1 || offset.indexOf(query) !== -1;
            });
        }

        function getHighlightedOptionId(index) {
            return 'auditflowTimezoneOption-' + index;
        }

        function syncSelectedText() {
            textInput.value = getOption(getSelectedValue()).label;
        }

        function updateActiveDescendant() {
            if (highlightedIndex >= 0 && highlightedIndex < filteredOptions.length) {
                textInput.setAttribute('aria-activedescendant', getHighlightedOptionId(highlightedIndex));
                return;
            }

            textInput.removeAttribute('aria-activedescendant');
        }

        function ensureHighlightedIndex() {
            if (!filteredOptions.length) {
                highlightedIndex = -1;
                return;
            }

            if (highlightedIndex >= 0 && highlightedIndex < filteredOptions.length) {
                return;
            }

            var selectedValue = getSelectedValue();
            highlightedIndex = 0;
            for (var i = 0; i < filteredOptions.length; i++) {
                if (filteredOptions[i].id === selectedValue) {
                    highlightedIndex = i;
                    break;
                }
            }
        }

        function createOptionButton(option, index) {
            var button = document.createElement('button');
            button.type = 'button';
            button.className = 'auditflow-timezone-picker__option';
            button.dataset.value = option.id;
            button.id = getHighlightedOptionId(index);
            button.setAttribute('role', 'option');
            button.setAttribute('aria-selected', option.id === getSelectedValue() ? 'true' : 'false');

            if (option.id === getSelectedValue()) {
                button.classList.add('auditflow-timezone-picker__option--selected');
            }
            if (index === highlightedIndex) {
                button.classList.add('auditflow-timezone-picker__option--active');
            }

            var label = document.createElement('span');
            label.className = 'auditflow-timezone-picker__option-label';
            label.textContent = option.label;
            button.appendChild(label);

            var offset = document.createElement('span');
            offset.className = 'auditflow-timezone-picker__option-offset';
            offset.textContent = option.offset || '';
            button.appendChild(offset);

            return button;
        }

        function renderOptions() {
            listbox.innerHTML = '';
            ensureHighlightedIndex();

            if (!filteredOptions.length) {
                setHidden(emptyState, false);
                updateActiveDescendant();
                return;
            }

            setHidden(emptyState, true);
            for (var i = 0; i < filteredOptions.length; i++) {
                listbox.appendChild(createOptionButton(filteredOptions[i], i));
            }

            updateActiveDescendant();
            scrollHighlightedOptionIntoView();
        }

        function scrollHighlightedOptionIntoView() {
            if (highlightedIndex < 0) {
                return;
            }

            var activeOption = document.getElementById(getHighlightedOptionId(highlightedIndex));
            if (activeOption && activeOption.scrollIntoView) {
                activeOption.scrollIntoView({ block: 'nearest' });
            }
        }

        function refreshOptions() {
            filteredOptions = filterOptions(getNormalizedQuery());
            highlightedIndex = filteredOptions.length ? 0 : -1;
            renderOptions();
        }

        function closeMenu(restoreSelection) {
            setHidden(menu, true);
            textInput.setAttribute('aria-expanded', 'false');
            if (restoreSelection !== false) {
                syncSelectedText();
            }
            updateActiveDescendant();
        }

        function openMenu() {
            setHidden(menu, false);
            textInput.setAttribute('aria-expanded', 'true');
            filteredOptions = filterOptions(getNormalizedQuery());
            highlightedIndex = -1;
            renderOptions();
        }

        function updateSelectedValue(value) {
            var option = getOption(value);
            hiddenInput.value = option.id;
            syncSelectedText();
            closeMenu(false);
        }

        function moveHighlight(step) {
            if (!filteredOptions.length) {
                return;
            }

            if (menu.classList.contains('jenkins-hidden')) {
                openMenu();
            }

            if (highlightedIndex < 0) {
                highlightedIndex = 0;
            } else {
                highlightedIndex = Math.max(0, Math.min(highlightedIndex + step, filteredOptions.length - 1));
            }

            renderOptions();
        }

        textInput.addEventListener('focus', function() {
            openMenu();
        });

        textInput.addEventListener('input', function() {
            if (menu.classList.contains('jenkins-hidden')) {
                openMenu();
            }
            refreshOptions();
        });

        textInput.addEventListener('keydown', function(event) {
            if (event.key === 'ArrowDown') {
                event.preventDefault();
                moveHighlight(1);
                return;
            }

            if (event.key === 'ArrowUp') {
                event.preventDefault();
                moveHighlight(-1);
                return;
            }

            if (event.key === 'Enter' && !menu.classList.contains('jenkins-hidden')) {
                if (highlightedIndex >= 0 && highlightedIndex < filteredOptions.length) {
                    event.preventDefault();
                    updateSelectedValue(filteredOptions[highlightedIndex].id);
                }
                return;
            }

            if (event.key === 'Escape') {
                event.preventDefault();
                closeMenu(true);
                textInput.blur();
                return;
            }

            if (event.key === 'Tab') {
                closeMenu(true);
            }
        });

        toggle.addEventListener('click', function() {
            if (menu.classList.contains('jenkins-hidden')) {
                openMenu();
                textInput.focus();
                textInput.select();
                return;
            }

            closeMenu(true);
            textInput.focus();
        });

        listbox.addEventListener('mousedown', function(event) {
            event.preventDefault();
        });

        listbox.addEventListener('click', function(event) {
            var button = event.target.closest('button[data-value]');
            if (!button) {
                return;
            }
            updateSelectedValue(button.dataset.value);
        });

        picker.addEventListener('focusout', function() {
            window.setTimeout(function() {
                if (!picker.contains(document.activeElement)) {
                    closeMenu(true);
                }
            }, 0);
        });

        document.addEventListener('mousedown', function(event) {
            if (!picker.contains(event.target)) {
                closeMenu(true);
            }
        });

        syncSelectedText();
        renderOptions();
        closeMenu(false);
    }

    window.addEventListener('load', initTimezonePicker);
})();