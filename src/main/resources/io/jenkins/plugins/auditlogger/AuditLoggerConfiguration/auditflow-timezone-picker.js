(function() {
    var RECENT_STORAGE_KEY = 'auditflow-display-timezone-recents';

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

    function uniqueValues(values) {
        var seen = {};
        var result = [];
        for (var i = 0; i < values.length; i++) {
            var value = values[i];
            if (!value || seen[value]) {
                continue;
            }
            seen[value] = true;
            result.push(value);
        }
        return result;
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

        var input = document.getElementById('auditflowDisplayTimeZoneId');
        var trigger = document.getElementById('auditflowTimezoneTrigger');
        var valueNode = document.getElementById('auditflowTimezoneValue');
        var popup = document.getElementById('auditflowTimezonePopup');
        var search = document.getElementById('auditflowTimezoneSearch');
        var recentSection = document.getElementById('auditflowTimezoneRecentSection');
        var recentList = document.getElementById('auditflowTimezoneRecentList');
        var popularSection = document.getElementById('auditflowTimezonePopularSection');
        var popularList = document.getElementById('auditflowTimezonePopularList');
        var resultsSection = document.getElementById('auditflowTimezoneResultsSection');
        var resultsList = document.getElementById('auditflowTimezoneResultsList');
        var emptyState = document.getElementById('auditflowTimezoneEmpty');
        var availableOptions = parseOptions('auditflowTimezoneOptions');
        var popularOptions = parseOptions('auditflowTimezonePopularOptions');
        var optionsById = {};

        for (var i = 0; i < availableOptions.length; i++) {
            optionsById[availableOptions[i].id] = availableOptions[i];
        }

        function getSelectedValue() {
            return input && input.value ? input.value : 'UTC';
        }

        function getOption(value) {
            return optionsById[value] || optionsById.UTC || availableOptions[0] || { id: 'UTC', label: 'UTC' };
        }

        function readRecentValues() {
            var stored = [];
            try {
                stored = JSON.parse(localStorage.getItem(RECENT_STORAGE_KEY) || '[]');
            } catch (ignored) {
                stored = [];
            }

            if (!Array.isArray(stored)) {
                stored = [];
            }

            var defaults = [getSelectedValue(), 'UTC'];
            var values = uniqueValues(stored.concat(defaults));
            var valid = [];
            for (var i = 0; i < values.length; i++) {
                if (optionsById[values[i]]) {
                    valid.push(values[i]);
                }
            }
            return valid.slice(0, 4);
        }

        function writeRecentValue(value) {
            var recents = readRecentValues();
            recents.unshift(value);
            recents = uniqueValues(recents).slice(0, 4);
            try {
                localStorage.setItem(RECENT_STORAGE_KEY, JSON.stringify(recents));
            } catch (ignored) {
                // Ignore localStorage availability issues.
            }
        }

        function createOptionButton(option) {
            var button = document.createElement('button');
            button.type = 'button';
            button.className = 'auditflow-timezone-picker__option';
            button.dataset.value = option.id;
            button.dataset.label = option.label;
            if (option.id === getSelectedValue()) {
                button.classList.add('auditflow-timezone-picker__option--selected');
            }

            var label = document.createElement('span');
            label.className = 'auditflow-timezone-picker__option-label';
            label.textContent = option.label;
            button.appendChild(label);

            if (option.id === getSelectedValue()) {
                var badge = document.createElement('span');
                badge.className = 'auditflow-timezone-picker__option-meta';
                badge.textContent = 'Selected';
                button.appendChild(badge);
            }

            return button;
        }

        function renderOptionList(container, options) {
            container.innerHTML = '';
            for (var i = 0; i < options.length; i++) {
                container.appendChild(createOptionButton(options[i]));
            }
        }

        function renderRecentOptions() {
            var recentValues = readRecentValues();
            var options = [];
            for (var i = 0; i < recentValues.length; i++) {
                if (optionsById[recentValues[i]]) {
                    options.push(optionsById[recentValues[i]]);
                }
            }
            renderOptionList(recentList, options);
            setHidden(recentSection, options.length === 0);
        }

        function renderPopularOptions() {
            var options = [];
            for (var i = 0; i < popularOptions.length; i++) {
                if (optionsById[popularOptions[i].id]) {
                    options.push(optionsById[popularOptions[i].id]);
                }
            }
            renderOptionList(popularList, options);
            setHidden(popularSection, options.length === 0);
        }

        function sortMatches(left, right, query) {
            var leftLabel = left.label.toLowerCase();
            var rightLabel = right.label.toLowerCase();
            var leftStarts = leftLabel.indexOf(query) === 0;
            var rightStarts = rightLabel.indexOf(query) === 0;
            if (leftStarts !== rightStarts) {
                return leftStarts ? -1 : 1;
            }
            return leftLabel.localeCompare(rightLabel);
        }

        function renderSearchResults(query) {
            var trimmed = query ? query.trim().toLowerCase() : '';
            if (!trimmed) {
                resultsList.innerHTML = '';
                setHidden(resultsSection, true);
                setHidden(recentSection, false);
                setHidden(popularSection, false);
                emptyState.textContent = 'Type to search all time zones.';
                return;
            }

            var matches = [];
            for (var i = 0; i < availableOptions.length; i++) {
                var option = availableOptions[i];
                var label = (option.label || '').toLowerCase();
                var id = (option.id || '').toLowerCase();
                if (label.indexOf(trimmed) !== -1 || id.indexOf(trimmed) !== -1) {
                    matches.push(option);
                }
            }

            matches.sort(function(left, right) {
                return sortMatches(left, right, trimmed);
            });

            matches = matches.slice(0, 12);
            renderOptionList(resultsList, matches);
            setHidden(resultsSection, matches.length === 0);
            setHidden(recentSection, true);
            setHidden(popularSection, true);
            emptyState.textContent = matches.length === 0
                ? 'No matching time zones.'
                : 'Showing ' + matches.length + ' matching time zone' + (matches.length === 1 ? '' : 's') + '.';
        }

        function closePopup() {
            setHidden(popup, true);
            trigger.setAttribute('aria-expanded', 'false');
        }

        function openPopup() {
            setHidden(popup, false);
            trigger.setAttribute('aria-expanded', 'true');
            search.focus();
            search.select();
        }

        function updateSelectedValue(value) {
            var option = getOption(value);
            input.value = option.id;
            valueNode.textContent = option.label;
            writeRecentValue(option.id);
            renderRecentOptions();
            renderPopularOptions();
            renderSearchResults(search.value || '');
            closePopup();
        }

        trigger.addEventListener('click', function() {
            if (popup.classList.contains('jenkins-hidden')) {
                openPopup();
                return;
            }
            closePopup();
        });

        popup.addEventListener('click', function(event) {
            var button = event.target.closest('button[data-value]');
            if (!button) {
                return;
            }
            updateSelectedValue(button.dataset.value);
        });

        search.addEventListener('input', function() {
            renderSearchResults(search.value || '');
        });

        search.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closePopup();
                trigger.focus();
            }
        });

        document.addEventListener('click', function(event) {
            if (!picker.contains(event.target)) {
                closePopup();
            }
        });

        renderRecentOptions();
        renderPopularOptions();
        renderSearchResults('');
        valueNode.textContent = getOption(getSelectedValue()).label;
    }

    window.addEventListener('load', initTimezonePicker);
})();