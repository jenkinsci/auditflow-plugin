(function() {
    'use strict';

    var CATALOG = [
        // Categories
        { id: 'CATEGORY:AUTH', label: 'Category: Authentication & Sessions', type: 'category', scope: 'audit', severity: 'CRITICAL', desc: 'Logins, failures, logouts, API auth, sessions' },
        { id: 'CATEGORY:SECURITY', label: 'Category: System & Security Config', type: 'category', scope: 'audit', severity: 'CRITICAL', desc: 'Script console, security realm, auth strategy, restarts' },
        { id: 'CATEGORY:CREDENTIALS', label: 'Category: Credentials & Secrets', type: 'category', scope: 'audit', severity: 'HIGH', desc: 'Credential creations, access, updates, deletions' },
        { id: 'CATEGORY:JOBS', label: 'Category: Jobs & Builds', type: 'category', scope: 'audit', severity: 'HIGH', desc: 'Job CRUD, build completions & failures' },
        { id: 'CATEGORY:NODES', label: 'Category: Nodes & Agents', type: 'category', scope: 'audit', severity: 'CRITICAL', desc: 'Node launch failure, online/offline, creation, disconnection' },
        { id: 'CATEGORY:ANOMALIES', label: 'Category: Security Anomalies', type: 'category', scope: 'anomaly', severity: 'CRITICAL', desc: 'All heuristics-flagged security anomalies' },

        // Anomaly Types
        { id: 'BRUTE_FORCE_LOGIN', label: 'Brute Force Login Attempts', type: 'anomaly', scope: 'anomaly', severity: 'CRITICAL', desc: 'Rapid repeated authentication failures' },
        { id: 'SUSPICIOUS_AUTH_PATTERN', label: 'Suspicious Auth Pattern', type: 'anomaly', scope: 'anomaly', severity: 'CRITICAL', desc: 'Successful login following brute force' },
        { id: 'ADMIN_PRIVILEGE_CHANGE', label: 'Admin Privilege Spike', type: 'anomaly', scope: 'anomaly', severity: 'CRITICAL', desc: 'Security matrix or admin rights changes' },
        { id: 'UNUSUAL_IP', label: 'Unusual IP Address Activity', type: 'anomaly', scope: 'anomaly', severity: 'HIGH', desc: 'Activity from new/unseen IP addresses' },
        { id: 'MULTI_IP_LOGIN', label: 'Concurrent Multi-IP Logins', type: 'anomaly', scope: 'anomaly', severity: 'HIGH', desc: 'Concurrent sessions from distinct IP addresses' },
        { id: 'USER_LIFECYCLE_ANOMALY', label: 'User Lifecycle Burst', type: 'anomaly', scope: 'anomaly', severity: 'HIGH', desc: 'Rapid creation or mass deletion of accounts' },

        // Direct Audit Actions
        { id: 'SCRIPT_CONSOLE_ACCESS', label: 'Script Console Evaluation', type: 'action', scope: 'audit', severity: 'CRITICAL', desc: 'Remoting / Script console code evaluation' },
        { id: 'SCRIPT_EXECUTION', label: 'Script Execution', type: 'action', scope: 'audit', severity: 'CRITICAL', desc: 'Pipeline or groovy script execution' },
        { id: 'FAILED_LOGIN', label: 'Failed Login Attempt', type: 'action', scope: 'audit', severity: 'CRITICAL', desc: 'Single failed authentication attempt' },
        { id: 'SYSTEM_RESTART', label: 'System Restart', type: 'action', scope: 'audit', severity: 'CRITICAL', desc: 'Jenkins controller restart' },
        { id: 'SECURITY_REALM_CHANGED', label: 'Security Realm Changed', type: 'action', scope: 'audit', severity: 'CRITICAL', desc: 'Authentication realm updated' },
        { id: 'AUTH_STRATEGY_CHANGED', label: 'Authorization Strategy Changed', type: 'action', scope: 'audit', severity: 'CRITICAL', desc: 'Role / permissions strategy modified' },
        { id: 'CREDENTIAL_DELETED', label: 'Credential Deleted', type: 'action', scope: 'audit', severity: 'HIGH', desc: 'Secret removed from credential store' },
        { id: 'JOB_DELETED', label: 'Job Deleted', type: 'action', scope: 'audit', severity: 'HIGH', desc: 'Pipeline or project deleted' },
        { id: 'BUILD_FAILURE', label: 'Build Failure', type: 'action', scope: 'audit', severity: 'HIGH', desc: 'Pipeline or project build failed' },
        { id: 'NODE_OFFLINE', label: 'Node Offline', type: 'action', scope: 'audit', severity: 'HIGH', desc: 'Build agent disconnected or went offline' },
        { id: 'LOGIN', label: 'Successful Login', type: 'action', scope: 'audit', severity: 'LOW', desc: 'User logged into Jenkins controller' },
        { id: 'LOGOUT', label: 'Successful Logout', type: 'action', scope: 'audit', severity: 'LOW', desc: 'User logged out of Jenkins' },
        { id: 'API_AUTH', label: 'API Token Auth', type: 'action', scope: 'audit', severity: 'LOW', desc: 'API / programmatic authentication' },
        { id: 'CREDENTIAL_ACCESSED', label: 'Credential Accessed', type: 'action', scope: 'audit', severity: 'LOW', desc: 'Secret used during build' },
        { id: 'CREDENTIAL_CREATED', label: 'Credential Created', type: 'action', scope: 'audit', severity: 'INFO', desc: 'New credential stored' }
    ];

    var SEVERITY_SCORES = {
        'CRITICAL': 4,
        'HIGH': 3,
        'MEDIUM': 2,
        'LOW': 1,
        'INFO': 0,
        'ALL': 0
    };

    var CATALOG_BY_ID = {};
    for (var i = 0; i < CATALOG.length; i++) {
        CATALOG_BY_ID[CATALOG[i].id.toUpperCase()] = CATALOG[i];
    }

    var initializedPickers = (typeof WeakSet !== 'undefined') ? new WeakSet() : null;

    function findScopeSelect(container) {
        var chunk = container.closest ? container.closest('.repeated-chunk, tr[name*="webhookEndpoints"], div[name*="webhookEndpoints"]') : null;
        if (chunk) {
            var sel = chunk.querySelector('select[name*="scope"]');
            if (sel) return sel;
        }
        var current = container.parentElement;
        while (current && current !== document.body) {
            var select = current.querySelector('select[name*="scope"]');
            if (select) {
                return select;
            }
            if (current.classList && current.classList.contains('repeated-chunk')) break;
            current = current.parentElement;
        }
        return null;
    }

    function findMinSeveritySelect(container) {
        var chunk = container.closest ? container.closest('.repeated-chunk, tr[name*="webhookEndpoints"], div[name*="webhookEndpoints"]') : null;
        if (chunk) {
            var sel = chunk.querySelector('select[name*="minSeverity"]');
            if (sel) return sel;
        }
        var current = container.parentElement;
        while (current && current !== document.body) {
            var select = current.querySelector('select[name*="minSeverity"]');
            if (select) {
                return select;
            }
            if (current.classList && current.classList.contains('repeated-chunk')) break;
            current = current.parentElement;
        }
        return null;
    }

    function initEventPicker(container) {
        if (!container) {
            return;
        }
        if (initializedPickers) {
            if (initializedPickers.has(container)) {
                return;
            }
            initializedPickers.add(container);
        } else {
            if (container.dataset.afBound === 'true') {
                return;
            }
            container.dataset.afBound = 'true';
        }
        container.dataset.initialized = 'true';

        var hiddenInput = container.querySelector('.auditflow-event-picker__value');
        var box = container.querySelector('.auditflow-event-picker__box');
        var chipsContainer = container.querySelector('.auditflow-event-picker__chips');
        var input = container.querySelector('.auditflow-event-picker__input');
        var menu = container.querySelector('.auditflow-event-picker__menu');

        if (!hiddenInput || !box || !chipsContainer || !input || !menu) {
            return;
        }

        var tags = [];
        var rawVal = hiddenInput.value || '';
        if (rawVal.trim()) {
            var parts = rawVal.split(',');
            for (var p = 0; p < parts.length; p++) {
                var item = parts[p].trim();
                if (item) {
                    tags.push(item);
                }
            }
        }

        var scopeSelect = findScopeSelect(container);
        var minSeveritySelect = findMinSeveritySelect(container);
        var highlightedIndex = -1;
        var currentFiltered = [];
        var navigableNodes = [];

        function refreshSelects() {
            if (!scopeSelect) {
                scopeSelect = findScopeSelect(container);
                if (scopeSelect) {
                    scopeSelect.addEventListener('change', onScopeChange);
                }
            }
            if (!minSeveritySelect) {
                minSeveritySelect = findMinSeveritySelect(container);
                if (minSeveritySelect) {
                    minSeveritySelect.addEventListener('change', onMinSeverityChange);
                }
            }
        }

        function getCurrentScope() {
            refreshSelects();
            return (scopeSelect && scopeSelect.value) ? scopeSelect.value : 'ALL_ALERTS';
        }

        function getCurrentMinSeverity() {
            refreshSelects();
            return (minSeveritySelect && minSeveritySelect.value) ? minSeveritySelect.value.toUpperCase() : 'ALL';
        }

        function getMinSeverityScore() {
            var s = getCurrentMinSeverity();
            return SEVERITY_SCORES[s] !== undefined ? SEVERITY_SCORES[s] : 0;
        }

        function syncToHidden() {
            hiddenInput.value = tags.join(', ');
            hiddenInput.dispatchEvent(new Event('change', { bubbles: true }));
            updatePlaceholder();
        }

        function updatePlaceholder() {
            if (tags.length === 0) {
                input.setAttribute('placeholder', 'Type to search & add categories or specific events (default: all)...');
            } else {
                input.setAttribute('placeholder', 'Add another...');
            }
        }

        function renderChips() {
            chipsContainer.innerHTML = '';
            var currentMinScore = getMinSeverityScore();
            var currentMinSev = getCurrentMinSeverity();

            for (var i = 0; i < tags.length; i++) {
                (function(tagIndex) {
                    var tagId = tags[tagIndex];
                    var upper = tagId.toUpperCase();
                    var meta = CATALOG_BY_ID[upper];
                    var type = meta ? meta.type : (tagId.indexOf('CATEGORY:') === 0 ? 'category' : 'action');
                    var label = meta ? meta.label : tagId;
                    var itemSev = meta && meta.severity ? meta.severity : null;
                    var itemScore = itemSev && SEVERITY_SCORES[itemSev] !== undefined ? SEVERITY_SCORES[itemSev] : null;
                    var isBelowThreshold = itemScore !== null && itemScore < currentMinScore;

                    var chip = document.createElement('span');
                    chip.className = 'auditflow-event-chip auditflow-event-chip--' + type + (isBelowThreshold ? ' auditflow-event-chip--warning' : '');

                    var text = document.createElement('span');
                    text.textContent = label;
                    chip.appendChild(text);

                    if (isBelowThreshold) {
                        var warnBadge = document.createElement('span');
                        warnBadge.className = 'auditflow-event-chip__warn-badge';
                        warnBadge.textContent = '⚠ < ' + currentMinSev;
                        warnBadge.title = 'This event severity (' + itemSev + ') is below the endpoint minimum severity (' + currentMinSev + ') and will not be dispatched.';
                        chip.appendChild(warnBadge);
                    }

                    var removeBtn = document.createElement('span');
                    removeBtn.className = 'auditflow-event-chip__remove';
                    removeBtn.innerHTML = '&times;';
                    removeBtn.title = 'Remove tag';
                    removeBtn.addEventListener('click', function(e) {
                        e.stopPropagation();
                        tags.splice(tagIndex, 1);
                        syncToHidden();
                        renderChips();
                        input.focus();
                    });
                    chip.appendChild(removeBtn);

                    chipsContainer.appendChild(chip);
                })(i);
            }
            updatePlaceholder();
        }

        function addTag(tagId) {
            var trimmed = (tagId || '').trim();
            if (!trimmed) return;
            var upper = trimmed.toUpperCase();

            // Avoid duplicate additions
            for (var i = 0; i < tags.length; i++) {
                if (tags[i].toUpperCase() === upper) {
                    input.value = '';
                    closeMenu();
                    return;
                }
            }

            tags.push(trimmed);
            syncToHidden();
            renderChips();
            input.value = '';
            closeMenu();
            input.focus();
        }

        function openMenu() {
            refreshSelects();
            renderMenu();
            menu.style.display = 'block';
        }

        function closeMenu() {
            menu.style.display = 'none';
            highlightedIndex = -1;
            updateHighlight();
        }

        function updateHighlight() {
            for (var i = 0; i < navigableNodes.length; i++) {
                if (i === highlightedIndex) {
                    navigableNodes[i].classList.add('auditflow-event-picker__item--highlighted');
                    if (typeof navigableNodes[i].scrollIntoView === 'function') {
                        navigableNodes[i].scrollIntoView({ block: 'nearest' });
                    }
                } else {
                    navigableNodes[i].classList.remove('auditflow-event-picker__item--highlighted');
                }
            }
        }

        function getAvailableOptions(query) {
            var scope = getCurrentScope();
            var minScore = getMinSeverityScore();
            var q = (query || '').trim().toLowerCase();

            var tagSet = {};
            for (var t = 0; t < tags.length; t++) {
                tagSet[tags[t].toUpperCase()] = true;
            }

            var results = [];
            for (var i = 0; i < CATALOG.length; i++) {
                var item = CATALOG[i];
                if (tagSet[item.id.toUpperCase()]) {
                    continue; // already selected
                }

                // Scope sync filtering
                if (scope === 'ANOMALIES_ONLY' && item.scope !== 'anomaly') {
                    continue;
                }
                if (scope === 'CRITICAL_LOGS_ONLY' && item.scope !== 'audit') {
                    continue;
                }

                var itemScore = item.severity && SEVERITY_SCORES[item.severity] !== undefined ? SEVERITY_SCORES[item.severity] : 0;
                var isBelow = itemScore < minScore;

                if (!q) {
                    // Empty query: adapt suggestions to chosen minimum severity
                    if (isBelow) {
                        continue;
                    }
                    var clone = Object.assign ? Object.assign({}, item) : item;
                    clone.isBelowThreshold = false;
                    results.push(clone);
                } else {
                    // Explicit search query: allow finding any catalog event matching query
                    var matchId = item.id.toLowerCase().indexOf(q) !== -1;
                    var matchLabel = item.label.toLowerCase().indexOf(q) !== -1;
                    var matchDesc = item.desc.toLowerCase().indexOf(q) !== -1;
                    if (matchId || matchLabel || matchDesc) {
                        var searchClone = Object.assign ? Object.assign({}, item) : item;
                        searchClone.isBelowThreshold = isBelow;
                        results.push(searchClone);
                    }
                }
            }
            return results;
        }

        function renderMenu() {
            var q = input.value.trim();
            currentFiltered = getAvailableOptions(q);
            menu.innerHTML = '';
            highlightedIndex = -1;
            navigableNodes = [];

            var currentMinSev = getCurrentMinSeverity();
            if (currentFiltered.length === 0 && !q) {
                var empty = document.createElement('div');
                empty.className = 'auditflow-event-picker__empty';
                empty.textContent = 'No additional events match current scope and ' + (currentMinSev === 'ALL' ? 'all severities' : currentMinSev + '+ severity') + '.';
                menu.appendChild(empty);
                return;
            }

            // Group by category, anomaly, action
            var categories = [];
            var anomalies = [];
            var actions = [];

            for (var i = 0; i < currentFiltered.length; i++) {
                var opt = currentFiltered[i];
                if (opt.type === 'category') categories.push(opt);
                else if (opt.type === 'anomaly') anomalies.push(opt);
                else actions.push(opt);
            }

            function addGroup(title, list) {
                if (list.length === 0) return;
                var header = document.createElement('div');
                header.className = 'auditflow-event-picker__group-header';
                header.textContent = title;
                menu.appendChild(header);

                for (var j = 0; j < list.length; j++) {
                    (function(option) {
                        var row = document.createElement('div');
                        row.className = 'auditflow-event-picker__item';

                        var left = document.createElement('div');
                        left.style.display = 'flex';
                        left.style.alignItems = 'center';

                        var badge = document.createElement('span');
                        badge.className = 'auditflow-event-picker__item-badge auditflow-event-picker__item-badge--' + option.type;
                        badge.textContent = option.type.toUpperCase();
                        left.appendChild(badge);

                        if (option.severity && option.type !== 'category') {
                            var sevBadge = document.createElement('span');
                            sevBadge.className = 'auditflow-event-picker__sev-badge auditflow-event-picker__sev-badge--' + option.severity.toLowerCase();
                            sevBadge.textContent = option.severity;
                            left.appendChild(sevBadge);
                        }

                        var lbl = document.createElement('span');
                        lbl.className = 'auditflow-event-picker__item-label';
                        lbl.textContent = option.label;
                        left.appendChild(lbl);

                        if (option.isBelowThreshold) {
                            var belowHint = document.createElement('span');
                            belowHint.className = 'auditflow-event-picker__below-hint';
                            belowHint.textContent = '(< ' + currentMinSev + ')';
                            belowHint.title = 'Severity (' + option.severity + ') is below endpoint minimum severity (' + currentMinSev + ')';
                            left.appendChild(belowHint);
                        }

                        row.appendChild(left);

                        var right = document.createElement('span');
                        right.className = 'auditflow-event-picker__item-desc';
                        right.textContent = option.desc;
                        row.appendChild(right);

                        row.addEventListener('mousedown', function(e) {
                            e.preventDefault(); // prevent blur
                            addTag(option.id);
                        });

                        menu.appendChild(row);
                        navigableNodes.push(row);
                    })(list[j]);
                }
            }

            addGroup('📁 Functional Categories', categories);
            addGroup('🚨 Anomaly Heuristics', anomalies);
            addGroup('⚡ Direct Audit Actions', actions);

            // If query typed but no catalog items matched, show helpful notice
            if (q && currentFiltered.length === 0) {
                var noMatch = document.createElement('div');
                noMatch.className = 'auditflow-event-picker__empty';
                noMatch.textContent = 'No catalog events matching "' + q + '".';
                menu.appendChild(noMatch);
            }

            // Allow adding freeform custom action if typed query doesn't match an existing selected tag
            if (q) {
                var customDiv = document.createElement('div');
                customDiv.className = 'auditflow-event-picker__custom-add';
                customDiv.textContent = '+ Add custom event label: "' + q.toUpperCase() + '"';
                customDiv.addEventListener('mousedown', function(e) {
                    e.preventDefault();
                    addTag(q.toUpperCase());
                });
                menu.appendChild(customDiv);
                navigableNodes.push(customDiv);
            }
        }

        function handleOpen(e) {
            if (e) {
                e.stopPropagation();
            }
            if (menu.style.display !== 'block') {
                openMenu();
            }
            input.focus();
        }

        // Event listeners on box and input
        box.addEventListener('click', handleOpen);
        input.addEventListener('click', handleOpen);

        input.addEventListener('focus', function() {
            openMenu();
        });

        input.addEventListener('input', function() {
            openMenu();
        });

        input.addEventListener('keydown', function(e) {
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (menu.style.display !== 'block') {
                    openMenu();
                } else if (navigableNodes.length > 0) {
                    highlightedIndex = (highlightedIndex + 1) % navigableNodes.length;
                    updateHighlight();
                }
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                if (menu.style.display !== 'block') {
                    openMenu();
                } else if (navigableNodes.length > 0) {
                    highlightedIndex = (highlightedIndex - 1 + navigableNodes.length) % navigableNodes.length;
                    updateHighlight();
                }
            } else if (e.key === 'Backspace' && input.value === '' && tags.length > 0) {
                tags.pop();
                syncToHidden();
                renderChips();
                openMenu();
            } else if (e.key === 'Enter') {
                e.preventDefault();
                if (highlightedIndex >= 0 && navigableNodes[highlightedIndex]) {
                    navigableNodes[highlightedIndex].dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true }));
                } else if (currentFiltered.length > 0) {
                    addTag(currentFiltered[0].id);
                } else {
                    var q = input.value.trim();
                    if (q) {
                        addTag(q.toUpperCase());
                    }
                }
            } else if (e.key === 'Escape') {
                closeMenu();
            }
        });

        // Close dropdown cleanly when clicking outside
        document.addEventListener('click', function(e) {
            if (!container.contains(e.target)) {
                closeMenu();
            }
        });

        function onScopeChange() {
            if (menu.style.display !== 'none') {
                renderMenu();
            }
        }

        function onMinSeverityChange() {
            renderChips();
            if (menu.style.display !== 'none') {
                renderMenu();
            }
        }

        if (scopeSelect) {
            scopeSelect.addEventListener('change', onScopeChange);
        }

        if (minSeveritySelect) {
            minSeveritySelect.addEventListener('change', onMinSeverityChange);
        }

        renderChips();
        renameChangePasswordButtons();
    }

    function renameChangePasswordButtons() {
        var buttons = document.querySelectorAll('button, input[type="button"]');
        for (var i = 0; i < buttons.length; i++) {
            var btn = buttons[i];
            var txt = (btn.textContent || btn.value || '').trim();
            if (txt.toLowerCase() === 'change password' || txt.toLowerCase() === 'change password...') {
                var container = btn.closest ? btn.closest('.repeated-chunk, tr, td, div.jenkins-form-item, div.jenkins-input-group') : null;
                if (container && (container.innerHTML.indexOf('webhookUrl') !== -1 || (container.closest && container.closest('.auditflow-endpoint-header')) || container.querySelector('input[name*="webhookUrl"]'))) {
                    if (btn.tagName.toLowerCase() === 'input') {
                        btn.value = 'Update URL';
                    } else {
                        btn.textContent = 'Update URL';
                    }
                }
            }
        }
    }

    function initAll() {
        var pickers = document.querySelectorAll('.auditflow-event-picker');
        for (var i = 0; i < pickers.length; i++) {
            initEventPicker(pickers[i]);
        }
        renameChangePasswordButtons();
    }

    if (window.Behaviour) {
        Behaviour.specify('.auditflow-event-picker', 'auditflow-event-picker', 0, function(el) {
            initEventPicker(el);
            renameChangePasswordButtons();
        });
        Behaviour.specify('.auditflow-endpoint-header', 'auditflow-endpoint-header', 0, function(el) {
            renameChangePasswordButtons();
        });
    }

    document.addEventListener('DOMContentLoaded', function() {
        initAll();
        if (window.MutationObserver) {
            try {
                var observer = new MutationObserver(function() {
                    initAll();
                });
                observer.observe(document.body, { childList: true, subtree: true });
            } catch (ignored) {}
        }
    });
})();
