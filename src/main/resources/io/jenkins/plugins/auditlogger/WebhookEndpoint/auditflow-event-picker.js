(function() {
    'use strict';

    var CATALOG = [
        // Categories
        { id: 'CATEGORY:AUTH', label: 'Category: Authentication & Sessions', type: 'category', scope: 'audit', desc: 'Logins, failures, logouts, API auth, sessions' },
        { id: 'CATEGORY:SECURITY', label: 'Category: System & Security Config', type: 'category', scope: 'audit', desc: 'Script console, security realm, auth strategy, restarts' },
        { id: 'CATEGORY:CREDENTIALS', label: 'Category: Credentials & Secrets', type: 'category', scope: 'audit', desc: 'Credential creations, access, updates, deletions' },
        { id: 'CATEGORY:JOBS', label: 'Category: Jobs & Builds', type: 'category', scope: 'audit', desc: 'Job CRUD, build completions & failures' },
        { id: 'CATEGORY:NODES', label: 'Category: Nodes & Agents', type: 'category', scope: 'audit', desc: 'Node online/offline, creation, disconnection' },
        { id: 'CATEGORY:ANOMALIES', label: 'Category: Security Anomalies', type: 'category', scope: 'anomaly', desc: 'All heuristics-flagged security anomalies' },

        // Anomaly Types
        { id: 'BRUTE_FORCE_LOGIN', label: 'Brute Force Login Attempts', type: 'anomaly', scope: 'anomaly', desc: 'Rapid repeated authentication failures' },
        { id: 'MULTI_IP_LOGIN', label: 'Concurrent Multi-IP Logins', type: 'anomaly', scope: 'anomaly', desc: 'Concurrent sessions from distinct IP addresses' },
        { id: 'UNUSUAL_IP', label: 'Unusual IP Address Activity', type: 'anomaly', scope: 'anomaly', desc: 'Activity from new/unseen IP addresses' },
        { id: 'SUSPICIOUS_AUTH_PATTERN', label: 'Suspicious Auth Pattern', type: 'anomaly', scope: 'anomaly', desc: 'Successful login following brute force' },
        { id: 'ADMIN_PRIVILEGE_CHANGE', label: 'Admin Privilege Spike', type: 'anomaly', scope: 'anomaly', desc: 'Security matrix or admin rights changes' },
        { id: 'USER_LIFECYCLE_ANOMALY', label: 'User Lifecycle Burst', type: 'anomaly', scope: 'anomaly', desc: 'Rapid creation or mass deletion of accounts' },

        // Direct Audit Actions
        { id: 'SCRIPT_CONSOLE_ACCESS', label: 'Script Console Evaluation', type: 'action', scope: 'audit', desc: 'Remoting / Script console code evaluation' },
        { id: 'SCRIPT_EXECUTION', label: 'Script Execution', type: 'action', scope: 'audit', desc: 'Pipeline or groovy script execution' },
        { id: 'FAILED_LOGIN', label: 'Failed Login Attempt', type: 'action', scope: 'audit', desc: 'Single failed authentication attempt' },
        { id: 'LOGIN', label: 'Successful Login', type: 'action', scope: 'audit', desc: 'User logged into Jenkins controller' },
        { id: 'API_AUTH', label: 'API Token Auth', type: 'action', scope: 'audit', desc: 'API / programmatic authentication' },
        { id: 'SYSTEM_RESTART', label: 'System Restart', type: 'action', scope: 'audit', desc: 'Jenkins controller restart' },
        { id: 'SECURITY_REALM_CHANGED', label: 'Security Realm Changed', type: 'action', scope: 'audit', desc: 'Authentication realm updated' },
        { id: 'AUTH_STRATEGY_CHANGED', label: 'Authorization Strategy Changed', type: 'action', scope: 'audit', desc: 'Role / permissions strategy modified' },
        { id: 'CREDENTIAL_DELETED', label: 'Credential Deleted', type: 'action', scope: 'audit', desc: 'Secret removed from credential store' },
        { id: 'CREDENTIAL_CREATED', label: 'Credential Created', type: 'action', scope: 'audit', desc: 'New credential stored' },
        { id: 'CREDENTIAL_ACCESSED', label: 'Credential Accessed', type: 'action', scope: 'audit', desc: 'Secret used during build' },
        { id: 'JOB_DELETED', label: 'Job Deleted', type: 'action', scope: 'audit', desc: 'Pipeline or project deleted' },
        { id: 'BUILD_FAILURE', label: 'Build Failure', type: 'action', scope: 'audit', desc: 'Pipeline or project build failed' },
        { id: 'NODE_OFFLINE', label: 'Node Offline', type: 'action', scope: 'audit', desc: 'Build agent disconnected or went offline' }
    ];

    var CATALOG_BY_ID = {};
    for (var i = 0; i < CATALOG.length; i++) {
        CATALOG_BY_ID[CATALOG[i].id.toUpperCase()] = CATALOG[i];
    }

    function findScopeSelect(container) {
        var current = container;
        while (current && current !== document.body) {
            var select = current.querySelector('select[name="_.scope"], select[name="scope"]');
            if (select) {
                return select;
            }
            current = current.parentElement;
        }
        return null;
    }

    function initEventPicker(container) {
        if (!container || container.dataset.initialized === 'true') {
            return;
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
        var highlightedIndex = -1;
        var currentFiltered = [];

        function getCurrentScope() {
            return scopeSelect ? scopeSelect.value : 'ALL_ALERTS';
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
            for (var i = 0; i < tags.length; i++) {
                (function(tagIndex) {
                    var tagId = tags[tagIndex];
                    var upper = tagId.toUpperCase();
                    var meta = CATALOG_BY_ID[upper];
                    var type = meta ? meta.type : (tagId.indexOf('CATEGORY:') === 0 ? 'category' : 'action');
                    var label = meta ? meta.label : tagId;

                    var chip = document.createElement('span');
                    chip.className = 'auditflow-event-chip auditflow-event-chip--' + type;

                    var text = document.createElement('span');
                    text.textContent = label;
                    chip.appendChild(text);

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
            renderMenu();
            menu.style.display = 'block';
        }

        function closeMenu() {
            menu.style.display = 'none';
            highlightedIndex = -1;
        }

        function getAvailableOptions(query) {
            var scope = getCurrentScope();
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

                if (!q) {
                    results.push(item);
                } else {
                    var matchId = item.id.toLowerCase().indexOf(q) !== -1;
                    var matchLabel = item.label.toLowerCase().indexOf(q) !== -1;
                    var matchDesc = item.desc.toLowerCase().indexOf(q) !== -1;
                    if (matchId || matchLabel || matchDesc) {
                        results.push(item);
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

            if (currentFiltered.length === 0 && !q) {
                var empty = document.createElement('div');
                empty.className = 'auditflow-event-picker__empty';
                empty.textContent = 'All available events matching current scope are selected.';
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

                        var lbl = document.createElement('span');
                        lbl.className = 'auditflow-event-picker__item-label';
                        lbl.textContent = option.label;
                        left.appendChild(lbl);

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
                    })(list[j]);
                }
            }

            addGroup('📁 Functional Categories', categories);
            addGroup('🚨 Anomaly Heuristics', anomalies);
            addGroup('⚡ Direct Audit Actions', actions);

            // Allow adding freeform custom action if typed query doesn't match an existing ID
            if (q) {
                var customDiv = document.createElement('div');
                customDiv.className = 'auditflow-event-picker__custom-add';
                customDiv.textContent = '+ Add custom event label: "' + q.toUpperCase() + '"';
                customDiv.addEventListener('mousedown', function(e) {
                    e.preventDefault();
                    addTag(q.toUpperCase());
                });
                menu.appendChild(customDiv);
            }
        }

        // Event listeners
        box.addEventListener('click', function() {
            input.focus();
        });

        input.addEventListener('focus', function() {
            openMenu();
        });

        input.addEventListener('input', function() {
            openMenu();
        });

        input.addEventListener('keydown', function(e) {
            if (e.key === 'Backspace' && input.value === '' && tags.length > 0) {
                tags.pop();
                syncToHidden();
                renderChips();
                openMenu();
            } else if (e.key === 'Enter') {
                e.preventDefault();
                var q = input.value.trim();
                if (currentFiltered.length > 0) {
                    addTag(currentFiltered[0].id);
                } else if (q) {
                    addTag(q.toUpperCase());
                }
            } else if (e.key === 'Escape') {
                closeMenu();
            }
        });

        input.addEventListener('blur', function() {
            setTimeout(closeMenu, 200);
        });

        if (scopeSelect) {
            scopeSelect.addEventListener('change', function() {
                if (menu.style.display !== 'none') {
                    renderMenu();
                }
            });
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
                var container = btn.closest('.repeated-chunk, tr, td, div.jenkins-form-item, div.jenkins-input-group');
                if (container && (container.innerHTML.indexOf('webhookUrl') !== -1 || container.closest('.auditflow-endpoint-header') || container.querySelector('input[name*="webhookUrl"]'))) {
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
                    renameChangePasswordButtons();
                });
                observer.observe(document.body, { childList: true, subtree: true });
            } catch (ignored) {}
        }
    });
})();
