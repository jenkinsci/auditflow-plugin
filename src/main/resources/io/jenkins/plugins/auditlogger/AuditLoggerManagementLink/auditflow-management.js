(function() {
    var allLogs = [];
    var currentInsights = [];
    var currentSummary = {};
    var currentPage = 1;
    var pageSize = 100;
    var totalLogs = 0;
    var totalPages = 1;
    var sortField = 'timestampMs';
    var sortAsc = false;
    var anomalyConfig = {};
    var displayTimeZone = 'UTC';
    var displayToday = '';
    var defaultViewMode = 'all';
    var defaultDatePreset = '';
    var defaultDateFrom = '';
    var defaultDateTo = '';
    var onboardingStorageKey = 'auditflow-onboarded';
    var anomalyDismissedKey = 'auditflow-anomaly-dismissed-id';
    var anomalyDismissedIdsKey = 'auditflow-anomaly-dismissed-ids';
    var anomalyDismissedTimestampKey = 'auditflow-anomaly-dismissed-until';
    var anomalyDismissed = false;
    var activeAnomalies = [];
    var lastServerAnomalies = [];
    var activeFilteredAnomalyAlertId = null;

    function setHidden(element, hidden) {
        if (element) {
            element.classList.toggle('jenkins-hidden', hidden);
        }
    }

    function parseAnomalyTimestamp(value) {
        var timestamp = typeof value === 'number' ? value : parseInt(value, 10);
        return isFinite(timestamp) && timestamp > 0 ? timestamp : 0;
    }

    function getDismissedAlertIds() {
        try {
            var raw = sessionStorage.getItem(anomalyDismissedIdsKey);
            if (raw) {
                return JSON.parse(raw) || {};
            }
        } catch (e) {}
        var single = sessionStorage.getItem(anomalyDismissedKey);
        var res = {};
        if (single) {
            res[single] = true;
        }
        return res;
    }

    function saveDismissedAlertIds(ids) {
        if (!ids || ids.length === 0) return;
        var map = getDismissedAlertIds();
        for (var i = 0; i < ids.length; i++) {
            if (ids[i]) {
                map[ids[i]] = true;
            }
        }
        try {
            sessionStorage.setItem(anomalyDismissedIdsKey, JSON.stringify(map));
            sessionStorage.setItem(anomalyDismissedKey, ids[ids.length - 1]);
        } catch (e) {}
    }

    function getUndismissedAnomalies(anomalies) {
        if (!anomalies || anomalies.length === 0) {
            return [];
        }
        var dismissedMap = getDismissedAlertIds();

        var result = [];
        for (var i = 0; i < anomalies.length; i++) {
            var candidate = anomalies[i];
            if (!candidate) continue;
            var alertId = candidate.alertId || ('auditflow-' + (candidate.type || '') + '-' + (candidate.user || '') + '-' + (candidate.timestamp || ''));
            if (dismissedMap[alertId]) {
                continue;
            }
            result.push(candidate);
        }
        return result;
    }

    function getLatestAnomaly(anomalies) {
        var un = getUndismissedAnomalies(anomalies);
        return un.length > 0 ? un[0] : null;
    }

    function refreshAnomalyDismissState(anomalies) {
        activeAnomalies = getUndismissedAnomalies(anomalies);
        latestAnomaly = activeAnomalies.length > 0 ? activeAnomalies[0] : null;
        anomalyDismissed = (activeAnomalies.length === 0);
    }

    function formatAnomalyStatus(alert) {
        if (!alert) {
            return 'No anomaly detected';
        }
        if (alert.details) {
            return alert.details;
        }
        if (alert.type === 'BRUTE_FORCE_LOGIN') {
            return 'Multiple failed logins detected for "' + (alert.user || 'UNKNOWN') + '".';
        }
        return 'Anomaly detected.';
    }

    function getRootUrl() {
        var head = document.querySelector('head');
        if (head && head.dataset && typeof head.dataset.rooturl === 'string') {
            return head.dataset.rooturl;
        }
        return '';
    }

    function loadUiDefaults() {
        var container = document.getElementById('auditContainer');
        if (!container || !container.dataset) {
            return;
        }
        defaultViewMode = container.dataset.defaultViewMode || 'all';
        defaultDatePreset = container.dataset.defaultDatePreset || '';
        defaultDateFrom = container.dataset.defaultDateFrom || '';
        defaultDateTo = container.dataset.defaultDateTo || '';
        onboardingStorageKey = container.dataset.onboardingStorageKey || 'auditflow-onboarded';
    }

    function applyConfiguredDefaults() {
        var searchText = document.getElementById('searchText');
        if (searchText) {
            searchText.value = '';
        }

        var searchColumn = document.getElementById('searchColumn');
        if (searchColumn) {
            searchColumn.value = 'all';
        }

        var filterAction = document.getElementById('filterAction');
        if (filterAction) {
            filterAction.value = '';
        }

        var pageSizeSelect = document.getElementById('pageSize');
        if (pageSizeSelect) {
            pageSizeSelect.value = '100';
        }
        pageSize = 100;
        currentPage = 1;
        sortField = 'timestampMs';
        sortAsc = false;

        var selectedViewMode = document.querySelector('input[name="viewMode"][value="' + defaultViewMode + '"]');
        if (selectedViewMode) {
            selectedViewMode.checked = true;
        }

        var datePreset = document.getElementById('datePreset');
        if (datePreset) {
            datePreset.value = defaultDatePreset;
        }

        var dateFrom = document.getElementById('dateFrom');
        if (dateFrom) {
            dateFrom.value = defaultDateFrom;
        }

        var dateTo = document.getElementById('dateTo');
        if (dateTo) {
            dateTo.value = defaultDateTo;
        }

        updateDateRangeVisibility();
    }

    function loadLogs(resetPage) {
        if (resetPage) {
            currentPage = 1;
        }

        var tbody = document.getElementById('tbody');
        if (tbody) {
            tbody.innerHTML = '<tr><td colspan="7">Loading...</td></tr>';
        }

        var params = buildRequestParams(true);
        fetch('api?' + params.toString())
            .then(function(response) {
                if (!response.ok) {
                    throw new Error('Request failed with status ' + response.status);
                }
                return response.json();
            })
            .then(function(data) {
                allLogs = data.logs || [];
                currentInsights = data.insights || [];
                currentSummary = data.summary || {};
                anomalyConfig = data.anomalyConfig || {};
                totalLogs = data.total || 0;
                totalPages = data.totalPages || 1;
                currentPage = data.page || currentPage;
                displayTimeZone = data.displayTimeZone || 'UTC';
                displayToday = data.displayToday || '';

                // hey! grabbing our new alerts from Phase 2
                var serverAnomalies = data.anomalies || [];
                refreshAnomalyDismissState(serverAnomalies);

                renderStats(currentSummary);
                computeRiskPanel(currentSummary);

                // show our new backend anomalies!
                renderServerAnomalies(serverAnomalies);
                
                scaleStatsGrid();
                renderTable(allLogs);
                updateResultCount();
                updateTimeZoneLabel();
                updatePaginationBar(totalPages);
                refreshInsightsIfVisible();
            })
            .catch(function() {
                var tbodyEl = document.getElementById('tbody');
                if (tbodyEl) {
                    tbodyEl.innerHTML = '<tr><td colspan="7">Error loading logs.</td></tr>';
                }
            });
    }

    function buildRequestParams(includePaging) {
        var params = new URLSearchParams();
        params.set('searchColumn', document.getElementById('searchColumn').value || 'all');
        params.set('searchText', document.getElementById('searchText').value || '');
        params.set('action', document.getElementById('filterAction').value || '');

        var checkedViewMode = document.querySelector('input[name="viewMode"]:checked');
        params.set('viewMode', checkedViewMode ? checkedViewMode.value : defaultViewMode);
        params.set('sortField', sortField || 'timestampMs');
        params.set('sortDir', sortAsc ? 'asc' : 'desc');

        var from = document.getElementById('dateFrom').value || '';
        var to = document.getElementById('dateTo').value || '';
        if (from) {
            params.set('dateFrom', from);
        }
        if (to) {
            params.set('dateTo', to);
        }

        if (includePaging !== false) {
            params.set('page', currentPage);
            params.set('pageSize', pageSize);
        }
        return params;
    }

    function updateResultCount() {
        var label = document.getElementById('resultCount');
        if (!label) {
            return;
        }
        if (totalLogs === 0) {
            label.textContent = '0 events';
            return;
        }
        if (pageSize <= 0 || allLogs.length >= totalLogs) {
            label.textContent = totalLogs + ' events';
            return;
        }
        label.textContent = 'Showing ' + allLogs.length + ' of ' + totalLogs + ' events';
    }

    function updateDateRangeVisibility() {
        var fields = document.getElementById('dateRangeFields');
        var datePreset = document.getElementById('datePreset');
        if (!fields || !datePreset) {
            return;
        }
        setHidden(fields, !!datePreset.value);
    }

    function updateTimeZoneLabel() {
        var label = document.getElementById('timestampTimeZone');
        if (label) {
            label.textContent = displayTimeZone
                ? ' (' + displayTimeZone + ')'
                : '';
        }
    }

    function applySearch() {
        loadLogs(true);
    }

    function sortBy(field) {
        if (sortField === field) {
            sortAsc = !sortAsc;
        } else {
            sortField = field;
            sortAsc = true;
        }
        loadLogs(true);
    }

    function updatePaginationBar(totalPagesCount) {
        var bar = document.getElementById('paginationBar');
        if (!bar) {
            return;
        }
        if (pageSize <= 0 || totalPagesCount <= 1 || totalLogs === 0) {
            setHidden(bar, true);
            return;
        }
        setHidden(bar, false);
        document.getElementById('pageInfo').textContent = 'Page ' + currentPage + ' of ' + totalPagesCount;
        document.getElementById('btnFirst').disabled = currentPage <= 1;
        document.getElementById('btnPrev').disabled = currentPage <= 1;
        document.getElementById('btnNext').disabled = currentPage >= totalPagesCount;
        document.getElementById('btnLast').disabled = currentPage >= totalPagesCount;
    }

    function changePageSize() {
        pageSize = parseInt(document.getElementById('pageSize').value, 10) || 0;
        currentPage = 1;
        loadLogs(false);
    }

    function firstPage() {
        if (currentPage === 1) {
            return;
        }
        currentPage = 1;
        loadLogs(false);
    }

    function prevPage() {
        if (currentPage <= 1) {
            return;
        }
        currentPage--;
        loadLogs(false);
    }

    function nextPage() {
        if (currentPage >= totalPages) {
            return;
        }
        currentPage++;
        loadLogs(false);
    }

    function lastPage() {
        if (currentPage === totalPages) {
            return;
        }
        currentPage = totalPages;
        loadLogs(false);
    }

    function renderTable(logs) {
        var tbody = document.getElementById('tbody');
        if (!tbody) {
            return;
        }
        tbody.innerHTML = '';
        if (!logs || logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="empty-state">'
                + '<h2>No audit events found</h2>'
                + '<p>Events will appear here as users log in, run builds, and modify configuration. Try adjusting your filters or check back later.</p>'
                + '</td></tr>';
            return;
        }

        for (var i = 0; i < logs.length; i++) {
            var entry = logs[i];
            var row = document.createElement('tr');
            var severityClass = severityBadgeClass(entry.severity, entry.action);
            row.innerHTML = ''
                + '<td class="timestamp-cell">' + esc(entry.readable || '') + '</td>'
                + '<td><strong>' + esc(entry.user || '') + '</strong></td>'
                + '<td><span class="badge ' + severityClass + '" title="Severity: ' + esc(entry.severity || 'INFO') + '">' + esc(formatAction(entry.action)) + '</span></td>'
                + '<td class="target-cell">' + esc(entry.target || '') + '</td>'
                + '<td class="detail-cell" title="' + escAttr(entry.details || '') + '">' + esc(entry.details || '') + '</td>'
                + '<td class="ip-cell">' + esc(entry.sourceIp || '-') + '</td>'
                + '<td>' + esc(entry.authMethod || entry.triggerType || '-') + '</td>';
            tbody.appendChild(row);
        }
    }

    function computeRiskPanel(summary) {
        var failedLogins = summary.riskFailedCount || 0;
        var credentialEvents = summary.riskCredentialCount || 0;
        var ipCount = summary.riskIpCount || 0;

        document.getElementById('riskFailedCount').textContent = failedLogins;
        document.getElementById('riskCredentialCount').textContent = credentialEvents;
        document.getElementById('riskIpCount').textContent = ipCount;

        var failedCard = document.getElementById('riskFailedLogins');
        if (failedCard) {
            failedCard.className = 'risk-card ' + (failedLogins >= 5 ? 'risk-red' : failedLogins >= 2 ? 'risk-orange' : 'risk-green');
        }
        var credentialCard = document.getElementById('riskCredentials');
        if (credentialCard) {
            credentialCard.className = 'risk-card ' + (credentialEvents >= 10 ? 'risk-red' : credentialEvents >= 3 ? 'risk-orange' : 'risk-green');
        }
    }

    function renderStats(summary) {
        var element;
        element = document.getElementById('stat-total'); if (element) { element.textContent = summary.todayTotal || 0; }
        element = document.getElementById('stat-logins'); if (element) { element.textContent = summary.todayLogins || 0; }
        element = document.getElementById('stat-failed'); if (element) { element.textContent = summary.todayFailed || 0; }
        element = document.getElementById('stat-builds'); if (element) { element.textContent = summary.todayBuilds || 0; }
        element = document.getElementById('stat-jobs'); if (element) { element.textContent = summary.todayJobs || 0; }
        element = document.getElementById('stat-config'); if (element) { element.textContent = summary.todayConfig || 0; }
    }

    function scaleStatsGrid() {
        var statsDiv = document.getElementById('stats');
        if (!statsDiv) {
            return;
        }
        var boxes = statsDiv.querySelectorAll('.stat-box');
        var count = boxes.length;
        if (count > 0) {
            statsDiv.style.gridTemplateColumns = 'repeat(' + count + ', 1fr)';
        }
    }

    function extractEntityFromDetails(details) {
        if (!details || typeof details !== 'string') return '';
        var m = details.match(/(?:provisioned|deleted|target|account|user|credential):\s*([^\s,]+)/i);
        if (m && m[1]) return m[1].replace(/["']/g, '').trim();
        var mQuote = details.match(/["']([^"']+)["']/);
        if (mQuote && mQuote[1]) return mQuote[1].trim();
        return '';
    }

    function filterByAnomaly(alert, element) {
        if (!alert) return;

        var alertId = alert.alertId || ('auditflow-' + (alert.type || '') + '-' + (alert.user || '') + '-' + (alert.timestamp || ''));
        activeFilteredAnomalyAlertId = alertId;

        // Highlight selected anomaly in the UI
        var allItems = document.querySelectorAll('.anomaly-combined-item, .anomaly-single-item');
        Array.prototype.forEach.call(allItems, function(el) {
            el.classList.remove('anomaly-item--active');
        });
        if (element) {
            element.classList.add('anomaly-item--active');
        }

        var searchInput = document.getElementById('searchText');
        var columnSelect = document.getElementById('searchColumn');
        var actionSelect = document.getElementById('filterAction');

        // Reset default filters first
        if (searchInput) searchInput.value = '';
        if (columnSelect) columnSelect.value = 'all';
        if (actionSelect) actionSelect.value = '';

        var type = alert.type || '';
        var hasRealUser = alert.user && alert.user !== 'UNKNOWN' && alert.user !== 'SYSTEM';
        var extractedTarget = extractEntityFromDetails(alert.details);

        // Smart filtering: Prioritize specific actor/target to avoid broad historical matches
        if (hasRealUser) {
            if (searchInput) searchInput.value = alert.user;
            if (columnSelect) columnSelect.value = 'user';

            if (type === 'BRUTE_FORCE_LOGIN') {
                if (actionSelect) actionSelect.value = 'FAILED_LOGIN';
            } else if (type === 'CREDENTIAL_EXPOSURE') {
                if (actionSelect) actionSelect.value = 'CREDENTIAL_ACCESSED';
            }
        } else if (extractedTarget) {
            if (searchInput) searchInput.value = extractedTarget;
            if (columnSelect) columnSelect.value = 'all';

            if (type === 'BRUTE_FORCE_LOGIN') {
                if (actionSelect) actionSelect.value = 'FAILED_LOGIN';
            } else if (type === 'CREDENTIAL_EXPOSURE') {
                if (actionSelect) actionSelect.value = 'CREDENTIAL_ACCESSED';
            }
        } else {
            // Fallback when neither actor nor target could be extracted
            if (type === 'BRUTE_FORCE_LOGIN') {
                if (actionSelect) actionSelect.value = 'FAILED_LOGIN';
            } else if (type === 'ADMIN_PRIVILEGE_CHANGE') {
                if (searchInput) searchInput.value = 'SECURITY';
                if (columnSelect) columnSelect.value = 'action';
            } else if (type === 'USER_LIFECYCLE_ANOMALY') {
                if (searchInput) searchInput.value = 'USER';
                if (columnSelect) columnSelect.value = 'action';
            } else if (type === 'CREDENTIAL_EXPOSURE') {
                if (actionSelect) actionSelect.value = 'CREDENTIAL_ACCESSED';
            } else if (alert.details) {
                var keyword = alert.details.split(':')[0] || alert.details;
                if (searchInput) searchInput.value = keyword.trim();
                if (columnSelect) columnSelect.value = 'all';
            }
        }

        // Show active anomaly filter indicator pill
        var indicator = document.getElementById('anomalyFilterIndicator');
        var indicatorText = document.getElementById('anomalyFilterText');
        if (indicator && indicatorText) {
            var label = (alert.type || 'ANOMALY').replace(/_/g, ' ');
            if (hasRealUser) {
                label += ' (' + alert.user + ')';
            } else if (extractedTarget) {
                label += ' (' + extractedTarget + ')';
            }
            indicatorText.textContent = label;
            indicator.classList.remove('jenkins-hidden');
        }

        // Load logs with applied filters
        loadLogs(true);

        // Smooth scroll to logs table
        var targetCard = document.getElementById('logsTable') || document.querySelector('.table-meta');
        if (targetCard) {
            targetCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }

    function clearAnomalyFilter() {
        activeFilteredAnomalyAlertId = null;
        var allItems = document.querySelectorAll('.anomaly-combined-item, .anomaly-single-item');
        Array.prototype.forEach.call(allItems, function(el) {
            el.classList.remove('anomaly-item--active');
        });

        var indicator = document.getElementById('anomalyFilterIndicator');
        if (indicator) {
            indicator.classList.add('jenkins-hidden');
        }

        var searchInput = document.getElementById('searchText');
        var columnSelect = document.getElementById('searchColumn');
        var actionSelect = document.getElementById('filterAction');
        if (searchInput) searchInput.value = '';
        if (columnSelect) columnSelect.value = 'all';
        if (actionSelect) actionSelect.value = '';

        loadLogs(true);
    }

    function bindAnomalyItemClickListeners() {
        var status = document.getElementById('anomalyStatus');
        if (!status) return;

        var items = status.querySelectorAll('.anomaly-combined-item, .anomaly-single-item');
        Array.prototype.forEach.call(items, function(item) {
            var idx = parseInt(item.getAttribute('data-alert-index'), 10);
            if (isNaN(idx) || !activeAnomalies[idx]) return;

            var alert = activeAnomalies[idx];

            item.addEventListener('click', function(e) {
                if (e.target && (e.target.classList.contains('anomaly-item__dismiss') || e.target.closest('.anomaly-item__dismiss'))) {
                    return;
                }
                e.preventDefault();
                filterByAnomaly(alert, item);
            });

            item.addEventListener('keydown', function(e) {
                if (e.target && (e.target.classList.contains('anomaly-item__dismiss') || e.target.closest('.anomaly-item__dismiss'))) {
                    return;
                }
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    filterByAnomaly(alert, item);
                }
            });
        });

        // Bind individual anomaly dismiss buttons (✕)
        var dismissButtons = status.querySelectorAll('.anomaly-item__dismiss');
        Array.prototype.forEach.call(dismissButtons, function(btn) {
            btn.addEventListener('click', function(e) {
                e.stopPropagation();
                e.preventDefault();
                var alertId = btn.getAttribute('data-alert-id');
                dismissSingleAnomaly(alertId);
            });
            btn.addEventListener('keydown', function(e) {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.stopPropagation();
                    e.preventDefault();
                    var alertId = btn.getAttribute('data-alert-id');
                    dismissSingleAnomaly(alertId);
                }
            });
        });
    }

    // displays our real backend anomalies - combines all undismissed ones
    function renderServerAnomalies(anomalies) {
        var box = document.getElementById('anomalyBox');
        var status = document.getElementById('anomalyStatus');
        var dismissBtn = document.getElementById('btnDismiss');
        var instruction = document.getElementById('anomalyInstruction');
        if (!box || !status) return;

        if (anomalies && Array.isArray(anomalies)) {
            lastServerAnomalies = anomalies;
        }
        activeAnomalies = getUndismissedAnomalies(lastServerAnomalies);

        if (activeAnomalies.length > 0) {
            box.classList.remove('jenkins-hidden');
            box.classList.add('anomaly-alert');
            box.classList.remove('anomaly-dismissed');

            if (instruction) {
                instruction.textContent = activeAnomalies.length > 1
                    ? '(Click any anomaly to view relevant logs)'
                    : '(Click to view relevant logs)';
            }

            if (dismissBtn) {
                if (activeAnomalies.length > 1) {
                    dismissBtn.classList.remove('jenkins-hidden');
                    dismissBtn.textContent = 'Dismiss All';
                    dismissBtn.setAttribute('title', 'Dismiss all ' + activeAnomalies.length + ' active anomalies');
                } else {
                    dismissBtn.classList.add('jenkins-hidden');
                }
            }

            if (activeAnomalies.length === 1) {
                var singleAlert = activeAnomalies[0];
                var singleSev = singleAlert.severity || 'HIGH';
                var singleSevClass = severityBadgeClass(singleSev, '');
                var singleAlertId = singleAlert.alertId || ('auditflow-' + (singleAlert.type || '') + '-' + (singleAlert.user || '') + '-' + (singleAlert.timestamp || ''));
                var isActive = (activeFilteredAnomalyAlertId === singleAlertId);

                var html = '<div class="anomaly-single-item' + (isActive ? ' anomaly-item--active' : '') + '" role="button" tabindex="0" data-alert-index="0" data-alert-id="' + escAttr(singleAlertId) + '" title="Click to view relevant logs for ' + escAttr(singleAlert.user || 'this anomaly') + '">'
                    + '<span class="badge ' + singleSevClass + '">' + esc(singleSev) + '</span> '
                    + '<span class="anomaly-combined-text">' + esc(formatAnomalyStatus(singleAlert)) + '</span>'
                    + '<button type="button" class="anomaly-item__dismiss" data-alert-id="' + escAttr(singleAlertId) + '" title="Dismiss this alert" aria-label="Dismiss this alert">✕</button>'
                    + '</div>';
                status.innerHTML = html;
            } else {
                var html = '<ul class="anomaly-combined-list">';
                for (var i = 0; i < activeAnomalies.length; i++) {
                    var alert = activeAnomalies[i];
                    var sev = alert.severity || 'HIGH';
                    var sevClass = severityBadgeClass(sev, '');
                    var alertId = alert.alertId || ('auditflow-' + (alert.type || '') + '-' + (alert.user || '') + '-' + (alert.timestamp || ''));
                    var isActive = (activeFilteredAnomalyAlertId === alertId);

                    html += '<li class="anomaly-combined-item' + (isActive ? ' anomaly-item--active' : '') + '" role="button" tabindex="0" data-alert-index="' + i + '" data-alert-id="' + escAttr(alertId) + '" title="Click to view relevant logs for ' + escAttr(alert.user || 'this anomaly') + '">'
                        + '<span class="badge ' + sevClass + '">' + esc(sev) + '</span> '
                        + '<span class="anomaly-combined-text">' + esc(formatAnomalyStatus(alert)) + '</span>'
                        + '<button type="button" class="anomaly-item__dismiss" data-alert-id="' + escAttr(alertId) + '" title="Dismiss this alert" aria-label="Dismiss this alert">✕</button>'
                        + '</li>';
                }
                html += '</ul>';
                status.innerHTML = html;
            }
            bindAnomalyItemClickListeners();
        } else if (activeAnomalies.length === 0 && anomalyDismissed) {
            box.classList.add('jenkins-hidden');
            box.classList.remove('anomaly-alert');
            box.classList.add('anomaly-dismissed');
            status.textContent = 'No anomaly detected';
            if (dismissBtn) {
                dismissBtn.classList.add('jenkins-hidden');
            }
        } else {
            box.classList.add('jenkins-hidden');
            box.classList.remove('anomaly-alert');
            box.classList.remove('anomaly-dismissed');
            status.textContent = 'No anomaly detected';
            if (dismissBtn) {
                dismissBtn.classList.add('jenkins-hidden');
            }
        }
    }

    function dismissSingleAnomaly(alertId) {
        if (!alertId) return;

        saveDismissedAlertIds([alertId]);

        // Tell server to dismiss specific alert
        fetch('dismissAlert?alertId=' + encodeURIComponent(alertId)).catch(function() {});

        // If this alert was actively filtered, clear the filter
        if (activeFilteredAnomalyAlertId === alertId) {
            clearAnomalyFilter();
        }

        // Re-render server anomalies with remaining active alerts
        renderServerAnomalies(lastServerAnomalies);
    }

    function dismissAnomaly() {
        anomalyDismissed = true;
        activeFilteredAnomalyAlertId = null;
        var indicator = document.getElementById('anomalyFilterIndicator');
        if (indicator) {
            indicator.classList.add('jenkins-hidden');
        }

        var idsToDismiss = [];
        if (activeAnomalies && activeAnomalies.length > 0) {
            for (var i = 0; i < activeAnomalies.length; i++) {
                var a = activeAnomalies[i];
                var id = a.alertId || ('auditflow-' + (a.type || '') + '-' + (a.user || '') + '-' + (a.timestamp || ''));
                if (id) {
                    idsToDismiss.push(id);
                }
            }
        }

        saveDismissedAlertIds(idsToDismiss);

        // Tell server to dismiss all
        fetch('dismissAlert?alertId=ALL').catch(function() {});

        activeAnomalies = [];

        var box = document.getElementById('anomalyBox');
        var status = document.getElementById('anomalyStatus');
        var dismissBtn = document.getElementById('btnDismiss');
        if (box) {
            box.classList.add('jenkins-hidden');
            box.classList.remove('anomaly-alert');
            box.classList.add('anomaly-dismissed');
        }
        if (status) {
            status.textContent = 'No anomaly detected';
        }
        if (dismissBtn) {
            dismissBtn.classList.add('jenkins-hidden');
        }
    }

    function severityBadgeClass(sev, action) {
        if (action === 'USER_CONFIG_UPDATED') {
            return 'badge-info';
        }
        if (sev === 'CRITICAL') {
            return 'badge-critical';
        }
        if (sev === 'HIGH') {
            return 'badge-high';
        }
        if (sev === 'MEDIUM') {
            return 'badge-medium';
        }
        if (sev === 'LOW') {
            return 'badge-low';
        }
        return 'badge-info';
    }

    function formatAction(action) {
        if (!action) {
            return '';
        }
        return action.replace(/_/g, ' ');
    }

    function clearAll() {
        var indicator = document.getElementById('anomalyFilterIndicator');
        if (indicator) {
            indicator.classList.add('jenkins-hidden');
        }
        var allItems = document.querySelectorAll('.anomaly-combined-item, .anomaly-single-item');
        Array.prototype.forEach.call(allItems, function(el) {
            el.classList.remove('anomaly-item--active');
        });
        activeFilteredAnomalyAlertId = null;

        applyConfiguredDefaults();
        loadLogs(false);
    }

    function applyDatePreset() {
        var preset = document.getElementById('datePreset').value;
        if (!preset) {
            updateDateRangeVisibility();
            loadLogs(true);
            return;
        }
        var base = getPresetBaseDate();
        var to = formatDateForInput(base);
        var fromDate = new Date(base.getTime());
        if (preset === '7d') {
            fromDate.setUTCDate(fromDate.getUTCDate() - 6);
        } else if (preset === 'month') {
            fromDate = new Date(Date.UTC(base.getUTCFullYear(), base.getUTCMonth(), 1));
        } else if (preset === '3m') {
            fromDate = new Date(Date.UTC(base.getUTCFullYear(), base.getUTCMonth() - 2, 1));
        } else if (preset === '6m') {
            fromDate = new Date(Date.UTC(base.getUTCFullYear(), base.getUTCMonth() - 5, 1));
        }
        document.getElementById('dateFrom').value = formatDateForInput(fromDate);
        document.getElementById('dateTo').value = to;
        updateDateRangeVisibility();
        loadLogs(true);
    }

    function onDateManualChange() {
        document.getElementById('datePreset').value = '';
        updateDateRangeVisibility();
        loadLogs(true);
    }

    function getPresetBaseDate() {
        if (displayToday) {
            var parsed = new Date(displayToday + 'T00:00:00Z');
            if (!isNaN(parsed.getTime())) {
                return parsed;
            }
        }
        var now = new Date();
        return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
    }

    function formatDateForInput(date) {
        var year = date.getUTCFullYear();
        var month = String(date.getUTCMonth() + 1).padStart(2, '0');
        var day = String(date.getUTCDate()).padStart(2, '0');
        return year + '-' + month + '-' + day;
    }

    function exportData(fmt) {
        var params = buildRequestParams(false).toString();
        if (fmt === 'json') {
            window.location.href = 'exportJson?' + params;
        } else {
            window.location.href = 'exportCsv?' + params;
        }
    }

    function dismissOnboarding() {
        var banner = document.getElementById('onboardingBanner');
        setHidden(banner, true);
        try {
            localStorage.setItem(onboardingStorageKey, '1');
        } catch (ignored) {
            // Ignore localStorage availability issues.
        }
    }

    function isOnboardingDismissed() {
        try {
            return localStorage.getItem(onboardingStorageKey) === '1';
        } catch (ignored) {
            return false;
        }
    }

    function esc(value) {
        var element = document.createElement('span');
        element.textContent = String(value);
        return element.innerHTML;
    }

    function escAttr(value) {
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/"/g, '&quot;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');
    }

    function generateSVGIcon(iconName) {
        var icons = document.getElementById('auditflow-icons');
        if (!icons || !icons.content) {
            return null;
        }

        var templateIcon = icons.content.querySelector('[data-auditflow-icon="' + iconName + '"]');
        if (!templateIcon || !templateIcon.firstElementChild) {
            return null;
        }

        var icon = templateIcon.firstElementChild.cloneNode(true);
        icon.classList.add('insights-icon');
        icon.setAttribute('aria-hidden', 'true');
        return icon;
    }

    function refreshInsightsIfVisible() {
        var panel = document.getElementById('insightsPanel');
        if (panel && !panel.classList.contains('jenkins-hidden')) {
            renderInsights(currentInsights);
        }
    }

    function toggleInsights() {
        var panel = document.getElementById('insightsPanel');
        if (!panel) {
            return;
        }
        var hidden = panel.classList.toggle('jenkins-hidden');
        if (!hidden) {
            renderInsights(currentInsights);
        }
    }

    function closeInsights() {
        var panel = document.getElementById('insightsPanel');
        if (panel) {
            panel.classList.add('jenkins-hidden');
        }
    }

    function renderInsights(insights) {
        var list = document.getElementById('insightsList');
        if (!list) {
            return;
        }
        if (!insights || insights.length === 0) {
            list.innerHTML = '<li class="insights-empty">No notable activity recorded today.</li>';
            return;
        }

        list.innerHTML = '';
        var fragment = document.createDocumentFragment();
        for (var i = 0; i < insights.length; i++) {
            var insight = insights[i];
            var severityClass = insight.severity === 'critical'
                ? 'badge-critical'
                : insight.severity === 'high'
                    ? 'badge-high'
                    : insight.severity === 'medium'
                        ? 'badge-medium'
                        : 'badge-low';

            var item = document.createElement('li');
            var icon = insight.icon ? generateSVGIcon(insight.icon) : null;
            if (icon) {
                item.appendChild(icon);
            } else {
                var placeholder = document.createElement('span');
                placeholder.className = 'insights-icon insights-icon--placeholder';
                placeholder.setAttribute('aria-hidden', 'true');
                item.appendChild(placeholder);
            }

            var text = document.createElement('span');
            text.className = 'insights-text';
            text.textContent = insight.text || '';
            item.appendChild(text);

            var badge = document.createElement('span');
            badge.className = 'badge insights-badge ' + severityClass;
            badge.textContent = String(insight.count || 0);
            item.appendChild(badge);

            fragment.appendChild(item);
        }
        list.appendChild(fragment);
    }

    function bindExportAction(button) {
        if (!button || button.dataset.auditflowBound === 'true') {
            return;
        }
        button.dataset.auditflowBound = 'true';
        button.addEventListener('click', function(event) {
            event.preventDefault();
            exportData(button.getAttribute('data-export-format'));
        });
    }

    function registerExportHandlers() {
        if (window.Behaviour && typeof window.Behaviour.specify === 'function') {
            Behaviour.specify('.data-export', 'auditflow-export', 0, bindExportAction);
            if (typeof Behaviour.applySubtree === 'function') {
                Behaviour.applySubtree(document);
            }
            return;
        }

        Array.prototype.forEach.call(document.querySelectorAll('.data-export'), bindExportAction);
    }

    function bindUiHandlers() {
        registerExportHandlers();

        var searchText = document.getElementById('searchText');
        if (searchText) {
            searchText.addEventListener('search', applySearch);
            searchText.addEventListener('keydown', function(event) {
                if (event.key === 'Enter') {
                    event.preventDefault();
                    applySearch();
                }
            });
        }

        var applySearchButton = document.getElementById('applySearchButton');
        if (applySearchButton) {
            applySearchButton.addEventListener('click', applySearch);
        }

        var clearAllButton = document.getElementById('clearAllButton');
        if (clearAllButton) {
            clearAllButton.addEventListener('click', clearAll);
        }

        var btnClearAnomalyFilter = document.getElementById('btnClearAnomalyFilter');
        if (btnClearAnomalyFilter) {
            btnClearAnomalyFilter.addEventListener('click', clearAnomalyFilter);
        }

        var refreshLogsButton = document.getElementById('refreshLogsButton');
        if (refreshLogsButton) {
            refreshLogsButton.addEventListener('click', function() {
                loadLogs(false);
            });
        }

        var toggleInsightsButton = document.getElementById('toggleInsightsButton');
        if (toggleInsightsButton) {
            toggleInsightsButton.addEventListener('click', toggleInsights);
        }

        var closeInsightsButton = document.getElementById('closeInsightsButton');
        if (closeInsightsButton) {
            closeInsightsButton.addEventListener('click', closeInsights);
        }

        var dismissOnboardingButton = document.getElementById('dismissOnboardingButton');
        if (dismissOnboardingButton) {
            dismissOnboardingButton.addEventListener('click', dismissOnboarding);
        }

        var dismissButton = document.getElementById('btnDismiss');
        if (dismissButton) {
            dismissButton.addEventListener('click', dismissAnomaly);
        }

        Array.prototype.forEach.call(document.querySelectorAll('input[name="viewMode"]'), function(input) {
            input.addEventListener('change', applySearch);
        });

        var filterAction = document.getElementById('filterAction');
        if (filterAction) {
            filterAction.addEventListener('change', applySearch);
        }

        var pageSizeSelect = document.getElementById('pageSize');
        if (pageSizeSelect) {
            pageSizeSelect.addEventListener('change', changePageSize);
        }

        var datePreset = document.getElementById('datePreset');
        if (datePreset) {
            datePreset.addEventListener('change', applyDatePreset);
        }

        var dateFrom = document.getElementById('dateFrom');
        if (dateFrom) {
            dateFrom.addEventListener('change', onDateManualChange);
        }

        var dateTo = document.getElementById('dateTo');
        if (dateTo) {
            dateTo.addEventListener('change', onDateManualChange);
        }

        Array.prototype.forEach.call(document.querySelectorAll('th[data-sort-field]'), function(header) {
            header.addEventListener('click', function() {
                sortBy(header.getAttribute('data-sort-field'));
            });
        });

        var btnFirst = document.getElementById('btnFirst');
        if (btnFirst) {
            btnFirst.addEventListener('click', firstPage);
        }

        var btnPrev = document.getElementById('btnPrev');
        if (btnPrev) {
            btnPrev.addEventListener('click', prevPage);
        }

        var btnNext = document.getElementById('btnNext');
        if (btnNext) {
            btnNext.addEventListener('click', nextPage);
        }

        var btnLast = document.getElementById('btnLast');
        if (btnLast) {
            btnLast.addEventListener('click', lastPage);
        }
    }

    window.addEventListener('load', function() {
        loadUiDefaults();
        applyConfiguredDefaults();
        bindUiHandlers();
        if (!isOnboardingDismissed()) {
            setHidden(document.getElementById('onboardingBanner'), false);
        }
        loadLogs(false);
    });

    window.auditflowDebug = {
        parsePatterns: parsePatterns,
        matchesAnyPattern: matchesAnyPattern,
        globMatch: globMatch,
        getAnomalyConfig: function() { return anomalyConfig; }
    };
})();
