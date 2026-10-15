const scanButton = document.getElementById("scanButton");
const result = document.getElementById("result");

const detailToggle = document.getElementById("detailToggle");

let showDetails = false;

let lastScanHtml = null;


function escapeHtml(value) {

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


function riskClass(risk) {

    if (risk === "HIGH") {
        return "risk-high";
    }

    if (risk === "MEDIUM") {
        return "risk-medium";
    }

    return "risk-low";
}


function renderList(items, emptyMessage = "None detected") {

    if (!items || items.length === 0) {

        return `<div class="empty">${escapeHtml(emptyMessage)}</div>`;
    }

    return `
        <ul>
            ${items.map(item => `<li>${escapeHtml(item)}</li>`).join("")}
        </ul>
    `;
}


function renderDetectedInformation(items) {

    if (!items || items.length === 0) {

        return `<div class="empty">None detected</div>`;
    }

    return `
        <div class="tag-container">
            ${items.map(item => {

                const name =
                    item.category
                        .replaceAll("_", " ");

                return `
                    <span class="tag">
                        ${escapeHtml(name)}
                    </span>
                `;

            }).join("")}
        </div>
    `;
}


function renderFormFields(fields) {

    if (!fields || fields.length === 0) {

        return `<div class="empty">
            No form fields found that collect sensitive information
        </div>`;
    }

    return `
        <ul class="field-list">
            ${fields.map(field => {

                const category =
                    field.category
                        .replaceAll("_", " ");

                const details = [];

                if (field.label) {
                    details.push(
                        `label: "${escapeHtml(field.label)}"`
                    );
                }

                if (field.placeholder) {
                    details.push(
                        `placeholder: "${escapeHtml(field.placeholder)}"`
                    );
                }

                if (field.accessibleLabel) {
                    details.push(
                        `accessible label: "${escapeHtml(field.accessibleLabel)}"`
                    );
                }

                if (field.instructions) {
                    details.push(
                        `instructions: "${escapeHtml(field.instructions)}"`
                    );
                }

                if (field.formPurpose) {
                    details.push(
                        `form: "${escapeHtml(field.formPurpose)}"`
                    );
                }

                return `
                    <li class="field-item">

                        <strong>
                            ${escapeHtml(category)}
                        </strong>
                        ${field.type
                            ? ` — input type "${escapeHtml(field.type)}"`
                            : ""}
                        ${field.required ? " — required" : ""}

                        ${details.length
                            ? `<div class="field-meta">${details.join("<br>")}</div>`
                            : ""}

                        ${field.evidence && field.evidence.length
                            ? `<div class="field-evidence">
                                 Because: ${field.evidence.map(
                                    item => escapeHtml(item)
                                 ).join("; ")}
                               </div>`
                            : ""}

                        ${field.crossOriginAction
                            ? `<div class="field-evidence warning">
                                 Submits to a different domain:
                                 ${escapeHtml(field.formAction)}
                               </div>`
                            : ""}

                    </li>
                `;

            }).join("")}
        </ul>
    `;
}


function renderCollectionSummary(summary) {

    if (!summary) {

        return `<div class="empty">
            No form-collection summary available
        </div>`;
    }

    const collected =
        summary.collected_categories || [];

    const mentionedOnly =
        summary.mentioned_only_categories || [];

    return `
        <p><strong>Actually requested by form fields</strong></p>

        ${collected.length
            ? renderDetectedInformation(
                collected.map(category => ({ category }))
              )
            : `<div class="empty">
                 None — no input field on this page asks for
                 sensitive information.
               </div>`}

        ${mentionedOnly.length ? `

            <p><strong>Only mentioned in the page text</strong></p>

            <div class="mention-note">
                These words appear in the page content, but no input
                field was found that collects this type of information.
            </div>

            ${renderDetectedInformation(
                mentionedOnly.map(category => ({ category }))
            )}
        ` : ""}

        ${summary.cross_origin_field_count ? `
            <div class="mention-note warning">
                ${summary.cross_origin_field_count}
                sensitive field(s) submit to a different domain
                than the page itself.
            </div>
        ` : ""}
    `;
}


function renderTfidfTerms(terms) {

    if (!terms || terms.length === 0) {

        return `<div class="empty">No TF-IDF terms found.</div>`;
    }

    return `
        <div class="term-list">

            ${terms.map(term => `
                <div class="term-row">

                    <span>
                        ${escapeHtml(term.term)}
                    </span>

                    <span>
                        ${Number(term.score).toFixed(4)}
                    </span>

                </div>
            `).join("")}

        </div>
    `;
}


function renderPiiEntities(items, modelLoaded) {

    if (!modelLoaded) {
        return `<div class="empty">
            PII model not trained. Run python train_pii_model.py.
        </div>`;
    }

    if (!items || items.length === 0) {
        return `<div class="empty">No PII spans detected</div>`;
    }

    const categoryLabels = {
        email: "Email addresses",
        phone: "Phone numbers",
        ip_address: "IP addresses",
        possible_pii: "Potential personal information (type unknown)"
    };
    const counts = {};

    items.forEach(item => {
        counts[item.type] = (counts[item.type] || 0) + 1;
    });

    return `
        <ul>
            ${Object.entries(counts).map(([type, count]) => `
                <li>
                    <strong>
                        ${escapeHtml(categoryLabels[type] || "Sensitive information")}
                    </strong>
                    ${count} ${count === 1 ? "match" : "matches"}; values hidden
                </li>
            `).join("")}
        </ul>
    `;
}


function renderProbabilities(probabilities) {

    if (!probabilities) {
        return "";
    }

    return `
        <div class="probabilities">

            <div>
                <span>LOW</span>
                <span>${probabilities.LOW}%</span>
            </div>

            <div>
                <span>MEDIUM</span>
                <span>${probabilities.MEDIUM}%</span>
            </div>

            <div>
                <span>HIGH</span>
                <span>${probabilities.HIGH}%</span>
            </div>

        </div>
    `;
}


function buildSimpleHtml(data, networkRecords) {

    return `
        <div class="risk-card ${riskClass(data.risk)}">

            <div class="risk-label">
                ${escapeHtml(data.risk)}
            </div>

            <div class="risk-title">
                Privacy Risk
            </div>

            <div class="risk-title">
                Indicator score
            </div>

            <div class="score">
                ${escapeHtml(data.risk_score)}
            </div>

        </div>


        <section>

            <h3>
                Data This Page Asks For
            </h3>

            ${renderCollectionSummary(
                data.collection_summary
            )}

        </section>


        <section>

            <h3>
                Sensitive Terms in Page Text
            </h3>

            <div class="mention-note">
                Keyword matches in visible text. These do not by
                themselves mean a form collects the data.
            </div>

            ${renderDetectedInformation(
                data.detected_information
            )}

        </section>


        <section>

            <h3>
                Third-Party Requests
            </h3>

            ${renderNetworkParties(networkRecords)}

        </section>


        <section>

            <h3>
                Recommendation
            </h3>

            <p>
                ${escapeHtml(
                    data.recommendation
                )}
            </p>

        </section>
    `;
}


function renderNetworkParties(records) {

    if (!records || records.length === 0) {

        return `
            <div class="empty">
                No network requests recorded for this tab yet.
            </div>
        `;
    }

    const counts = {
        firstParty: 0,
        thirdParty: 0,
        unknown: 0
    };

    const thirdPartyDomains = {};

    records.forEach((record) => {

        if (record.partyClassification === "first-party") {
            counts.firstParty += 1;
        } else if (record.partyClassification === "third-party") {
            counts.thirdParty += 1;

            const domain =
                record.requestRegistrableDomain ||
                record.requestDomain ||
                "unknown";

            thirdPartyDomains[domain] =
                (thirdPartyDomains[domain] || 0) + 1;
        } else {
            counts.unknown += 1;
        }
    });

    const rankedDomains =
        Object.entries(thirdPartyDomains)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 15);

    return `
        <div class="network-counts">

            <div>
                <span>First-party requests</span>
                <span>${counts.firstParty}</span>
            </div>

            <div>
                <span>Third-party requests</span>
                <span>${counts.thirdParty}</span>
            </div>

        </div>

        ${rankedDomains.length ? `
            <p><strong>Third-party domains contacted</strong></p>

            <div class="term-list">
                ${rankedDomains.map(([domain, count]) => `
                    <div class="term-row">
                        <span>${escapeHtml(domain)}</span>
                        <span>${count}</span>
                    </div>
                `).join("")}
            </div>
        ` : `
            <div class="empty">
                No third-party requests recorded for this tab.
            </div>
        `}

        <div class="mention-note">
            Third-party requests are a potential indicator only.
            They are common for fonts, payments, and embedded media
            and are not proof of tracking or a privacy breach.
        </div>
    `;
}


async function getTabNetworkRecords(tabId) {

    try {

        const stored =
            await chrome.storage.session.get({
                networkRecords: []
            });

        return (stored.networkRecords || []).filter(
            (record) => record.tabId === tabId
        );

    } catch (error) {

        console.error(
            "Could not read network records:",
            error
        );

        return [];
    }
}


async function saveScan(data, url) {

    const stored =
        await chrome.storage.local.get({
            scanHistory: []
        });

    const history = stored.scanHistory;

    history.unshift({
        url: url,
        risk: data.risk,
        risk_score: data.risk_score,
        confidence: data.confidence,
        timestamp: new Date().toISOString()
    });

    const limitedHistory = history.slice(0, 10);

    await chrome.storage.local.set({
        scanHistory: limitedHistory
    });
}


async function getCurrentTab() {

    const tabs = await chrome.tabs.query({
        active: true,
        currentWindow: true
    });

    return tabs[0];
}


async function scanPage() {

    scanButton.disabled = true;

    result.innerHTML = `
        <div class="loading">
            Scanning webpage...
        </div>
    `;

    try {

        const tab = await getCurrentTab();

        if (!tab || !tab.id) {

            throw new Error(
                "No active webpage was found."
            );
        }


        chrome.tabs.sendMessage(
            tab.id,
            {
                action: "analyzePage"
            },
            async (response) => {

                if (chrome.runtime.lastError) {

                    result.innerHTML = `
                        <div class="error-box">

                            <strong>
                                Could not scan this page.
                            </strong>

                            <p>
                                ${escapeHtml(
                                    chrome.runtime.lastError.message
                                )}
                            </p>

                            <p>
                                Try refreshing the webpage
                                and scan again.
                            </p>

                        </div>
                    `;

                    scanButton.disabled = false;
                    return;
                }


                if (!response || !response.success) {

                    result.innerHTML = `
                        <div class="error-box">
                            Unable to collect webpage data.
                        </div>
                    `;

                    scanButton.disabled = false;
                    return;
                }


                const pageData = response.data;


                result.innerHTML = `
                    <div class="loading">
                        Analyzing privacy risks and PII...
                    </div>
                `;


                try {

                    const apiResponse =
                        await fetch(
                            "http://127.0.0.1:5000/analyze",
                            {
                                method: "POST",

                                headers: {
                                    "Content-Type":
                                        "application/json"
                                },

                                body: JSON.stringify(
                                    pageData
                                )
                            }
                        );


                    if (!apiResponse.ok) {

                        throw new Error(
                            `API returned HTTP ${apiResponse.status}`
                        );
                    }


                    const data =
                        await apiResponse.json();


                    if (data.error) {

                        throw new Error(
                            data.error
                        );
                    }


                    // Read this tab's temporary network log for the
                    // first-party / third-party display.
                    const networkRecords =
                        await getTabNetworkRecords(tab.id);


                    lastScanHtml = {

                        simple: buildSimpleHtml(
                            data,
                            networkRecords
                        ),

                        full: `

                        <div class="risk-card ${riskClass(data.risk)}">

                            <div class="risk-label">
                                ${escapeHtml(data.risk)}
                            </div>

                            <div class="risk-title">
                                Privacy Risk
                            </div>

                            <div class="risk-title">
                                Indicator score
                            </div>

                            <div class="score">
                                ${escapeHtml(data.risk_score)}
                            </div>

                        </div>


                        <section>

                            <h3>Model confidence</h3>

                            <p>
                                ${escapeHtml(data.confidence)}% confidence in the
                                ${escapeHtml(data.risk)} classification
                            </p>

                            ${renderProbabilities(
                                data.probabilities
                            )}

                        </section>


                        <section>

                            <h3>Data This Page Asks For</h3>

                            ${renderCollectionSummary(
                                data.collection_summary
                            )}

                        </section>


                        <section>

                            <h3>
                                Sensitive Terms in Page Text
                            </h3>

                            <div class="mention-note">
                                Keyword matches in visible text. These
                                do not by themselves mean a form
                                collects the data.
                            </div>

                            ${renderDetectedInformation(
                                data.detected_information
                            )}

                        </section>


                        <section>

                            <h3>
                                Sensitive Form Fields
                            </h3>

                            ${renderFormFields(
                                data.sensitive_form_fields
                            )}

                        </section>


                        <section>

                            <h3>
                                Third-Party Requests
                            </h3>

                            ${renderNetworkParties(networkRecords)}

                        </section>


                        <section>

                            <h3>
                                Privacy Indicators
                            </h3>

                            <p><strong>Collection requests</strong></p>

                            ${renderList(
                                data.collection_indicators,
                                "No collection-related phrases detected."
                            )}

                            <p><strong>Tracking and analytics</strong></p>

                            ${renderList(
                                data.tracking_indicators,
                                "No tracking-related terms detected."
                            )}

                        </section>

                        ${false ? `
                        <section>

                            <h3>
                                PII Entity Detection
                            </h3>

                            ${renderPiiEntities(
                                data.pii_entities,
                                data.pii_entity_model_loaded
                            )}

                        </section>


                        <section>

                            <h3>
                                PII Patterns
                            </h3>

                            ${data.pii_patterns &&
                            data.pii_patterns.length
                                ? renderList(
                                    data.pii_patterns.map(
                                        item =>
                                            item.message
                                    )
                                )
                                : `<div class="empty">
                                    None detected
                                   </div>`
                            }

                        </section>
` : ""}

                        <section>

                            <h3>
                                Top TF-IDF Terms
                            </h3>

                            ${renderTfidfTerms(
                                data.tfidf_terms
                            )}

                        </section>


                        <section>

                            <h3>
                                Why?
                            </h3>

                            ${renderList(
                                data.explanation
                            )}

                        </section>


                        <section>

                            <h3>
                                Recommendation
                            </h3>

                            <p>
                                ${escapeHtml(
                                    data.recommendation
                                )}
                            </p>

                        </section>

                    `
                    };


                    result.innerHTML = showDetails
                        ? lastScanHtml.full
                        : lastScanHtml.simple;


                    await saveScan(
                        data,
                        pageData.url
                    );


                } catch (error) {

                    console.error(error);

                    result.innerHTML = `
                        <div class="error-box">

                            <strong>
                                Could not analyze webpage.
                            </strong>

                            <p>
                                ${escapeHtml(
                                    error.message
                                )}
                            </p>

                            <p>
                                Make sure the Flask API
                                is running on
                                127.0.0.1:5000.
                            </p>

                        </div>
                    `;
                }


                scanButton.disabled = false;

            }
        );

    } catch (error) {

        result.innerHTML = `
            <div class="error-box">
                ${escapeHtml(error.message)}
            </div>
        `;

        scanButton.disabled = false;
    }
}


scanButton.addEventListener(
    "click",
    scanPage
);


detailToggle.addEventListener(
    "change",
    () => {

        showDetails = detailToggle.checked;

        chrome.storage.local.set({
            showFullDetails: showDetails
        });

        if (lastScanHtml) {

            result.innerHTML = showDetails
                ? lastScanHtml.full
                : lastScanHtml.simple;
        }
    }
);


chrome.storage.local.get(
    { showFullDetails: false },
    (stored) => {

        showDetails = Boolean(stored.showFullDetails);

        detailToggle.checked = showDetails;
    }
);