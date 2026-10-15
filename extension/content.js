function normalizeText(value) {

    return String(value || "")
        .replace(/\s+/g, " ")
        .trim();
}


function getVisibleText(element) {

    return normalizeText(element.textContent || "");
}


function resolveIdReferences(element, attributeName) {

    const raw = element.getAttribute(attributeName);

    if (!raw) {
        return "";
    }

    const parts = [];

    raw.split(/\s+/).forEach((id) => {

        if (!id) {
            return;
        }

        const referenced = document.getElementById(id);

        if (referenced) {

            const text = getVisibleText(referenced);

            if (text) {
                parts.push(text);
            }
        }
    });

    return parts.join(" ");
}


function getLabelForInput(input) {
    const id = input.id;

    if (id) {
        const label = document.querySelector(`label[for="${CSS.escape(id)}"]`);

        if (label) {
            return getVisibleText(label);
        }
    }

    const parentLabel = input.closest("label");

    if (parentLabel) {
        return getVisibleText(parentLabel);
    }

    return "";
}


function getAccessibleLabel(input) {

    const ariaLabel = normalizeText(input.getAttribute("aria-label"));

    if (ariaLabel) {
        return ariaLabel;
    }

    const labelledByText = resolveIdReferences(input, "aria-labelledby");

    if (labelledByText) {
        return labelledByText;
    }

    const title = normalizeText(input.getAttribute("title"));

    if (title) {
        return title;
    }

    return normalizeText(input.getAttribute("alt"));
}


function getFieldContainer(input) {

    return (
        input.closest(
            ".form-group, .form-field, .field, .form-row, .input-group, [data-field]"
        ) || input.parentElement
    );
}


function getInstructions(input) {

    const parts = [];

    const describedByText = resolveIdReferences(input, "aria-describedby");

    if (describedByText) {
        parts.push(describedByText);
    }

    const description = normalizeText(
        input.getAttribute("aria-description")
    );

    if (description) {
        parts.push(description);
    }

    const container = getFieldContainer(input);

    if (container) {

        container.querySelectorAll(
            ".help-text, .helper-text, .hint, .field-hint, .description, .form-text, .instructions"
        ).forEach((element) => {

            if (element === input || element.contains(input)) {
                return;
            }

            const text = getVisibleText(element);

            if (text) {
                parts.push(text);
            }
        });
    }

    return Array.from(new Set(parts)).join(" ");
}


function getNearestHeading(element) {

    let node = element;

    while (node && node !== document.body) {

        let sibling = node.previousElementSibling;

        while (sibling) {

            if (/^H[1-6]$/.test(sibling.tagName)) {

                const text = getVisibleText(sibling);

                if (text) {
                    return text;
                }
            }

            sibling = sibling.previousElementSibling;
        }

        node = node.parentElement;
    }

    return "";
}


function getFormPurpose(form) {

    const ariaLabel = normalizeText(form.getAttribute("aria-label"));

    if (ariaLabel) {
        return ariaLabel;
    }

    const labelledByText = resolveIdReferences(form, "aria-labelledby");

    if (labelledByText) {
        return labelledByText;
    }

    const legend = form.querySelector("legend");

    if (legend) {

        const legendText = getVisibleText(legend);

        if (legendText) {
            return legendText;
        }
    }

    const headingText = getNearestHeading(form);

    if (headingText) {
        return headingText;
    }

    return normalizeText(form.getAttribute("name"));
}


function isCrossOriginAction(rawAction) {

    if (!rawAction) {
        return false;
    }

    try {

        const actionUrl = new URL(rawAction, window.location.href);

        return actionUrl.hostname !== window.location.hostname;

    } catch (error) {

        return false;
    }
}


function isIgnorableField(input) {

    const type = (input.type || "").toLowerCase();

    return [
        "hidden",
        "submit",
        "button",
        "reset",
        "image"
    ].includes(type);
}


function collectFieldMetadata(input) {

    return {
        type: input.type || input.tagName.toLowerCase(),
        name: input.name || "",
        id: input.id || "",
        placeholder: input.placeholder || "",
        label: getLabelForInput(input),
        accessibleLabel: getAccessibleLabel(input),
        instructions: getInstructions(input),
        autocomplete: input.autocomplete || "",
        inputMode: input.getAttribute("inputmode") || "",
        required: Boolean(
            input.required ||
            input.getAttribute("required") !== null
        )
    };
}


function getFormData() {

    const forms = [];

    document.querySelectorAll("form").forEach((form, formIndex) => {

        const fields = [];

        form.querySelectorAll(
            "input, textarea, select"
        ).forEach((input) => {

            if (isIgnorableField(input)) {
                return;
            }

            fields.push(collectFieldMetadata(input));
        });

        forms.push({
            index: formIndex + 1,
            method: form.method || "GET",
            action: form.action || "",
            purpose: getFormPurpose(form),
            crossOriginAction: isCrossOriginAction(
                form.getAttribute("action")
            ),
            fields: fields
        });
    });

    // Fields handled by page scripts outside any <form> element.
    const standaloneFields = Array.from(
        document.querySelectorAll("input, textarea, select")
    ).filter((input) => !input.closest("form") && !isIgnorableField(input));

    if (standaloneFields.length > 0) {

        forms.push({
            index: forms.length + 1,
            method: "POST",
            action: "",
            purpose: "Fields outside any form element (handled by page scripts)",
            crossOriginAction: false,
            standalone: true,
            fields: standaloneFields.map(collectFieldMetadata)
        });
    }

    return forms;
}


function getExternalResources() {

    const currentHost = window.location.hostname;

    const resources = [];

    document.querySelectorAll("script[src], iframe[src], img[src], link[href]").forEach((element) => {

        const url =
            element.src ||
            element.href ||
            "";

        if (!url) {
            return;
        }

        try {

            const resourceUrl = new URL(url);

            if (
                resourceUrl.hostname &&
                resourceUrl.hostname !== currentHost
            ) {
                resources.push({
                    type: element.tagName.toLowerCase(),
                    url: resourceUrl.href,
                    hostname: resourceUrl.hostname
                });
            }

        } catch (error) {
            // Ignore invalid URLs
        }
    });

    return resources.slice(0, 100);
}


function getPageData() {

    const bodyText = document.body
        ? document.body.innerText
        : "";

    return {
        url: window.location.href,
        title: document.title || "",
        text: bodyText.slice(0, 50000),
        forms: getFormData(),
        externalResources: getExternalResources()
    };
}


chrome.runtime.onMessage.addListener(
    (request, sender, sendResponse) => {

        if (request.action === "analyzePage") {

            try {

                const pageData = getPageData();

                sendResponse({
                    success: true,
                    data: pageData
                });

            } catch (error) {

                sendResponse({
                    success: false,
                    error: error.message
                });
            }

            return true;
        }
    }
);