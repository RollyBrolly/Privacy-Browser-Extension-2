
console.log("Privacy Risk Detector service worker started!");

const MAX_RECORDS = 300;


// ===========================================================================
// Registrable-domain (eTLD+1) helpers
// ===========================================================================
// Public Suffix List aware comparison. The full list contains ~10,000
// entries and is updated over time; this curated subset covers the most
// common multi-label public suffixes (country-code second-level
// namespaces such as "co.uk" or "com.ph", plus a few well-known
// private-section entries such as "github.io"). Hostnames whose suffix
// is not listed fall back to the standard PSL default rule: the public
// suffix is the last label and the registrable domain is the last two.
// This avoids naive "last two labels" comparisons that would treat
// "shop.example.co.uk" and "cdn.example.com" as the same site, or
// "alice.github.io" and "bob.github.io" as one site.

const MULTI_PART_PUBLIC_SUFFIXES = new Set([
  // United Kingdom
  "co.uk", "org.uk", "me.uk", "net.uk", "ac.uk", "gov.uk", "ltd.uk",
  "plc.uk", "sch.uk",
  // Australia
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
  // New Zealand
  "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz",
  // Japan
  "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "ad.jp", "lg.jp",
  // South Korea
  "co.kr", "or.kr", "ne.kr", "re.kr", "pe.kr", "go.kr", "ac.kr",
  // China
  "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
  // Taiwan
  "com.tw", "org.tw", "net.tw", "edu.tw", "gov.tw", "idv.tw",
  // Hong Kong
  "com.hk", "org.hk", "net.hk", "edu.hk", "gov.hk", "idv.hk",
  // Philippines
  "com.ph", "org.ph", "net.ph", "edu.ph", "gov.ph", "ngo.ph",
  // Singapore
  "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg", "per.sg",
  // Malaysia
  "com.my", "net.my", "org.my", "edu.my", "gov.my",
  // India
  "co.in", "firm.in", "net.in", "org.in", "gen.in", "ind.in", "ac.in",
  "edu.in", "gov.in",
  // South America
  "com.br", "net.br", "org.br", "gov.br", "edu.br", "art.br",
  "com.mx", "net.mx", "org.mx", "edu.mx", "gob.mx",
  "com.ar", "net.ar", "org.ar", "gob.ar", "edu.ar",
  "com.co", "net.co", "org.co", "edu.co", "gov.co",
  "com.pe", "net.pe", "org.pe", "edu.pe", "gob.pe",
  "com.ve", "net.ve", "org.ve", "edu.ve", "gob.ve",
  // Africa
  "com.ng", "net.ng", "org.ng", "edu.ng", "gov.ng",
  "co.za", "org.za", "net.za", "web.za", "gov.za", "ac.za",
  // Middle East
  "co.il", "org.il", "net.il", "ac.il", "gov.il", "muni.il",
  "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa",
  "com.tr", "net.tr", "org.tr", "edu.tr", "gov.tr", "web.tr",
  "com.eg", "net.eg", "org.eg", "edu.eg", "gov.eg",
  // Europe (non-.uk)
  "co.at", "or.at", "ac.at", "gv.at", "priv.at",
  "com.de", "com.es", "com.pt", "com.pl", "com.gr", "com.ru"
]);


// PSL private-section entries: separate sites hosted under these
// suffixes (for example "alice.github.io" vs "bob.github.io") belong
// to different parties, so each subdomain is its own registrable
// domain here.
const PRIVATE_SECTION_SUFFIXES = new Set([
  "github.io", "gitlab.io", "blogspot.com", "appspot.com",
  "azurewebsites.net", "herokuapp.com", "vercel.app", "netlify.app",
  "pages.dev", "workers.dev", "web.app", "firebaseapp.com",
  "cloudfront.net", "s3.amazonaws.com"
]);


const IPV4_PATTERN = /^\d{1,3}(\.\d{1,3}){3}$/;


function normalizeHostname(hostname) {

  return String(hostname || "")
    .trim()
    .toLowerCase()
    .replace(/\.$/, "");
}


function isIpAddress(hostname) {

  // IPv4 or IPv6 (IPv6 literals contain colons).
  return IPV4_PATTERN.test(hostname) || hostname.includes(":");
}


function getRegistrableDomain(hostname) {

  const normalized = normalizeHostname(hostname);

  if (!normalized) {
    return "";
  }

  // IP addresses and single-label hosts (localhost) are their own
  // "registrable domain".
  if (isIpAddress(normalized) || !normalized.includes(".")) {
    return normalized;
  }

  const labels = normalized.split(".");

  if (labels.length <= 2) {
    return normalized;
  }

  // Longest-match first: try a 3-label public suffix, then 2 labels.
  for (let suffixLength = 3; suffixLength >= 2; suffixLength--) {

    const candidate = labels.slice(-suffixLength).join(".");

    if (
      MULTI_PART_PUBLIC_SUFFIXES.has(candidate) ||
      PRIVATE_SECTION_SUFFIXES.has(candidate)
    ) {

      const registrableLabels = labels.slice(-(suffixLength + 1));

      // The hostname itself is only a public suffix (e.g. "co.uk").
      if (registrableLabels.length <= 1) {
        return normalized;
      }

      return registrableLabels.join(".");
    }
  }

  // Default PSL rule: public suffix is the final label, so the
  // registrable domain is the last two labels.
  return labels.slice(-2).join(".");
}


function classifyRequest(requestHostname, pageHostname) {

  const requestDomain = getRegistrableDomain(requestHostname);
  const pageDomain = getRegistrableDomain(pageHostname);

  if (!requestDomain || !pageDomain) {

    return {
      requestDomain: requestDomain,
      pageDomain: pageDomain,
      isThirdParty: null,
      classification: "unknown"
    };
  }

  const isThirdParty = requestDomain !== pageDomain;

  return {
    requestDomain: requestDomain,
    pageDomain: pageDomain,
    isThirdParty: isThirdParty,
    classification: isThirdParty ? "third-party" : "first-party"
  };
}


// Monitor network requests made by browser tabs.
chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    // Ignore requests that are not associated with a tab.
    if (details.tabId < 0) return;

    console.log(
  "Request detected:",
  details.method,
  details.url,
  "Tab ID:",
  details.tabId
);

    try {
      const requestUrl = new URL(details.url);

      // Only process normal web requests.
      if (!["http:", "https:"].includes(requestUrl.protocol)) {
        return;
      }

      const initiatorUrl = details.initiator
        ? new URL(details.initiator)
        : null;

      // Determine the page (initiator) host. Fall back to the tab's
      // current URL when the initiator is unknown (e.g. some
      // navigations).
      let pageHostname = initiatorUrl?.hostname ?? "";

      if (!pageHostname && details.tabId >= 0) {
        try {
          const tab = await chrome.tabs.get(details.tabId);
          pageHostname = new URL(tab.url ?? "").hostname ?? "";
        } catch {
          // Tab may already be closed; leave pageHostname empty.
        }
      }

      // First-party vs third-party using registrable domains
      // (Public Suffix List aware), not naive last-two-label matching.
      const classification = classifyRequest(
        requestUrl.hostname,
        pageHostname
      );

      // Store metadata only, not request bodies or form values.
      const record = {
        id: `${details.requestId}-${details.timeStamp}`,
        time: details.timeStamp,
        tabId: details.tabId,
        requestDomain: requestUrl.hostname,
        initiatorDomain: initiatorUrl?.hostname ?? "unknown",
        resourceType: details.type,
        method: details.method,
        requestRegistrableDomain: classification.requestDomain,
        pageRegistrableDomain: classification.pageDomain,
        // "first-party", "third-party", or "unknown".
        partyClassification: classification.classification
      };

      // Keep a limited, temporary list of requests.
      const { networkRecords = [] } =
        await chrome.storage.session.get("networkRecords");

      const updatedRecords = [
        record,
        ...networkRecords
      ].slice(0, MAX_RECORDS);

      await chrome.storage.session.set({
        networkRecords: updatedRecords
      });

    } catch (error) {
      console.error("Could not record network request:", error);
    }
  },
  {
    urls: ["http://*/*", "https://*/*"]
  }
);

// Allow the popup to clear the recorded requests.
chrome.runtime.onMessage.addListener(
  (message, sender, sendResponse) => {
    if (message?.type === "CLEAR_NETWORK_RECORDS") {
      chrome.storage.session.set({
        networkRecords: []
      })
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false }));

      return true;
    }
  }
);
