import * as Sentry from "@sentry/browser";
import { importLibrary, setOptions } from "@googlemaps/js-api-loader";

const localStorageRequiredMessage = "Local storage is required to use this app. Please make sure it's enabled in your browser, then reload the page.";

const sentryConfig = window.sentryConfig || {};
const sentryEnabled = Boolean(sentryConfig.dsn);

if (sentryEnabled) {
    Sentry.init({
        ...sentryConfig,
        integrations: [
            Sentry.browserTracingIntegration(),
            Sentry.browserProfilingIntegration(),
            Sentry.httpClientIntegration(),
        ],
    });

    const serverData = window.serverData;
    if (serverData && (serverData.selfApiaryId != null || serverData.emailAddress)) {
        Sentry.setUser({
            id: serverData.selfApiaryId != null ? String(serverData.selfApiaryId) : undefined,
            email: serverData.emailAddress || undefined,
        });
    }
}

function reportJsError(error, tags, level) {
    if (!sentryEnabled) {
        return;
    }

    Sentry.withScope(function (scope) {
        scope.setTag("runtime", "browser");
        scope.setLevel(level || "error");
        if (tags) {
            Object.keys(tags).forEach(function (key) {
                scope.setTag(key, tags[key]);
            });
        }
        Sentry.captureException(error);
    });
}

function reportJsMessage(message, tags, level) {
    if (!sentryEnabled) {
        return;
    }

    Sentry.withScope(function (scope) {
        scope.setTag("runtime", "browser");
        if (tags) {
            Object.keys(tags).forEach(function (key) {
                scope.setTag(key, tags[key]);
            });
        }
        Sentry.captureMessage(message, level || "warning");
    });
}

let localData = null;

try {
    localData = localStorage.getItem("formFields");
} catch (error) {
    reportJsError(error, { step: "localStorage_read" }, "error");
    alert(localStorageRequiredMessage);
}

const app = Elm.Main.init(
    {
        flags: {
            serverData: window.serverData,
            localData: localData,
        }
    }
);

app.ports.reportError.subscribe(function (payload) {
    if (!sentryEnabled) {
        return;
    }

    Sentry.withScope(function (scope) {
        scope.setTag("runtime", "browser");
        if (payload.tags) {
            Object.keys(payload.tags).forEach(function (key) {
                scope.setTag(key, payload.tags[key]);
            });
        }
        Sentry.captureMessage(payload.message, payload.level || "error");
    });
});

app.ports.saveToLocalStorage.subscribe(function (message) {
    try {
        localStorage.setItem("formFields", message);
    } catch (error) {
        reportJsError(error, { step: "localStorage_write" }, "error");
        alert(localStorageRequiredMessage);
        return;
    }

    app.ports.localStorageSaved.send(null);
});

app.ports.showAlert.subscribe(function (message) {
    alert(message);
});

function attachAutocomplete(places, fieldId) {
    const input = document.getElementById(fieldId);

    if (input === null) {
        window.requestAnimationFrame(function () {
            attachAutocomplete(places, fieldId);
        });
        return;
    }

    const autocomplete = new places.Autocomplete(input, {
        componentRestrictions: { country: ["us"] },
        fields: ["address_components"],
        types: ["address"],
    });

    autocomplete.addListener("place_changed", function () {
        app.ports.placeChanged.send(autocomplete.getPlace());
    });
}

app.ports.initializeAutocomplete.subscribe(function (message) {
    setOptions({
        key: message.apiKey,
        v: "weekly",
        language: "en",
        region: "US",
    });

    importLibrary("places").then(function (places) {
        attachAutocomplete(places, message.fieldId);
    }).catch(function (error) {
        reportJsError(error, { step: "places_import" }, "warning");
    });
});

app.ports.initializeOneTap.subscribe(function () {
    const script = document.createElement("script");
    script.async = true;
    script.src = "https://accounts.google.com/gsi/client";
    script.onerror = function () {
        reportJsMessage("Failed to load Google Identity Services client", { step: "gsi_script_load" }, "warning");
    };

    document.head.appendChild(script);
});
