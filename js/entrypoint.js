import { importLibrary, setOptions } from "@googlemaps/js-api-loader";

const localStorageRequiredMessage = "Local storage is required to use this app. Please make sure it's enabled in your browser, then reload the page.";

let localData = null;

try {
    localData = localStorage.getItem("formFields");
} catch (error) {
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

app.ports.saveToLocalStorage.subscribe(function (message) {
    try {
        localStorage.setItem("formFields", message);
    } catch (error) {
        alert(localStorageRequiredMessage);
        return;
    }

    app.ports.localStorageSaved.send(true);
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
    });
});

app.ports.initializeOneTap.subscribe(function () {
    const script = document.createElement("script");
    script.async = true;
    script.src = "https://accounts.google.com/gsi/client";

    document.head.appendChild(script);
});
