const localStorageRequiredMessage = "Local storage is required to use this app. Please make sure it is enabled in your browser, then reload the page.";

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
    "use strict";

    try {
        localStorage.setItem("formFields", message);
    } catch (error) {
        alert(localStorageRequiredMessage);
        return;
    }

    app.ports.localStorageSaved.send(true);
});

app.ports.showAlert.subscribe(function (message) {
    "use strict";

    alert(message);
});

app.ports.initializeAutocomplete.subscribe(function (message) {
    "use strict";

    const script = document.createElement('script');
    script.type = 'text/javascript';
    script.async = true;
    script.src = "https://maps.googleapis.com/maps/api/js?&libraries=places&callback=initializeAutocomplete&loading=async&language=en&region=US&key=" + message;

    document.head.appendChild(script);
});

app.ports.initializeOneTap.subscribe(function (message) {
    "use strict";

    const script = document.createElement('script');
    script.type = 'text/javascript';
    script.async = true;
    script.src = "https://accounts.google.com/gsi/client";

    document.head.appendChild(script);
});
