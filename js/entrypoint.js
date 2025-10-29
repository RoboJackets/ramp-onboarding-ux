const app = Elm.Main.init(
    {
        flags: {
            serverData: window.serverData,
            localData: localStorage.getItem("formFields"),
        }
    }
);

app.ports.saveToLocalStorage.subscribe(function (message) {
    "use strict";

    localStorage.setItem("formFields", message);
    app.ports.localStorageSaved.send(true);
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
