const app = Elm.Main.init(
    {
        flags: {
            serverData: window.serverData,
            localData: localStorage.getItem("formFields"),
        }
    }
);

app.ports.saveToLocalStorage.subscribe(function (message) {
    localStorage.setItem("formFields", message);
    app.ports.localStorageSaved.send(true);
});

app.ports.initializeAutocomplete.subscribe(function (message) {
    script = document.createElement('script');
    script.type = 'text/javascript';
    script.async = true;
    script.src = "https://maps.googleapis.com/maps/api/js?&libraries=places&callback=initializeAutocomplete&loading=async&language=en&region=US&key=" + message;

    document.getElementsByTagName("head").item(0).appendChild(script);
});

app.ports.initializeOneTap.subscribe(function (message) {
    script = document.createElement('script');
    script.type = 'text/javascript';
    script.async = true;
    script.src = "https://accounts.google.com/gsi/client";

    document.getElementsByTagName("head").item(0).appendChild(script);
})
