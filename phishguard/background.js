chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

    if (message.type === "URL_CAPTURE") {

        fetch("http://localhost:8000/analyse", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                url: message.url
            })
        })
        .then(res => res.json())
        .then(data => {

            console.log("Analysis result:", data)

        })

    }

});