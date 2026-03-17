document.getElementById("checkBtn").addEventListener("click", async () => {

    const resultText = document.getElementById("result");
    const reasonsList = document.getElementById("reasons");

    resultText.innerText = "Checking...";
    reasonsList.innerHTML = "";

    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    let url = tab.url;

    try {
        let response = await fetch("http://127.0.0.1:8000/analyse", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url })
        });

        let data = await response.json();

        // Display result
        resultText.innerText = data.prediction.toUpperCase();
        resultText.className = data.prediction;

        // Display reasons
        data.reasons.forEach(reason => {
            let li = document.createElement("li");
            li.innerText = reason;
            reasonsList.appendChild(li);
        });

    } catch (error) {
        resultText.innerText = "Error connecting to backend";
    }
});