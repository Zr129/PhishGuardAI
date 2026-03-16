document.getElementById("scanBtn").addEventListener("click", async () => {

    let [tab] = await chrome.tabs.query({active: true, currentWindow: true})

    let url = tab.url

    fetch("http://localhost:8000/analyse", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({url: url})
    })
    .then(res => res.json())
    .then(data => {

        document.getElementById("result").innerHTML =
        `
        Classification: ${data.classification}<br>
        Score: ${data.score}<br>
        Reasons: ${data.reasons.join(", ")}
        `
    })

})