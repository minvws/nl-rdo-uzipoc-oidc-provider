(function(){
    addEventListener("submit", (event) => {
        try{
            let uziId = document.getElementById("uziId").value
            let state = document.getElementById("state").value
            let response = fetch("/submit", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({uzi_id: uziId, state: state})
            })
            response.then(async (response) => {
                if (response.status === 200) {
                    let jsonResponse = await response.json()
                    window.location.href = jsonResponse["redirect_url"]
                } else {
                    console.log("Error: " + response.statusText);
                }
            });
        } finally {
            event.preventDefault();
        }
    });
})();
