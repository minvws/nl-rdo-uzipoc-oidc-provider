(function(){
    addEventListener("submit", (event) => {
        try{
            let body = {}
            for (let i = 0; i < event.target.elements.length; i++) {
                if (event.target.elements[i].name !== "submit"){
                    body[event.target.elements[i].name] = event.target.elements[i].value
                }
            }
            let response = fetch("/submit", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(body)
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
