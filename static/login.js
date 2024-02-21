async function handleOnSubmit(event) {
    event.preventDefault();

    const bsn = document.getElementById("uzi_id").value;
    const state = document.getElementById("state").value;

    const response = await fetch("/submit", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            "uzi_id": bsn,
            "state": state,
        }),
    });

    if (response.status !== 200) {
        console.log("Error: " + response.statusText);
        return
    }
    const data = await response.json();
    console.log(`bsn sent ${bsn}`)

    window.location.href = data["redirect_url"];
}

window.addEventListener("DOMContentLoaded", () => {
    const loginMethodTag = document.getElementById("identities") ?? document.getElementById("zsm");
    if (loginMethodTag.id == "zsm") {
        const form = document.getElementById("form")
        form.addEventListener("submit", handleOnSubmit);
    } else {
        const forms = document.getElementsByTagName("form");
        for (let i = 0; i < forms.length; i++) {
            forms[i].addEventListener("submit", handleOnSubmit);
        }
    }
})
