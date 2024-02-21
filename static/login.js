function getValueFromElementById(id) {
    const element = document.getElementById(id);
    if (!element) {
        console.error(`Element ${id} does not exist`);
        return
    }

    return element.value;
}

async function handleOnSubmit(event) {
    event.preventDefault();

    const bsn = getValueFromElementById("uzi_id");
    const state = getValueFromElementById("state");

    try {
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
    } catch (error) {
        console.error(error.message);
    }
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
