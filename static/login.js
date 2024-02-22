function getValueFromElementById(id) {
    const element = document.getElementById(id);
    if (!element) {
        console.error(`Element ${id} does not exist`);
        return
    }

    return element.value;
}


async function habdleUserInfoToken(event) {
    event.preventDefault();

    const bsn = getValueFromElementById("bsn_number");
    const tokenValidityInSeconds = getValueFromElementById("token_expiry");

    const params = tokenValidityInSeconds ? {
        "bsn": bsn,
        "token_expiry_in_seconds" : tokenValidityInSeconds
    } : {"bsn": bsn};

    const searchParmas = new URLSearchParams(params);
    const url = `/signed-userinfo?${searchParmas.toString()}`
    const response = await fetch (url, {
        method: "GET",
        headers: {
            "Content-Type": "application/json"
        },
    });
    const userinfoToken = await response.json();

    // Remove input from Dom
    const tokenInputSection = document.getElementById("token_input_section");
    tokenInputSection.remove();

    // create new elements
    const tokenInputDiv = document.createElement("div");
    tokenInputDiv.setAttribute("class", "txt_field")

    const inputToken = document.createElement("input");
    inputToken.setAttribute("id", "userinfo_token");
    inputToken.setAttribute("type", "text");
    inputToken.setAttribute("value", userinfoToken["signed_userinfo"]);

    const inputTokenLabel = document.createElement("label");
    inputTokenLabel.setAttribute("for", "userinfo_token");
    inputTokenLabel.innerHTML = "Signed Token"

    const span = document.createElement("span");

    // start injecting new elements to the DOM
    tokenInputDiv.appendChild(inputToken);
    tokenInputDiv.appendChild(span);
    tokenInputDiv.appendChild(inputTokenLabel);

     // change button text
    const submitButton = document.getElementById("submit_button");
    submitButton.value = "Login";


    const form = document.getElementById("form");
    form.removeChild(submitButton);
    form.appendChild(tokenInputDiv);
    form.appendChild(submitButton);

    form.removeEventListener("submit", habdleUserInfoToken)
    form.addEventListener("submit", handleLogin)
}


async function handleLogin (event) {
    const userinfoToken = getValueFromElementById("userinfo_token");
    const state = getValueFromElementById("state");

    const body = {
        "signed_userinfo": userinfoToken,
        "state": state,
        "login_hint": "zsm"
    };
    try {
            const response = await fetch("/submit", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(body)
        });

        if (response.status !== 200) {
            console.log("Error: " + response.statusText);
            return
        }

        const data = await response.json();
        window.location.href = data["redirect_url"];
    } catch (error) {
        console.error(error.message)
    }

}

async function handleIdentitiesOnSubmit(event) {
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
                "login_hint": "identities"
            }),
        });

        if (response.status !== 200) {
            console.log("Error: " + response.statusText);
            return
        }
        const data = await response.json();

        window.location.href = data["redirect_url"];
    } catch (error) {
        console.error(error.message);
    }
}

window.addEventListener("DOMContentLoaded", () => {
    const loginMethodTag = document.getElementById("identities") ?? document.getElementById("zsm");
    if (loginMethodTag.id == "zsm") {
        const form = document.getElementById("form")
        form.addEventListener("submit", habdleUserInfoToken);
    } else {
        const forms = document.getElementsByTagName("form");
        for (let i = 0; i < forms.length; i++) {
            forms[i].addEventListener("submit", handleIdentitiesOnSubmit);
        }
    }
})
