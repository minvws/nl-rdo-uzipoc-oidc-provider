function getValueFromElementById(id) {
    const element = document.getElementById(id);
    if (!element) {
        console.error(`Element ${id} does not exist`);
        return
    }

    return element.value;
}


async function handleUserInfoToken(event) {
    event.preventDefault();

    const bsn = getValueFromElementById("bsn-number");
    const userinfoValidityInSeconds = getValueFromElementById("token-expiry");

    const params = userinfoValidityInSeconds ? {
        "bsn": bsn,
        "userinfo_validity_in_seconds" : userinfoValidityInSeconds
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

    const tokenInput = document.getElementById("token-input");
    tokenInput.value = userinfoToken["signed_userinfo"];

    const loginButton = document.getElementById("login-button");
    if (loginButton.disabled) {
        loginButton.disabled = false;
    }

}

async function handleLogin (event) {
    event.preventDefault();

    const userinfoToken = getValueFromElementById("token-input");
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

    const bsn = getValueFromElementById("bsn-number");
    const state = getValueFromElementById("state");

    try {
        const response = await fetch("/submit", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                "bsn": bsn,
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

function handleDisableLoginButton (event) {
    event.preventDefault();
    const loginButton = document.getElementById("login-button");
    const inputTokenValue = getValueFromElementById("token-input");

    if (inputTokenValue.length > 0) {
        loginButton.disabled = false;
    } else {
    loginButton.disabled = true;
    }
}

window.addEventListener("DOMContentLoaded", () => {
    const loginMethodTag = document.getElementById("identities") ?? document.getElementById("zsm");
    if (loginMethodTag.id == "zsm") {
        const inputToken = document.getElementById("token-input");
        const loginButton = document.getElementById("login-button");
        loginButton.disabled = true;
        inputToken.addEventListener("input", handleDisableLoginButton);

        const tokenForm = document.getElementById("token-form");
        const loginForm = document.getElementById("login-form");

        tokenForm.addEventListener("submit", handleUserInfoToken);
        loginForm.addEventListener("submit", handleLogin);

    } else {
        const forms = document.getElementsByTagName("form");
        for (let i = 0; i < forms.length; i++) {
            forms[i].addEventListener("submit", handleIdentitiesOnSubmit);
        }
    }
})
