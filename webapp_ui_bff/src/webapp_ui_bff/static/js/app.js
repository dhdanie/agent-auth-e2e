function login() {
    window.location.href = '/login';
}

function logout() {
    window.location.href = '/logout';
}

async function fetchUserInfo() {
    const responseArea = document.getElementById('apiResponse');
    responseArea.textContent = 'Fetching user info...';
    try {
        const response = await fetch('/api/bff/userinfo');
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`HTTP error! status: ${response.status}, message: ${errorText}`);
        }
        const data = await response.json();
        responseArea.textContent = JSON.stringify(data, null, 2);
    } catch (error) {
        console.error('Error fetching user info:', error);
        responseArea.textContent = `Error fetching user info: ${error.message}`;
    }
}

async function callInvokeWeather() {
    const responseArea = document.getElementById('apiResponse');
    responseArea.textContent = `Calling agent...`;
    try {
        const response = await fetch('/api/bff/invoke-weather', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({city: 'Redmond'}) // Hardcoded city
        });

        const responseText = await response.text();
        let data;
        try {
            data = JSON.parse(responseText);
        } catch (e) {
            data = null;
        }

        // Handle paused/consent_required response
        if (data && data.status === 'paused' && data.reason === 'consent_required') {
            showConsentPrompt(data.consent_url, data.invocation_id);
            responseArea.textContent = 'Action paused: User consent required. Please grant consent to continue.';
            return;
        }

        if (!response.ok) {
            let detail = responseText;
            try {
                const errorJson = JSON.parse(responseText);
                detail = errorJson.detail || responseText;
            } catch (e) {}
            throw new Error(`HTTP error! status: ${response.status}, message: ${detail}`);
        }

        responseArea.textContent = JSON.stringify(data, null, 2);
    } catch (error) {
        console.error('Error calling invoke weather:', error);
        responseArea.textContent = `Error: ${error.message}`;
    }
}

function showConsentPrompt(consentUrl, invocationId) {
    let consentDiv = document.getElementById('consentPrompt');
    if (!consentDiv) {
        consentDiv = document.createElement('div');
        consentDiv.id = 'consentPrompt';
        consentDiv.style.margin = '1em 0';
        document.getElementById('responseArea').appendChild(consentDiv);
    }
    consentDiv.innerHTML = `
        <p><strong>Additional consent is required to continue.</strong></p>
        <a href="${consentUrl}" target="_blank" id="consentLink">Grant Consent</a>
        <button id="resumeButton" style="margin-left:1em;display:none;">Resume</button>
        <input type="hidden" id="pausedInvocationId" value="${invocationId}">
        <p id="consentInstructions">After granting consent, return here and click Resume.</p>
    `;
    // Show Resume button after user clicks consent link
    document.getElementById('consentLink').addEventListener('click', function() {
        setTimeout(() => {
            document.getElementById('resumeButton').style.display = '';
        }, 2000);
    });
    document.getElementById('resumeButton').addEventListener('click', resumePausedInvocation);
}

async function resumePausedInvocation() {
    const invocationId = document.getElementById('pausedInvocationId').value;
    const responseArea = document.getElementById('apiResponse');
    responseArea.textContent = 'Resuming agent invocation...';
    try {
        const response = await fetch('/api/bff/resume-invocation', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({invocation_id: invocationId})
        });
        const data = await response.json();
        responseArea.textContent = JSON.stringify(data, null, 2);
        // Remove consent prompt after resuming
        const consentDiv = document.getElementById('consentPrompt');
        if (consentDiv) consentDiv.remove();
    } catch (error) {
        responseArea.textContent = `Error resuming invocation: ${error.message}`;
    }
}
