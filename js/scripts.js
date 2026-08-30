document.querySelectorAll("#oauth [required]").forEach(e => e.dataset.wasRequired = "1");

let pageOauth = document.querySelector('.page_oauth');
let returnTo = document.querySelector('.page_oauth #returnTo');
if (pageOauth !== undefined && pageOauth != null) {
	if (returnTo && returnTo.value === 'register') {
		showRegisterForm();
	} else if (returnTo && returnTo.value === 'connect') {
		showLoginForm();
	}
	document.querySelector('.page_oauth #showRegisterForm').addEventListener('click', showRegisterForm);
	document.querySelector('.page_oauth #showLoginForm').addEventListener('click', showLoginForm);
	document.querySelector('form[id="oauth"]').addEventListener('keydown', function(e) {
		if (e.keyIdentifier === 'U+000A' || e.keyIdentifier === 'Enter' || e.code === 'Enter') {
			e.preventDefault();
			if (e.target.nodeName === 'BUTTON' && e.target.type === 'submit') {
				e.target.click();
				return false;
			}
		}
	}, true);

}

function applyRequired(panelId, active) {
	document.querySelectorAll("#oauth #" + panelId + " input, #oauth #" + panelId + " select")
		.forEach(e => e.required = active && e.dataset.wasRequired === "1");
}

function showRegisterForm() {
	document.querySelector("#oauth #register-form").style.display = "block";
	document.querySelector("#oauth #login-form").style.display = "none";
	applyRequired("register-form", true);
	applyRequired("login-form", false);
}

function showLoginForm() {
	document.querySelector("#oauth #register-form").style.display = "none";
	document.querySelector("#oauth #login-form").style.display = "block";
	applyRequired("register-form", false);
	applyRequired("login-form", true);
}

