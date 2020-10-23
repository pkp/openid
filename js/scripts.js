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
}

function showRegisterForm() {
	document.querySelector("#oauth #register-form").style.display = "block";
	document.querySelector("#oauth #login-form").style.display = "none";
	document.querySelectorAll("#oauth #register-form input:not(#emailConsent)").forEach(e => e.required = true);
	document.querySelectorAll("#oauth #register-form select").forEach(e => e.required = true);
	document.querySelectorAll("#oauth #login-form input").forEach(e => e.required = false);
}

function showLoginForm() {
	document.querySelector("#oauth #register-form").style.display = "none";
	document.querySelector("#oauth #login-form").style.display = "block";
	document.querySelectorAll("#oauth #register-form input").forEach(e => e.required = false);
	document.querySelectorAll("#oauth #register-form select").forEach(e => e.required = false);
	document.querySelectorAll("#oauth #login-form input").forEach(e => e.required = true);
}
