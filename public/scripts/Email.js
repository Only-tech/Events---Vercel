// emailjs.init("mSiePQQEQ-83LNBaf"); //clé publique

// const form = document.getElementById("contact-form");
// const status = document.getElementById("form-status");
// const spinner = document.getElementById("loading-spinner");

// form.addEventListener("submit", function(e) {
//     e.preventDefault();
//     spinner.style.display = "flex";
//     status.textContent = "";

//     emailjs.sendForm("service_r7k5fdk", "template_1qncn8e", this)
//     .then(() => {
//         spinner.style.display = "none";
//         status.textContent = "Message envoyé avec succès";
//         status.style.color = "#065F46";
//         status.style.background = "#DCFCE7";
//         form.reset();
//     }, (error) => {
//         spinner.style.display = "none";
//         status.textContent = "Erreur : " + error.text;
//         status.style.color = "#FEE2E2";
//         status.style.background = "#991B1B";
//     });
// });