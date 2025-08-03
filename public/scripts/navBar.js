const header = document.querySelector("header");
let lastScrollY = window.scrollY;
let scrollingUp = false;

window.addEventListener("scroll", () => {
  let currentScrollY = window.scrollY;

  // Affiche ou cache la navbar au scroll
  if (currentScrollY < lastScrollY) {
    scrollingUp = true;
  } else {
    scrollingUp = false;
  }

  if (scrollingUp) {
    header.style.transform = "translateY(0)";
    header.style.opacity = "1";
  } else {
    header.style.transform = "translateY(-100%)";
    header.style.opacity = "0";
  }

  // Met à jour la position du scroll
  lastScrollY = currentScrollY;
});

const menuToggle = document.getElementById("burgerBtn");
const mobileMenu = document.querySelector(".mobile-menu");
const cellMenu = document.querySelector(".cell-menu");

menuToggle.addEventListener("click", () => {
    mobileMenu.classList.toggle("open");
    cellMenu.classList.toggle("open");
});





// document.getElementById("home").addEventListener("click", function () {
//   let target = document.querySelector(this.getAttribute("data-target"));

//   if (target) {
//     window.scrollTo({
//       top: target.offsetTop,
//       behavior: "smooth",
//     });
//   }
// });


