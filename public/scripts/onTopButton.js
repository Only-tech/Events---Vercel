window.addEventListener("scroll", function() {
    let scrollTopBtn = document.getElementById("scrollTopBtn");

    if (window.scrollY > 500) {
        scrollTopBtn.style.display = "flex";
    } else {
        scrollTopBtn.style.display = "none";
    }
});

document.getElementById("scrollTopBtn").addEventListener("click", function() {
    window.scrollTo({ top: 0, behavior: "smooth" });
});
