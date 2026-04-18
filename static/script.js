// ================= INITIAL PAGE LOAD =================
window.addEventListener("load", () => {
    const loader = document.getElementById("loader");
    if (loader) loader.style.display = "none";

    const theme = localStorage.getItem("theme");
    if (theme === "light") {
        document.body.classList.add("light");
    }
});

// ================= MENU =================
function toggleMenu() {
    const menu = document.getElementById("menu");
    if (!menu) return;

    menu.style.display =
        menu.style.display === "block" ? "none" : "block";
}

// ================= THEME =================
function toggleTheme() {
    document.body.classList.toggle("light");

    localStorage.setItem(
        "theme",
        document.body.classList.contains("light") ? "light" : "dark"
    );
}

// ================= NAVIGATION =================
function goBack() {
    window.location.href = "/";
}

function navigate(path) {
    const loader = document.getElementById("loader");
    if (loader) loader.style.display = "flex";

    setTimeout(() => {
        window.location.href = path;
    }, 400);
}