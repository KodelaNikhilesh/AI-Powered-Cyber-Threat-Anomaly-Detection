// ================= CYBER LOADER =================
window.addEventListener("load", () => {
    const loader = document.getElementById("cyber-loader");
    if (loader) {
        setTimeout(() => loader.classList.add("hidden"), 800);
    }
});

// Fix back/forward cache issue
window.addEventListener("pageshow", function (event) {
    const loader = document.getElementById("cyber-loader");
    if (event.persisted && loader) {
        loader.classList.add("hidden");
    }
});

// Show loader when navigating
document.addEventListener("click", e => {
    const link = e.target.closest("a");
    if (!link) return;

    if (link.target === "_blank") return;
    if (link.href.startsWith("javascript")) return;

    const loader = document.getElementById("cyber-loader");
    if (loader) loader.classList.remove("hidden");
});


// ================= THREAT METER INIT =================
function initThreatMeter() {
    const meter = document.getElementById("meterFill");
    const status = document.getElementById("threatStatus");
    const scoreElement = document.querySelector(".score-number");

    if (!meter || !status || !scoreElement) return;

    const score = parseInt(scoreElement.innerText) || 0;

    setTimeout(() => {
        meter.style.width = score + "%";
    }, 200);

    if (score < 30) {
        meter.style.background = "#22c55e";
        status.innerText = "LOW RISK – System Stable";
    }
    else if (score < 60) {
        meter.style.background = "#f59e0b";
        status.innerText = "MEDIUM RISK – Elevated Activity";
    }
    else if (score < 80) {
        meter.style.background = "#f97316";
        status.innerText = "HIGH RISK – Suspicious Activity";
    }
    else {
        meter.style.background = "#ef4444";
        status.innerText = "CRITICAL – Immediate Action Required";
    }
}

window.addEventListener("DOMContentLoaded", initThreatMeter);