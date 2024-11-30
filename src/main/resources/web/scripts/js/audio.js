function checkForUpdate() {
    fetch('/version/{BROADCAST_ID}')
        .then(response => response.text())
        .then(version => {
            if (localStorage.getItem('audioVersion') !== version) {
                localStorage.setItem('audioVersion', version);
                window.location.reload();
            }
        });
}
function updateLoop() {
    setInterval(checkForUpdate, 1000);
}
window.onload = updateLoop;