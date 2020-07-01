const idleCheckPlugin = {
    id: '@adyne/general:idle-check',
    activate: activateIdleCheck,
    autoStart: true
};
function activateIdleCheck(app) {
    console.log(`JupyterLab extension autologout is activated`);
    var timeout = 300 * 1000; // 5 min
    var timeoutId = 0;
    var lastTrigger = 0;
    function startTimer() {
        timeoutId = window.setTimeout(doInactive, timeout);
    }
    function resetTimer() {
        // timer reset every 10 sec on event trigger
        if (Date.now() - lastTrigger > 10000) {
            console.log(`logout timer reset`);
            lastTrigger = Date.now();
            window.clearTimeout(timeoutId);
            startTimer();
        }
    }
    function doInactive() {
        console.log(`auto logout triggered`);
        window.location.href = "/hub/logout/idle";
    }
    function setupTimers() {
        document.addEventListener("mousemove", resetTimer);
        document.addEventListener("mousedown", resetTimer);
        document.addEventListener("keypress", resetTimer);
        document.addEventListener("touchmove", resetTimer);
        startTimer();
    }
    setupTimers();
}
const plugins = [idleCheckPlugin];
export default plugins;
//# sourceMappingURL=index.js.map