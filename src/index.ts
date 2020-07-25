import { JupyterFrontEnd, JupyterFrontEndPlugin } from '@jupyterlab/application'; 
import { URLExt } from '@jupyterlab/coreutils';
import { ServerConnection } from '@jupyterlab/services';

const TIMEOUT_PERIOD = 3600 * 1000;  // 60 min

const idleCheckPlugin: JupyterFrontEndPlugin<void> = {
  id: '@adyne/general:idle-check',
  activate: activateIdleCheck,
  autoStart: true
};

function activateIdleCheck(
  app: JupyterFrontEnd
): void {
        console.log(`JupyterLab extension @adyne.autologout is activated`);
        var timeout = TIMEOUT_PERIOD;
        var timeoutId = 0;
        var lastTrigger = 0;
        
        const SETTINGS = ServerConnection.makeSettings();
        
        async function getKernelData() {
            var active = false;
            const url = URLExt.join(SETTINGS.baseUrl, 'api/kernels');
            const response = await ServerConnection.makeRequest(url, {}, SETTINGS);
            if (response.status !== 200) {
                console.log(`Error reading server status: ` + response.status);
                throw new Error('Error reading kernels status');
            }
        
            const data = await response.json();
            if (!Array.isArray(data)) {
                throw new Error('Invalid Kernel List');
            }
            try {
                data.forEach(x => {
                    if (x.execution_state !== 'idle') {
                        active = true;
                    }
                });
            } catch (err) {
                console.log(`Error parsing kernels data: ` + err);
            }
            return active;
        }

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

        async function doInactive() {
            var serverActive = await getKernelData();
            if (!serverActive) {
                window.location.href = "/hub/logout/idle";
            }
            else {
                resetTimer();
            }
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

const plugins: JupyterFrontEndPlugin<any>[] = [idleCheckPlugin];
export default plugins;

