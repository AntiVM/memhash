
let workers = [];
let isRunning = false;
let currentMode = null;
let countdownInterval = null;
let totalProgress = 0;
const TOTAL_TIME = 40; 

const input = '53-6a6628c0bad070cee245b0e8a7861c55b25df96beecde8048f2b83632b61fa5d-1732207722948-010203';
const statsDisplay = document.querySelector('#hashrate');
const resultsDisplay = document.querySelector('#results');
const toggleButton = document.querySelector('#startButton');
const workerCount = navigator.hardwareConcurrency || 4;

const results = {
    sha256: 0,
    nitro_sha256: 0,
    default_sha256: 0,
    normal_sha256: 0
};

function getModeName(mode) {
    const names = {
        'sha256': 'Nitrocore',
        'nitro_sha256': 'Supersonic',
        'default_sha256': 'Turbo',
        'normal_sha256': 'Normal'
    };
    return names[mode] || mode;
}

function updateProgress(mode, secondsLeft) {
    const modeOrder = ['sha256', 'nitro_sha256', 'default_sha256', 'normal_sha256'];
    const stage = modeOrder.indexOf(mode);
    totalProgress = ((stage * 10) + (10 - secondsLeft)) / TOTAL_TIME * 100;
    
    const progressBar = document.querySelector('.progress-bar');
    const progressText = document.querySelector('.progress-text');
    
    progressBar.style.width = `${totalProgress}%`;
    progressText.textContent = 'Processing '+getModeName(mode)+' mode...';
}

async function runBenchmark(mode, currentWorkers) {
    return new Promise((resolve) => {
        currentMode = mode;
        let workerResults = new Array(currentWorkers.length).fill(0);
        let completedWorkers = 0;
        let secondsLeft = 10;
        
        if (countdownInterval) {
            clearInterval(countdownInterval);
        }
        
        updateProgress(mode, secondsLeft);
        
        countdownInterval = setInterval(() => {
            secondsLeft--;
            updateProgress(mode, secondsLeft);
            if (secondsLeft <= 0) {
                clearInterval(countdownInterval);
            }
        }, 1000);

        currentWorkers.forEach((worker, index) => {
            worker.onmessage = function(e) {
                if (e.data.type === 'stats' && e.data.mode === mode) {
                    workerResults[index] = e.data.hashes;
                    completedWorkers++;
                    
                    console.log(`${getModeName(mode)} - Worker ${index + 1}: ${e.data.hashes/10} h/s`);
                    
                    if (completedWorkers === currentWorkers.length) {
                        clearInterval(countdownInterval);
                        const totalHashes = workerResults.reduce((a, b) => a + b, 0);
                        results[mode] = Math.floor(totalHashes / 10);
                        console.log(`${getModeName(mode)} - Total: ${results[mode]} h/s`);
                        resolve();
                    }
                }
            };
            worker.postMessage({ type: mode });
        });
    });
}

async function startFullBenchmark() {
    isRunning = true;
    toggleButton.disabled = true;
    totalProgress = 0;
    
    const progressBar = document.querySelector('.progress-bar');
    const progressText = document.querySelector('.progress-text');
    progressBar.style.width = '0%';
    progressText.textContent = '';

    results.sha256 = 0;
    results.nitro_sha256 = 0;
    results.default_sha256 = 0;
    results.normal_sha256 = 0;
    resultsDisplay.innerHTML = '';
    
    stopBenchmark();

 
    workers = [];
    for (let i = 0; i < workerCount; i++) {
        const worker = new Worker('worker.js');
        worker.onerror = function(e) {
            console.error('Worker error:', e);
        };
        worker.postMessage({ input: input });
        workers.push(worker);
    }

    await runBenchmark('sha256', workers);
    await runBenchmark('nitro_sha256', workers);
    await runBenchmark('default_sha256', workers);

 
    stopBenchmark();

 
    workers = [new Worker('worker.js')];
    workers[0].postMessage({ input: input });
    await runBenchmark('normal_sha256', workers);

    displayResults();
    stopBenchmark();
    
    toggleButton.disabled = false;
    progressText.textContent = 'Completed';
}

function displayResults() {
    const maxValue = Math.max(
        results.sha256,
        results.nitro_sha256,
        results.default_sha256,
        results.normal_sha256
    );

    const resultHTML = `
        <h3>Benchmark Results:</h3>
        <div class="results-container">
            <div class="result-row">
                <div class="result-label">Nitrocore (js-sha256):</div>
                <div class="result-bar-container">
                    <div class="result-bar sonic-bar" style="width: ${(results.sha256 / maxValue * 100)}%"></div>
                    <div class="result-value">${results.sha256.toLocaleString()} h/s</div>
                </div>
            </div>
            <div class="result-row">
                <div class="result-label">Supersonic (forge-sha256):</div>
                <div class="result-bar-container">
                    <div class="result-bar nitro-bar" style="width: ${(results.nitro_sha256 / maxValue * 100)}%"></div>
                    <div class="result-value">${results.nitro_sha256.toLocaleString()} h/s</div>
                </div>
            </div>
            <div class="result-row">
                <div class="result-label">Turbo (SubtleCrypto):</div>
                <div class="result-bar-container">
                    <div class="result-bar turbo-bar" style="width: ${(results.default_sha256 / maxValue * 100)}%"></div>
                    <div class="result-value">${results.default_sha256.toLocaleString()} h/s</div>
                </div>
            </div>
            <div class="result-row">
                <div class="result-label">Normal (SubtleCrypto):</div>
                <div class="result-bar-container">
                    <div class="result-bar normal-bar" style="width: ${(results.normal_sha256 / maxValue * 100)}%"></div>
                    <div class="result-value">${results.normal_sha256.toLocaleString()} h/s</div>
                </div>
            </div>
        </div>
    `;
    resultsDisplay.innerHTML = resultHTML;
}

function stopBenchmark() {
    if (countdownInterval) {
        clearInterval(countdownInterval);
    }
    isRunning = false;
    workers.forEach(worker => worker.terminate());
    workers = [];
}

document.addEventListener('DOMContentLoaded', () => {
    toggleButton.addEventListener('click', () => {
        if (!isRunning) {
            startFullBenchmark();
        }
    });
});
