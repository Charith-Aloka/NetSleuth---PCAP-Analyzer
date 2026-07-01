// Main Application Entry Point

class PCAPAnalyzer {
    constructor() {
        this.initialized = false;
        this.version = '1.0.0';
        this.apiHealthy = false;
    }

    async init() {
        if (this.initialized) return;
        
        console.log(`PCAP Analyzer v${this.version} - Starting initialization...`);
        
        try {
            // Wait for DOM to be ready
            if (document.readyState === 'loading') {
                await new Promise(resolve => {
                    document.addEventListener('DOMContentLoaded', resolve);
                });
            }
            
            console.log('DOM ready, initializing components...');
            
            // Initialize all components
            await this.initializeComponents();
            
            // Check backend connectivity
            await this.checkBackendHealth();
            
            // Load initial data
            await this.loadInitialData();
            
            // Set up Electron integration
            this.setupElectronIntegration();
            
            this.initialized = true;
            console.log('PCAP Analyzer initialization complete!');
            
        } catch (error) {
            console.error('Failed to initialize PCAP Analyzer:', error);
            this.showInitializationError(error);
        }
    }

    async initializeComponents() {
        // Initialize UI Manager
        if (window.ui) {
            window.ui.init();
        }
        
        // Initialize File Manager
        if (window.fileManager) {
            window.fileManager.init();
        }
        
        console.log('All components initialized');
    }

    async checkBackendHealth() {
        try {
            console.log('Checking backend health...');
            
            // Try to reach the backend with a lightweight health endpoint
            await window.api.get('/health');
            
            this.apiHealthy = true;
            console.log('Backend is healthy and responding');
            
        } catch (error) {
            console.warn('Backend health check failed:', error);
            this.apiHealthy = false;
            
            // Show warning but don't prevent app from starting
            window.ui.showStatus(
                'Backend server is not responding. Please make sure the Python backend is running.',
                'warning',
                10000
            );
        }
    }

    async loadInitialData() {
        if (!this.apiHealthy) {
            console.log('Skipping initial data load due to backend connectivity issues');
            return;
        }

        try {
            console.log('Loading initial data...');
            
            // Load files
            await window.fileManager.loadFiles();
            
            console.log('Initial data loaded successfully');
            
        } catch (error) {
            console.error('Error loading initial data:', error);
            window.ui.showStatus(`Error loading data: ${error.message}`, 'error');
        }
    }

    setupElectronIntegration() {
        // Check if running in Electron
        if (typeof window.electronAPI !== 'undefined') {
            console.log('Setting up Electron integration...');
            
            // Listen for menu events
            window.electronAPI.onMenuUploadFile(() => {
                const fileInput = window.ui.get('fileInput');
                if (fileInput) fileInput.click();
            });
            
            window.electronAPI.onMenuRefresh(() => {
                if (window.fileManager) {
                    window.fileManager.loadFiles();
                }
            });
            
            console.log('Electron integration setup complete');
        } else {
            console.log('Running in browser mode (not Electron)');
        }
    }

    showInitializationError(error) {
        // Create error display
        const errorDiv = document.createElement('div');
        errorDiv.style.cssText = `
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: #fee;
            border: 2px solid #fcc;
            border-radius: 8px;
            padding: 2rem;
            max-width: 500px;
            text-align: center;
            z-index: 9999;
            font-family: system-ui, sans-serif;
        `;
        
        errorDiv.innerHTML = `
            <h2 style="color: #c53030; margin-bottom: 1rem;">
                <i style="font-size: 2rem; display: block; margin-bottom: 0.5rem;">⚠️</i>
                Initialization Failed
            </h2>
            <p style="margin-bottom: 1rem; color: #742a2a;">
                The PCAP Analyzer failed to initialize properly.
            </p>
            <details style="text-align: left; margin-bottom: 1rem;">
                <summary style="cursor: pointer; font-weight: bold;">Error Details</summary>
                <pre style="background: #f5f5f5; padding: 1rem; border-radius: 4px; font-size: 0.8rem; overflow: auto; margin-top: 0.5rem;">${error.message}</pre>
            </details>
            <button onclick="location.reload()" style="background: #3182ce; color: white; border: none; padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer;">
                Reload Application
            </button>
        `;
        
        document.body.appendChild(errorDiv);
    }

    // Public methods for external access
    async refresh() {
        if (window.fileManager) {
            await window.fileManager.loadFiles();
        }
    }

    getVersion() {
        return this.version;
    }

    isHealthy() {
        return this.initialized && this.apiHealthy;
    }
}

// Global error handling
window.addEventListener('error', (event) => {
    console.error('Global error:', event.error);
    
    if (window.ui) {
        window.ui.showStatus(`Application error: ${event.error.message}`, 'error');
    }
});

window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
    
    if (window.ui) {
        window.ui.showStatus(`Unhandled error: ${event.reason.message || event.reason}`, 'error');
    }
});

// Create and initialize the application
window.app = new PCAPAnalyzer();

// Auto-initialize when script loads
window.app.init().catch(error => {
    console.error('Failed to auto-initialize:', error);
});

// Expose app for debugging
if (typeof window.electronAPI !== 'undefined' && window.electronAPI.isDev()) {
    window.debug = {
        app: window.app,
        ui: window.ui,
        fileManager: window.fileManager,
        analysisManager: window.analysisManager,
        api: window.api
    };
    console.log('Debug objects available on window.debug');
}
