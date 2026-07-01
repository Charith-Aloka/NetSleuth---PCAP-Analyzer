// API Configuration and Helper Functions
const API_CONFIG = {
    baseURL: 'http://localhost:5000/api',
    timeout: 30000
};

class APIError extends Error {
    constructor(message, status = null, data = null) {
        super(message);
        this.name = 'APIError';
        this.status = status;
        this.data = data;
    }
}

class APIClient {
    constructor(config = {}) {
        this.baseURL = config.baseURL || API_CONFIG.baseURL;
        this.timeout = config.timeout || API_CONFIG.timeout;
    }

    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const config = {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        };

        // Remove Content-Type for FormData
        if (options.body instanceof FormData) {
            delete config.headers['Content-Type'];
        }

        try {
            console.log(`API Request: ${config.method || 'GET'} ${url}`);
            
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.timeout);
            
            const response = await fetch(url, {
                ...config,
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);

            // Handle non-JSON responses (like file downloads)
            if (response.headers.get('content-type')?.includes('application/octet-stream')) {
                if (!response.ok) {
                    throw new APIError(`HTTP ${response.status}: ${response.statusText}`, response.status);
                }
                return response;
            }

            // Parse JSON response
            let data;
            try {
                data = await response.json();
            } catch (e) {
                console.warn('Failed to parse JSON response:', e);
                data = null;
            }

            if (!response.ok) {
                const errorMessage = data?.error || `HTTP ${response.status}: ${response.statusText}`;
                throw new APIError(errorMessage, response.status, data);
            }

            console.log(`API Response: ${response.status} ${response.statusText}`);
            return data;

        } catch (error) {
            if (error.name === 'AbortError') {
                throw new APIError('Request timeout', 408);
            }
            if (error instanceof APIError) {
                throw error;
            }
            console.error('API Request failed:', error);
            throw new APIError(`Network error: ${error.message}`);
        }
    }

    // HTTP Methods
    async get(endpoint, params = {}) {
        const queryString = new URLSearchParams(params).toString();
        const url = queryString ? `${endpoint}?${queryString}` : endpoint;
        return this.request(url, { method: 'GET' });
    }

    async post(endpoint, body = null) {
        return this.request(endpoint, {
            method: 'POST',
            body: body instanceof FormData ? body : JSON.stringify(body)
        });
    }

    async put(endpoint, body = null) {
        return this.request(endpoint, {
            method: 'PUT',
            body: JSON.stringify(body)
        });
    }

    async delete(endpoint) {
        return this.request(endpoint, { method: 'DELETE' });
    }

    async download(endpoint) {
        return this.request(endpoint, { method: 'GET' });
    }

    // Threat assessment
    async assessDomains(fileId) {
        return this.post(`/analysis/${fileId}/assess_domains`);
    }

    async getAssessments(fileId) {
        return this.get(`/analysis/${fileId}/assessments`);
    }
}

// Create global API instance
window.api = new APIClient();

// Export for module systems (if needed)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { APIClient, APIError };
}
