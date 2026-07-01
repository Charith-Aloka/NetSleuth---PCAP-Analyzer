// DOM Optimization Utilities - Enhanced Memory Management
// Provides memory-efficient DOM manipulation methods with advanced caching

class DOMOptimizer {
    constructor() {
        this.recycledElements = new Map();
        this.observedElements = new WeakMap();
        this.batchOperations = [];
        this.animationFrame = null;
    }

    // Element recycling for memory efficiency
    createElement(tagName, className = '', pool = 'default') {
        const poolKey = `${tagName}_${pool}`;
        
        if (!this.recycledElements.has(poolKey)) {
            this.recycledElements.set(poolKey, []);
        }
        
        const pool_array = this.recycledElements.get(poolKey);
        let element;
        
        if (pool_array.length > 0) {
            element = pool_array.pop();
            element.className = className;
            element.innerHTML = '';
            element.removeAttribute('style');
        } else {
            element = document.createElement(tagName);
            if (className) element.className = className;
        }
        
        return element;
    }

    recycleElement(element, pool = 'default') {
        if (!element || !element.tagName) return;
        
        const poolKey = `${element.tagName.toLowerCase()}_${pool}`;
        
        if (!this.recycledElements.has(poolKey)) {
            this.recycledElements.set(poolKey, []);
        }
        
        element.style.display = 'none';
        element.innerHTML = '';
        element.className = '';
        
        const pool_array = this.recycledElements.get(poolKey);
        if (pool_array.length < 50) {
            pool_array.push(element);
        }
    }

    // Batch DOM operations for performance
    batchUpdate(operation) {
        this.batchOperations.push(operation);
        
        if (!this.animationFrame) {
            this.animationFrame = requestAnimationFrame(() => {
                this.executeBatchOperations();
            });
        }
    }

    executeBatchOperations() {
        const fragment = document.createDocumentFragment();
        
        this.batchOperations.forEach(operation => {
            try {
                operation(fragment);
            } catch (error) {
                console.error('Batch operation error:', error);
            }
        });
        
        this.batchOperations = [];
        this.animationFrame = null;
    }

    // Create table rows efficiently using DocumentFragment
    static createTableRows(data, rowTemplate, emptyMessage = 'No data available', colSpan = 1) {
        const tbody = document.createElement('tbody');
        
        if (!data || data.length === 0) {
            const emptyRow = document.createElement('tr');
            const emptyCell = document.createElement('td');
            emptyCell.colSpan = colSpan;
            emptyCell.style.textAlign = 'center';
            emptyCell.style.color = 'var(--text-muted)';
            emptyCell.textContent = emptyMessage;
            emptyRow.appendChild(emptyCell);
            tbody.appendChild(emptyRow);
            return tbody;
        }

        const fragment = document.createDocumentFragment();
        
        data.forEach(item => {
            const row = document.createElement('tr');
            row.innerHTML = rowTemplate(item);
            fragment.appendChild(row);
        });
        
        tbody.appendChild(fragment);
        return tbody;
    }

    // Replace table body efficiently
    static replaceTableBody(tableSelector, newTbody) {
        const table = document.querySelector(tableSelector);
        if (!table) return;
        
        const oldTbody = table.querySelector('tbody');
        if (oldTbody) {
            // Clean up event listeners before removal
            this.cleanupEventListeners(oldTbody);
            oldTbody.remove();
        }
        
        table.appendChild(newTbody);
    }

    // Clean up event listeners to prevent memory leaks
    static cleanupEventListeners(element) {
        if (!element) return;
        
        // Remove all event listeners by cloning the element
        const newElement = element.cloneNode(true);
        element.parentNode?.replaceChild(newElement, element);
    }

    // Efficient HTML escaping
    static escapeHtml(text) {
        if (typeof text !== 'string') return text;
        
        const escapeMap = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '/': '&#x2F;'
        };
        
        return text.replace(/[&<>"'/]/g, (s) => escapeMap[s]);
    }

    // Debounce function to prevent excessive DOM updates
    static debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    // Throttle function for scroll events
    static throttle(func, limit) {
        let inThrottle;
        return function(...args) {
            if (!inThrottle) {
                func.apply(this, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    }

    // Enhanced virtual scrolling for large datasets
    setupVirtualScroll(container, options = {}) {
        const config = {
            itemHeight: 50,
            buffer: 5,
            totalItems: 0,
            renderItem: null,
            ...options
        };

        const viewport = {
            height: container.clientHeight,
            scrollTop: 0,
            startIndex: 0,
            endIndex: 0,
            visibleItems: Math.ceil(container.clientHeight / config.itemHeight)
        };

        // Create virtual container
        const virtualContainer = document.createElement('div');
        virtualContainer.style.position = 'relative';
        virtualContainer.style.height = `${config.totalItems * config.itemHeight}px`;
        
        const itemsContainer = document.createElement('div');
        itemsContainer.style.position = 'absolute';
        itemsContainer.style.top = '0';
        itemsContainer.style.width = '100%';
        
        virtualContainer.appendChild(itemsContainer);
        container.appendChild(virtualContainer);

        const updateVirtualScroll = () => {
            viewport.scrollTop = container.scrollTop;
            viewport.startIndex = Math.max(0, Math.floor(viewport.scrollTop / config.itemHeight) - config.buffer);
            viewport.endIndex = Math.min(config.totalItems - 1, viewport.startIndex + viewport.visibleItems + config.buffer * 2);

            itemsContainer.innerHTML = '';
            itemsContainer.style.top = `${viewport.startIndex * config.itemHeight}px`;

            for (let i = viewport.startIndex; i <= viewport.endIndex; i++) {
                if (config.renderItem) {
                    const item = config.renderItem(i);
                    if (item) {
                        itemsContainer.appendChild(item);
                    }
                }
            }
        };

        let scrollTimeout;
        container.addEventListener('scroll', () => {
            clearTimeout(scrollTimeout);
            scrollTimeout = setTimeout(updateVirtualScroll, 16);
        });

        return {
            update: (newTotalItems) => {
                config.totalItems = newTotalItems;
                virtualContainer.style.height = `${config.totalItems * config.itemHeight}px`;
                updateVirtualScroll();
            },
            refresh: updateVirtualScroll
        };
    }

    // Memory cleanup
    cleanup() {
        this.recycledElements.clear();
        
        if (this.animationFrame) {
            cancelAnimationFrame(this.animationFrame);
            this.animationFrame = null;
        }
        
        this.batchOperations = [];
    }

    // Legacy virtual scrolling method for backward compatibility
    static createVirtualScrollTable(containerId, data, itemHeight = 40, visibleItems = 10) {
        const container = document.getElementById(containerId);
        if (!container) return;

        const totalHeight = data.length * itemHeight;
        const viewport = container.querySelector('.viewport') || container;
        
        viewport.style.height = `${visibleItems * itemHeight}px`;
        viewport.style.overflow = 'auto';
        
        let startIndex = 0;
        let endIndex = Math.min(data.length, visibleItems);
        
        const renderItems = () => {
            viewport.innerHTML = '';
            const fragment = document.createDocumentFragment();
            
            for (let i = startIndex; i < endIndex; i++) {
                const item = data[i];
                if (item) {
                    const element = document.createElement('div');
                    element.style.height = `${itemHeight}px`;
                    element.style.position = 'absolute';
                    element.style.top = `${i * itemHeight}px`;
                    element.innerHTML = this.renderItem ? this.renderItem(item) : item.toString();
                    fragment.appendChild(element);
                }
            }
            
            viewport.appendChild(fragment);
        };

        viewport.addEventListener('scroll', this.throttle(() => {
            const scrollTop = viewport.scrollTop;
            startIndex = Math.floor(scrollTop / itemHeight);
            endIndex = Math.min(data.length, startIndex + visibleItems + 2);
            renderItems();
        }, 16));

        renderItems();
    }
}

// Global instances
const domOptimizer = new DOMOptimizer();

// Export for use in other modules
if (typeof window !== 'undefined') {
    window.DOMOptimizer = DOMOptimizer;
    window.domOptimizer = domOptimizer;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { DOMOptimizer, domOptimizer };
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (window.domOptimizer) {
        window.domOptimizer.cleanup();
    }
});
