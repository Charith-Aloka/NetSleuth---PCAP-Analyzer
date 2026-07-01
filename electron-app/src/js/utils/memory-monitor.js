// Memory Monitor Utility
// Helps track and log memory usage to identify leaks

class MemoryMonitor {
    constructor() {
        this.enabled = false;
        this.interval = null;
        this.logs = [];
        this.maxLogs = 100;
        this.lastGC = Date.now();
    }

    // Start monitoring memory usage
    start(intervalMs = 10000) {
        if (this.interval) return;
        
        this.enabled = true;
        console.log('🔍 Memory monitoring started');
        
        // Initial reading
        this.logMemoryUsage('Initial');
        
        this.interval = setInterval(() => {
            this.logMemoryUsage('Periodic');
            this.checkForLeaks();
        }, intervalMs);
    }

    // Stop monitoring
    stop() {
        if (this.interval) {
            clearInterval(this.interval);
            this.interval = null;
            this.enabled = false;
            console.log('🔍 Memory monitoring stopped');
        }
    }

    // Log current memory usage
    logMemoryUsage(context = 'Manual') {
        if (!this.enabled) return;

        const memInfo = this.getMemoryInfo();
        const timestamp = new Date().toISOString();
        
        const logEntry = {
            timestamp,
            context,
            ...memInfo,
            domNodes: document.querySelectorAll('*').length,
            eventListeners: this.estimateEventListeners()
        };

        this.logs.push(logEntry);
        
        // Keep only the last maxLogs entries
        if (this.logs.length > this.maxLogs) {
            this.logs = this.logs.slice(-this.maxLogs);
        }

        console.log(`📊 Memory [${context}]:`, {
            'Used JSHeap': `${(memInfo.usedJSHeapSize / 1024 / 1024).toFixed(1)}MB`,
            'Total JSHeap': `${(memInfo.totalJSHeapSize / 1024 / 1024).toFixed(1)}MB`,
            'Heap Limit': `${(memInfo.jsHeapSizeLimit / 1024 / 1024).toFixed(1)}MB`,
            'DOM Nodes': logEntry.domNodes,
            'Est. Listeners': logEntry.eventListeners
        });
    }

    // Get memory information
    getMemoryInfo() {
        if (window.performance && window.performance.memory) {
            return {
                usedJSHeapSize: window.performance.memory.usedJSHeapSize,
                totalJSHeapSize: window.performance.memory.totalJSHeapSize,
                jsHeapSizeLimit: window.performance.memory.jsHeapSizeLimit
            };
        }
        
        // Fallback for browsers without performance.memory
        return {
            usedJSHeapSize: 0,
            totalJSHeapSize: 0,
            jsHeapSizeLimit: 0
        };
    }

    // Estimate number of event listeners (rough approximation)
    estimateEventListeners() {
        let count = 0;
        const elements = document.querySelectorAll('*');
        
        elements.forEach(el => {
            // Check for common event listener indicators
            if (el.onclick || el.onchange || el.oninput || el.onsubmit) count++;
            if (el.getAttribute && (
                el.getAttribute('onclick') || 
                el.getAttribute('onchange') || 
                el.getAttribute('oninput')
            )) count++;
        });
        
        return count;
    }

    // Check for potential memory leaks
    checkForLeaks() {
        if (this.logs.length < 3) return;

        const recent = this.logs.slice(-3);
        const memoryTrend = recent.map(log => log.usedJSHeapSize);
        
        // Check if memory is consistently increasing
        const isIncreasing = memoryTrend.every((val, i) => 
            i === 0 || val >= memoryTrend[i - 1]
        );

        if (isIncreasing && memoryTrend[2] - memoryTrend[0] > 50 * 1024 * 1024) {
            console.warn('🚨 Potential memory leak detected! Memory increased by', 
                ((memoryTrend[2] - memoryTrend[0]) / 1024 / 1024).toFixed(1), 'MB');
            this.suggestCleanup();
        }

        // Check DOM node count
        const domTrend = recent.map(log => log.domNodes);
        if (domTrend[2] > domTrend[0] * 1.5) {
            console.warn('🚨 DOM nodes increased significantly:', 
                domTrend[0], '->', domTrend[2]);
        }

        // Suggest garbage collection if memory is high
        const currentMemMB = memoryTrend[2] / 1024 / 1024;
        if (currentMemMB > 500 && Date.now() - this.lastGC > 30000) {
            this.forceGarbageCollection();
        }
    }

    // Suggest cleanup actions
    suggestCleanup() {
        console.log('💡 Memory cleanup suggestions:');
        console.log('  - Clear large data arrays when not needed');
        console.log('  - Remove unused event listeners');
        console.log('  - Clean up DOM elements that are no longer displayed');
        console.log('  - Use WeakMap/WeakSet for temporary references');
    }

    // Force garbage collection if available
    forceGarbageCollection() {
        if (window.gc && typeof window.gc === 'function') {
            console.log('🗑️ Forcing garbage collection...');
            window.gc();
            this.lastGC = Date.now();
            
            // Log memory after GC
            setTimeout(() => {
                this.logMemoryUsage('Post-GC');
            }, 1000);
        } else {
            console.log('💡 To enable garbage collection, start Chrome with --js-flags="--expose-gc"');
        }
    }

    // Get memory usage summary
    getSummary() {
        if (this.logs.length === 0) return null;

        const latest = this.logs[this.logs.length - 1];
        const first = this.logs[0];
        
        return {
            current: {
                memory: `${(latest.usedJSHeapSize / 1024 / 1024).toFixed(1)}MB`,
                domNodes: latest.domNodes,
                listeners: latest.eventListeners
            },
            growth: {
                memory: `${((latest.usedJSHeapSize - first.usedJSHeapSize) / 1024 / 1024).toFixed(1)}MB`,
                domNodes: latest.domNodes - first.domNodes,
                timespan: `${((new Date(latest.timestamp) - new Date(first.timestamp)) / 1000 / 60).toFixed(1)} minutes`
            },
            recommendations: this.getRecommendations(latest)
        };
    }

    // Get performance recommendations
    getRecommendations(latest) {
        const recommendations = [];
        
        const memoryMB = latest.usedJSHeapSize / 1024 / 1024;
        if (memoryMB > 200) {
            recommendations.push('High memory usage detected - consider optimizing data structures');
        }
        
        if (latest.domNodes > 5000) {
            recommendations.push('High DOM node count - consider virtual scrolling or pagination');
        }
        
        if (latest.eventListeners > 100) {
            recommendations.push('Many event listeners detected - use event delegation where possible');
        }
        
        return recommendations;
    }

    // Export logs for analysis
    exportLogs() {
        const data = {
            exportDate: new Date().toISOString(),
            logs: this.logs,
            summary: this.getSummary()
        };
        
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `memory-logs-${Date.now()}.json`;
        a.click();
        
        URL.revokeObjectURL(url);
        console.log('💾 Memory logs exported');
    }
}

// Global memory monitor instance
const memoryMonitor = new MemoryMonitor();

// Auto-start in development
if (process?.env?.NODE_ENV === 'development') {
    memoryMonitor.start(15000); // Every 15 seconds in dev
}

// Expose globally
if (typeof window !== 'undefined') {
    window.memoryMonitor = memoryMonitor;
}

// Console commands for easy access
console.log('📊 Memory monitor available:');
console.log('  memoryMonitor.start()     - Start monitoring');
console.log('  memoryMonitor.stop()      - Stop monitoring');
console.log('  memoryMonitor.logMemoryUsage() - Manual log');
console.log('  memoryMonitor.getSummary() - Get summary');
console.log('  memoryMonitor.exportLogs() - Export data');

if (typeof module !== 'undefined' && module.exports) {
    module.exports = MemoryMonitor;
}
