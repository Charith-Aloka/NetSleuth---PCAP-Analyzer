/**
 * AI Chat Interface - JavaScript
 * Natural language interface for network analysis
 */

let currentPcapId = null;
let isProcessing = false;

// Initialize chat interface
function init() {
    console.log('Initializing AI Chat...');
    
    // Set welcome time
    const welcomeTime = document.getElementById('welcomeTime');
    if (welcomeTime) {
        welcomeTime.textContent = formatTime(new Date());
    }
    
    // Load PCAP files for context selector
    loadPcapFiles();
    
    // Load suggestions
    loadSuggestions();
    
    // Setup event listeners
    setupEventListeners();
    
    // Auto-resize textarea
    setupTextareaAutoResize();
}

// Setup event listeners
function setupEventListeners() {
    // Chat form submission
    const chatForm = document.getElementById('chatForm');
    chatForm.addEventListener('submit', handleSendMessage);
    
    // PCAP selector change
    const pcapSelector = document.getElementById('pcapSelector');
    pcapSelector.addEventListener('change', (e) => {
        currentPcapId = e.target.value ? parseInt(e.target.value) : null;
        loadSuggestions();
    });
    
    // Clear chat button
    const clearChatBtn = document.getElementById('clearChatBtn');
    clearChatBtn.addEventListener('click', handleClearChat);
    
    // Export chat button
    const exportChatBtn = document.getElementById('exportChatBtn');
    exportChatBtn.addEventListener('click', handleExportChat);
    
    // Character count
    const messageInput = document.getElementById('messageInput');
    messageInput.addEventListener('input', updateCharCount);
    
    // Enter to send (Shift+Enter for new line)
    messageInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            if (!isProcessing && messageInput.value.trim()) {
                chatForm.dispatchEvent(new Event('submit'));
            }
        }
    });
}

// Setup textarea auto-resize
function setupTextareaAutoResize() {
    const textarea = document.getElementById('messageInput');
    
    textarea.addEventListener('input', () => {
        textarea.style.height = 'auto';
        textarea.style.height = Math.min(textarea.scrollHeight, 200) + 'px';
    });
}

// Load PCAP files
async function loadPcapFiles() {
    try {
        const data = await window.api.get('/files');
        const files = data.files || [];
        
        const selector = document.getElementById('pcapSelector');
        
        // Clear existing options (except first)
        while (selector.options.length > 1) {
            selector.remove(1);
        }
        
        // Add PCAP options
        files.forEach(file => {
            const option = document.createElement('option');
            option.value = file.id;
            option.textContent = `${file.original_filename} (${formatFileSize(file.size)})`;
            selector.appendChild(option);
        });
        
    } catch (error) {
        console.error('Error loading PCAP files:', error);
    }
}

// Load suggestions
async function loadSuggestions() {
    try {
        const url = currentPcapId 
            ? `/chat/suggestions?pcap_id=${currentPcapId}`
            : '/chat/suggestions';
        
        const data = await window.api.get(url);
        const suggestions = data.suggestions || [];
        
        const suggestionsList = document.getElementById('suggestionsList');
        suggestionsList.innerHTML = '';
        
        suggestions.forEach(suggestion => {
            const button = document.createElement('button');
            button.className = 'suggestion-item';
            button.textContent = suggestion;
            button.addEventListener('click', () => {
                document.getElementById('messageInput').value = suggestion;
                document.getElementById('messageInput').focus();
            });
            suggestionsList.appendChild(button);
        });
        
    } catch (error) {
        console.error('Error loading suggestions:', error);
    }
}

// Handle send message
async function handleSendMessage(e) {
    e.preventDefault();
    
    if (isProcessing) return;
    
    const messageInput = document.getElementById('messageInput');
    const message = messageInput.value.trim();
    
    if (!message) return;
    
    // Clear input
    messageInput.value = '';
    messageInput.style.height = 'auto';
    updateCharCount();
    
    // Add user message to chat
    addMessage('user', message);
    
    // Show loading indicator
    const loadingId = addLoadingMessage();
    
    // Disable send button
    isProcessing = true;
    const sendBtn = document.getElementById('sendBtn');
    sendBtn.disabled = true;
    
    try {
        // Send message to backend
        const response = await window.api.post('/chat/message', {
            message: message,
            pcap_id: currentPcapId
        });
        
        // Remove loading indicator
        removeMessage(loadingId);
        
        // Add assistant response
        addMessage('assistant', response.response, response.timestamp);
        
    } catch (error) {
        console.error('Error sending message:', error);
        removeMessage(loadingId);
        addMessage('assistant', '❌ Sorry, I encountered an error processing your message. Please try again.');
    } finally {
        isProcessing = false;
        sendBtn.disabled = false;
    }
}

// Add message to chat
function addMessage(role, content, timestamp = null) {
    const messagesContainer = document.getElementById('chatMessages');
    
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${role}-message`;
    messageDiv.id = `msg-${Date.now()}`;
    
    const avatarDiv = document.createElement('div');
    avatarDiv.className = 'message-avatar';
    avatarDiv.innerHTML = role === 'assistant' 
        ? '<i class="fas fa-robot"></i>'
        : '<i class="fas fa-user"></i>';
    
    const contentDiv = document.createElement('div');
    contentDiv.className = 'message-content';
    
    const headerDiv = document.createElement('div');
    headerDiv.className = 'message-header';
    
    const senderSpan = document.createElement('span');
    senderSpan.className = 'message-sender';
    senderSpan.textContent = role === 'assistant' ? 'NetSleuth AI' : 'You';
    
    const timeSpan = document.createElement('span');
    timeSpan.className = 'message-time';
    timeSpan.textContent = timestamp ? formatTime(new Date(timestamp)) : formatTime(new Date());
    
    headerDiv.appendChild(senderSpan);
    headerDiv.appendChild(timeSpan);
    
    const textDiv = document.createElement('div');
    textDiv.className = 'message-text';
    
    // Parse markdown-style formatting
    textDiv.innerHTML = parseMessageContent(content);
    
    contentDiv.appendChild(headerDiv);
    contentDiv.appendChild(textDiv);
    
    messageDiv.appendChild(avatarDiv);
    messageDiv.appendChild(contentDiv);
    
    messagesContainer.appendChild(messageDiv);
    
    // Scroll to bottom
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
    
    return messageDiv.id;
}

// Add loading message
function addLoadingMessage() {
    const messagesContainer = document.getElementById('chatMessages');
    
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message assistant-message loading';
    messageDiv.id = `loading-${Date.now()}`;
    
    const avatarDiv = document.createElement('div');
    avatarDiv.className = 'message-avatar';
    avatarDiv.innerHTML = '<i class="fas fa-robot"></i>';
    
    const contentDiv = document.createElement('div');
    contentDiv.className = 'message-content';
    
    const textDiv = document.createElement('div');
    textDiv.className = 'message-text';
    textDiv.innerHTML = `
        <div class="loading-dots">
            <div class="loading-dot"></div>
            <div class="loading-dot"></div>
            <div class="loading-dot"></div>
        </div>
    `;
    
    contentDiv.appendChild(textDiv);
    messageDiv.appendChild(avatarDiv);
    messageDiv.appendChild(contentDiv);
    
    messagesContainer.appendChild(messageDiv);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
    
    return messageDiv.id;
}

// Remove message
function removeMessage(messageId) {
    const message = document.getElementById(messageId);
    if (message) {
        message.remove();
    }
}

// Parse message content (basic markdown-like formatting)
function parseMessageContent(content) {
    // Escape HTML first
    let html = content
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
    
    // Bold: **text**
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    
    // Code: `code`
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
    
    // Links: [text](url) - make clickable
    html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank">$1</a>');
    
    // Line breaks
    html = html.replace(/\n/g, '<br>');
    
    // Lists: lines starting with - or *
    html = html.replace(/^[-*] (.+)$/gm, '<li>$1</li>');
    if (html.includes('<li>')) {
        html = html.replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>');
    }
    
    return html;
}

// Handle clear chat
async function handleClearChat() {
    if (!confirm('Are you sure you want to clear the chat history?')) {
        return;
    }
    
    try {
        await window.api.post('/chat/clear', {});
        
        // Clear messages (keep welcome message)
        const messagesContainer = document.getElementById('chatMessages');
        const messages = messagesContainer.querySelectorAll('.message:not(.welcome-message)');
        messages.forEach(msg => msg.remove());
        
    } catch (error) {
        console.error('Error clearing chat:', error);
        alert('Failed to clear chat history');
    }
}

// Handle export chat
function handleExportChat() {
    const messagesContainer = document.getElementById('chatMessages');
    const messages = messagesContainer.querySelectorAll('.message');
    
    let exportText = 'NetSleuth AI Chat Export\n';
    exportText += '='.repeat(50) + '\n\n';
    
    messages.forEach(msg => {
        if (msg.classList.contains('welcome-message')) return;
        
        const sender = msg.querySelector('.message-sender').textContent;
        const time = msg.querySelector('.message-time').textContent;
        const text = msg.querySelector('.message-text').textContent;
        
        exportText += `[${time}] ${sender}:\n${text}\n\n`;
    });
    
    // Create download link
    const blob = new Blob([exportText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `netsleuth-chat-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
}

// Update character count
function updateCharCount() {
    const messageInput = document.getElementById('messageInput');
    const charCount = document.getElementById('charCount');
    const count = messageInput.value.length;
    charCount.textContent = `${count}/2000`;
    
    if (count > 1800) {
        charCount.style.color = 'var(--warning-color)';
    } else if (count > 1950) {
        charCount.style.color = 'var(--danger-color)';
    } else {
        charCount.style.color = 'var(--text-tertiary)';
    }
}

// Format time
function formatTime(date) {
    return date.toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
