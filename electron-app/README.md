# PCAP Network Analyzer

A modern desktop application for analyzing network traffic from PCAP files using Scapy and Electron.

## Features

### 🔍 **Network Analysis**
- **IP Address Analysis**: Discover all IP addresses and their packet counts
- **Device Discovery**: Identify network devices with MAC addresses and hostnames  
- **Domain Resolution**: Extract domains from DNS and HTTP traffic
- **Flow Analysis**: Analyze network flows with detailed statistics

### 📁 **File Management**
- **Drag & Drop Upload**: Easy PCAP file uploading
- **Multiple Format Support**: .pcap, .pcapng, .cap files
- **File Organization**: Search, sort, and manage uploaded files
- **Duplicate Prevention**: Automatic SHA256 hash checking

### 🎨 **Modern Interface**
- **Clean Design**: Modern, responsive user interface
- **Real-time Progress**: Upload and analysis progress tracking
- **Status Notifications**: Clear feedback for all operations
- **Keyboard Shortcuts**: Efficient navigation and operations

## Project Structure

```
PCAP Analizer/
├── backend/                    # Python Flask backend
│   ├── app.py                 # Main Flask application
│   ├── routes/                # API route handlers
│   │   ├── files.py          # File management endpoints
│   │   └── analyze.py        # Analysis endpoints
│   ├── services/              # Business logic
│   │   └── analyzer.py       # Scapy analysis engine
│   ├── utils/                 # Utility functions
│   │   └── db.py             # Database operations
│   └── requirements.txt       # Python dependencies
│
├── electron-app-new/          # Electron desktop application
│   ├── main.js               # Electron main process
│   ├── preload.js            # Secure context bridge
│   ├── package.json          # Node.js dependencies
│   └── src/                  # Application source
│       ├── index.html        # Main HTML interface
│       ├── css/              # Stylesheets
│       │   └── styles.css    # Main application styles
│       └── js/               # JavaScript modules
│           ├── api.js        # API communication layer
│           ├── ui.js         # UI management and helpers
│           ├── files.js      # File management logic
│           ├── analysis.js   # Analysis operations
│           └── app.js        # Main application entry
│
└── database/                  # SQLite database storage
    └── pcap_analyzer.db      # Application database
```

## Technology Stack

### Backend
- **Python 3.8+** - Core backend language
- **Flask** - Web framework and API server
- **Scapy** - Network packet analysis library
- **SQLite** - Lightweight database storage
- **Werkzeug** - File upload handling

### Frontend
- **Electron** - Desktop application framework
- **HTML5/CSS3** - Modern web technologies
- **Vanilla JavaScript** - No heavy frameworks, pure JS
- **Font Awesome** - Icon library

## Installation & Setup

### Prerequisites
- Python 3.8 or higher
- Node.js 16 or higher
- npm or yarn package manager

### Backend Setup
```bash
cd backend
pip install -r requirements.txt
python app.py
```

### Frontend Setup
```bash
cd electron-app-new
npm install
npm start
```

## API Endpoints

### File Management
- `POST /api/upload` - Upload PCAP files
- `GET /api/files` - List uploaded files
- `GET /api/download/<id>` - Download file by ID
- `DELETE /api/delete/<id>` - Delete file by ID

### Analysis
- `POST /api/analyze/<id>` - Trigger analysis for file
- `GET /api/analysis/<id>/summary` - Get analysis summary
- `GET /api/analysis/<id>/ips` - Get IP addresses
- `GET /api/analysis/<id>/devices` - Get network devices
- `GET /api/analysis/<id>/domains` - Get discovered domains
- `GET /api/analysis/<id>/flows` - Get network flows

## Database Schema

The application uses SQLite with the following main tables:

- **uploaded_files**: Stores file metadata and paths
- **analysis_runs**: Tracks analysis execution
- **ip_observations**: IP addresses found in packets
- **devices**: Network devices with MAC/IP mappings
- **domains**: DNS/HTTP domain resolutions
- **flows**: Network flow statistics

## Development

### Running in Development Mode
```bash
# Backend with debug mode
cd backend
python app.py

# Frontend with dev tools
cd electron-app-new
npm run dev
```

### Code Organization

The application follows a modular architecture:

1. **Backend**: RESTful API with clean separation of routes, services, and data layers
2. **Frontend**: Component-based JavaScript modules with clear responsibilities
3. **Database**: Normalized schema optimized for network analysis queries

### Key Features Implementation

- **File Upload**: Secure multipart upload with hash-based deduplication
- **Analysis Engine**: Scapy-powered packet parsing with efficient database storage
- **Real-time UI**: Event-driven updates with proper error handling
- **Cross-platform**: Electron ensures consistent experience across operating systems

## Security Considerations

- Content Security Policy (CSP) implemented
- Input validation and sanitization
- Secure file handling with temporary storage
- No direct file system access from renderer process

## Performance Optimizations

- Lazy loading of large datasets
- Efficient database queries with proper indexing
- Memory management for large PCAP files
- Background processing for analysis tasks

## Contributing

1. Fork the repository
2. Create a feature branch
3. Follow the existing code style and structure
4. Add tests for new functionality
5. Submit a pull request with clear description

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues, questions, or contributions, please use the GitHub issue tracker.
