# SabreBridge - Device Integration Platform

[![Version](https://img.shields.io/badge/version-v2.0.0-blue.svg)](https://github.com/peterkrauspe-Sabre/SabreBridge)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-%3E%3D3.8-brightgreen.svg)](https://python.org/)

A comprehensive device integration platform for connecting various hardware devices to SabreCloud infrastructure. This project enables seamless data collection, processing, and synchronization from multiple device types including access control systems, cameras, and IoT devices.

## 🚀 Features

### 🔌 **Device Integration**
- **Access Control Systems** - ZKTeco, Hikvision, Dahua integration
- **Camera Systems** - IP camera data collection and streaming
- **IoT Devices** - Generic device connectivity framework
- **Real-time Data Sync** - Live data streaming to SabreCloud

### 🖥️ **User Interface**
- **GUI Application** - User-friendly desktop interface
- **Service Mode** - Background service operation
- **Configuration Management** - YAML-based configuration
- **Logging & Monitoring** - Comprehensive logging system

### 🔧 **Core Components**
- **Bridge Core** - Main integration engine
- **Collectors** - Device-specific data collectors
- **Sinks** - Data output handlers
- **Scheduler** - Automated data processing
- **Time Sync** - Device time synchronization

## 🏗️ Architecture

### **Project Structure**
```
SabreBridge/
├── sabre_bridge/           # Core application package
│   ├── collectors/         # Device collectors
│   │   ├── dahua.py        # Dahua device integration
│   │   └── hik.py          # Hikvision device integration
│   ├── sinks/              # Data output handlers
│   │   ├── directdb.py     # Direct database output
│   │   └── zkpush.py       # ZKTeco push handler
│   ├── bridge_core.py      # Main bridge engine
│   ├── gui_app.py          # GUI application
│   ├── service_app.py      # Service application
│   └── zk_scheduler.py     # ZKTeco scheduler
├── config.yaml             # Configuration file
├── person_map.csv          # Person mapping data
├── install_service.bat     # Service installation
├── run_gui.bat             # GUI launcher
└── uninstall_service.bat   # Service removal
```

### **Data Flow**
1. **Device Collectors** → Collect data from hardware devices
2. **Bridge Core** → Process and validate data
3. **Sinks** → Output data to SabreCloud or local storage
4. **Scheduler** → Manage automated operations
5. **GUI/Service** → Provide user interface and background operation

## 📦 Installation

### **Prerequisites**
- Python 3.8 or higher
- Windows 10/11 (for service functionality)
- Network access to target devices

### **Quick Start**

1. **Clone the repository**
   ```bash
   git clone https://github.com/peterkrauspe-Sabre/SabreBridge.git
   cd SabreBridge
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure the system**
   ```bash
   # Edit config.yaml with your device settings
   notepad config.yaml
   ```

4. **Run the application**
   ```bash
   # GUI Mode
   run_gui.bat
   
   # Service Mode
   install_service.bat
   ```

## 🔧 Configuration

### **config.yaml**
```yaml
# Device Configuration
devices:
  zkteco:
    ip: "192.168.1.45"
    port: 4370
    timeout: 30
  
  hikvision:
    ip: "192.168.1.100"
    username: "admin"
    password: "password"
  
  dahua:
    ip: "192.168.1.101"
    username: "admin"
    password: "password"

# SabreCloud Integration
sabrecloud:
  endpoint: "https://api.sabrecloud.com"
  api_key: "your-api-key"
  sync_interval: 300

# Logging Configuration
logging:
  level: "INFO"
  file: "logs/sabre_bridge.log"
  max_size: "10MB"
  backup_count: 5
```

### **person_map.csv**
CSV file mapping device user IDs to SabreCloud person records:
```csv
device_id,sabrecloud_id,name,department
001,USR001,John Doe,Engineering
002,USR002,Jane Smith,Sales
```

## 🚀 Usage

### **GUI Application**
```bash
# Launch GUI
run_gui.bat
```

Features:
- Device status monitoring
- Configuration management
- Manual data sync
- Log viewing
- Service control

### **Service Mode**
```bash
# Install as Windows service
install_service.bat

# Uninstall service
uninstall_service.bat
```

### **Command Line**
```bash
# Run bridge core directly
python -m sabre_bridge

# Run specific collector
python sabre_bridge/collectors/hik.py

# Run scheduler
python sabre_bridge/zk_scheduler.py
```

## 📊 Supported Devices

### **Access Control Systems**
- **ZKTeco** - Attendance logs, user management
- **Hikvision** - Access control, attendance
- **Dahua** - Access control integration

### **Camera Systems**
- **IP Cameras** - Event data, motion detection
- **NVR Systems** - Centralized camera management

### **Generic IoT**
- **REST APIs** - HTTP-based device integration
- **MQTT** - Message-based device communication
- **Custom Protocols** - Extensible collector framework

## 🔄 Data Synchronization

### **Real-time Sync**
- Live data streaming to SabreCloud
- Event-driven data processing
- Automatic retry mechanisms

### **Batch Processing**
- Scheduled data collection
- Offline data storage
- Bulk synchronization

### **Data Formats**
- **Attendance Logs** - Standard attendance format
- **Access Events** - Door access records
- **Device Status** - Health and status information

## 🛠️ Development

### **Adding New Device Support**

1. **Create Collector**
   ```python
   # sabre_bridge/collectors/new_device.py
   class NewDeviceCollector:
       def __init__(self, config):
           self.config = config
       
       def collect_data(self):
           # Implementation
           pass
   ```

2. **Register Collector**
   ```python
   # Update bridge_core.py
   from .collectors.new_device import NewDeviceCollector
   ```

3. **Add Configuration**
   ```yaml
   # config.yaml
   devices:
     new_device:
       ip: "192.168.1.200"
       # device-specific settings
   ```

### **Testing**
```bash
# Run tests
python -m pytest tests/

# Test specific collector
python sabre_bridge/test.py
```

## 📝 API Reference

### **Bridge Core**
- `BridgeCore()` - Main bridge engine
- `start_collection()` - Start data collection
- `stop_collection()` - Stop data collection
- `get_status()` - Get bridge status

### **Collectors**
- `BaseCollector` - Base collector class
- `collect_data()` - Collect data from device
- `test_connection()` - Test device connectivity

### **Sinks**
- `BaseSink` - Base sink class
- `send_data()` - Send data to destination
- `validate_data()` - Validate data format

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-device`)
3. Commit your changes (`git commit -m 'Add new device support'`)
4. Push to the branch (`git push origin feature/new-device`)
5. Open a Pull Request

## 📞 Support

- **Documentation**: [Wiki](https://github.com/peterkrauspe-Sabre/SabreBridge/wiki)
- **Issues**: [GitHub Issues](https://github.com/peterkrauspe-Sabre/SabreBridge/issues)
- **Email**: peterkrauspe@gmail.com

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Version**: v2.0.0  
**Last Updated**: 2025-10-27  
**Status**: Active Development 🚀
