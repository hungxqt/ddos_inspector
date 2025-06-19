# DDoS Inspector Environment Configuration

The DDoS Inspector supports flexible configuration through environment variables and `.env` files, making it easy to deploy in different environments without modifying configuration files.

## Configuration Priority

The configuration follows this priority order:

1. **Explicit configuration parameters** (highest priority)
2. **Environment variables** 
3. **`.env` file** in current working directory
4. **`$SNORT_DATA_DIR`** fallback
5. **`/tmp`** final fallback

## Supported Environment Variables

### File Paths
- `DDOS_METRICS_FILE` - Path to metrics output file
- `DDOS_BLOCKED_IPS_FILE` - Path to blocked IPs list
- `DDOS_RATE_LIMITED_IPS_FILE` - Path to rate-limited IPs list
- `SNORT_DATA_DIR` - Fallback directory for all files

### Examples

#### Method 1: Environment Variables
```bash
# Set environment variables
export DDOS_METRICS_FILE="/var/log/ddos/metrics.json"
export DDOS_BLOCKED_IPS_FILE="/var/log/ddos_inspector/blocked_ips.log"
export DDOS_RATE_LIMITED_IPS_FILE="/var/log/ddos_inspector/rate_limited_ips.log"

# Run Snort
snort -c snort.conf
```

#### Method 2: .env File
Create a `.env` file in your working directory:

```bash
# DDoS Inspector Configuration
DDOS_METRICS_FILE=/var/log/ddos/metrics.json
DDOS_BLOCKED_IPS_FILE=/var/log/ddos_inspector/blocked_ips.log
DDOS_RATE_LIMITED_IPS_FILE=/var/log/ddos_inspector/rate_limited_ips.log

# Optional: Set Snort data directory
SNORT_DATA_DIR=/var/log/snort
```

#### Method 3: Snort Configuration
In your `snort.conf` or Lua configuration:

```lua
-- Option 1: Use environment variables (default behavior)
ddos_inspector = {
    use_env_files = true,  -- Enable .env file support (default)
    -- Files will be automatically read from environment
}

-- Option 2: Disable environment support
ddos_inspector = {
    use_env_files = false,  -- Disable environment variable support
    metrics_file = "/explicit/path/metrics.json",
    blocked_ips_file = "/var/log/ddos_inspector/blocked_ips.log",
    rate_limited_ips_file = "/var/log/ddos_inspector/rate_limited_ips.log"
}

-- Option 3: Mix explicit and environment
ddos_inspector = {
    use_env_files = true,
    metrics_file = "/explicit/path/metrics.json",  -- This overrides environment
    -- blocked_ips_file and rate_limited_ips_file will use environment
}
```

## Docker Configuration

### Docker Compose Example
```yaml
version: '3.8'
services:
  snort-ddos:
    image: snort:latest
    environment:
      - DDOS_METRICS_FILE=/data/ddos_metrics.json
      - DDOS_BLOCKED_IPS_FILE=/var/log/ddos_inspector/blocked_ips.log
      - DDOS_RATE_LIMITED_IPS_FILE=/var/log/ddos_inspector/rate_limited_ips.log
      - SNORT_DATA_DIR=/data
    volumes:
      - ./data:/data
      - ./config:/config
    command: snort -c /config/snort.conf
```

### Dockerfile Example
```dockerfile
FROM snort:latest

# Set default environment variables
ENV DDOS_METRICS_FILE=/var/log/ddos/metrics.json
ENV DDOS_BLOCKED_IPS_FILE=/var/log/ddos_inspector/blocked_ips.log
ENV DDOS_RATE_LIMITED_IPS_FILE=/var/log/ddos_inspector/rate_limited_ips.log
ENV SNORT_DATA_DIR=/var/log/snort

# Create directories
RUN mkdir -p /var/log/ddos /var/log/snort

# Copy configuration
COPY snort.conf /etc/snort/

CMD ["snort", "-c", "/etc/snort/snort.conf"]
```

## Kubernetes Configuration

### ConfigMap Example
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ddos-inspector-config
data:
  DDOS_METRICS_FILE: "/data/ddos_metrics.json"
  DDOS_BLOCKED_IPS_FILE: "/data/blocked_ips.txt" 
  DDOS_RATE_LIMITED_IPS_FILE: "/data/rate_limited_ips.txt"
  SNORT_DATA_DIR: "/data"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: snort-ddos
spec:
  replicas: 1
  selector:
    matchLabels:
      app: snort-ddos
  template:
    metadata:
      labels:
        app: snort-ddos
    spec:
      containers:
      - name: snort
        image: snort:latest
        envFrom:
        - configMapRef:
            name: ddos-inspector-config
        volumeMounts:
        - name: data
          mountPath: /data
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: snort-data
```

## Security Considerations

### Allowed Path Prefixes
For security, file paths are restricted to these prefixes:
- `/var/log/ddos_inspector/`
- `/tmp/ddos_inspector/`
- `/home/` (for development)
- `/opt/ddos_inspector/`

### Path Validation
- No directory traversal (`..`) allowed
- No double slashes (`//`) allowed
- Directories are automatically created if they don't exist

## Troubleshooting

### Check Current Configuration
The DDoS Inspector logs its active configuration on startup:

```
DDoS Inspector: Applying configuration profile: default
DDoS Inspector: - Using metrics file: /var/log/ddos/metrics.json (from DDOS_METRICS_FILE)
DDoS Inspector: - Using blocked IPs file: /var/log/ddos/blocked.txt (from .env file)
DDoS Inspector: - Using rate limited IPs file: /tmp/ddos_inspector_rate_limited_ips.txt (fallback)
```

### Common Issues

1. **Permission Denied**
   - Ensure Snort has write permissions to the target directories
   - Check SELinux/AppArmor policies if applicable

2. **File Not Found**
   - Verify the directory exists or can be created
   - Check the `SNORT_DATA_DIR` environment variable

3. **Invalid Path**
   - Ensure paths use allowed prefixes
   - Avoid special characters and directory traversal

### Debug Environment Loading
Set log level to debug to see environment variable resolution:

```lua
ddos_inspector = {
    log_level = "debug",
    use_env_files = true
}
```

This will show detailed information about which environment variables are being read and from where.
