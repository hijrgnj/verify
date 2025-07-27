# 🛡️ Advanced Discord Verification System

A comprehensive verification system that detects VPNs, logs hardware IDs, tracks user fingerprints, and prevents duplicate accounts from joining your Discord server.

## 🌟 Features

### 🔒 Security Features
- **VPN/Proxy Detection**: Multi-service VPN detection using various APIs
- **Hardware ID Tracking**: Unique device fingerprinting to prevent duplicate accounts
- **Browser Fingerprinting**: Canvas, WebGL, and audio fingerprinting
- **Spoofing Detection**: Detects attempts to manipulate browser data
- **Automation Detection**: Identifies headless browsers and automation tools
- **Risk Assessment**: Automated scoring system to evaluate user trustworthiness

### 📊 Discord Bot Features
- **Invite Tracking**: Track which invites are used by new members
- **Duplicate Detection**: Automatically kick users with matching hardware IDs
- **Data Export**: Export all verification data (owner/whitelisted only)
- **Configuration System**: Extensive settings for customization
- **Real-time Logging**: Comprehensive security event logging
- **Tutorial System**: Built-in setup guide and help commands

## 🚀 Quick Start

### 1. GitHub Pages Setup

1. **Fork this repository** or create a new repository
2. **Enable GitHub Pages** in repository settings
3. **Upload the website files**:
   - `index.html`
   - `styles.css` 
   - `verification.js`

4. **Configure the website**:
   - Edit `verification.js`
   - Replace `YOUR_DISCORD_WEBHOOK_URL_HERE` with your Discord webhook URL
   - Optionally add VPN API keys for enhanced detection

### 2. Discord Bot Setup

1. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Create a Discord Bot**:
   - Go to [Discord Developer Portal](https://discord.com/developers/applications)
   - Create a new application and bot
   - Copy the bot token

3. **Configure the bot**:
   - Edit `discord_bot.py`
   - Replace `YOUR_BOT_TOKEN_HERE` with your bot token
   - Replace `YOUR_GITHUB_PAGES_URL_HERE` with your GitHub Pages URL

4. **Set up Discord Webhook**:
   - Create a webhook in your Discord server
   - Use this webhook URL in the website configuration

5. **Run the bot**:
   ```bash
   python discord_bot.py
   ```

### 3. Server Configuration

1. **Invite the bot** to your server with Administrator permissions
2. **Run setup command**: `!setup`
3. **Configure channels**:
   ```
   !set_channel #verification
   !set_logs #security-logs
   ```
4. **Get verification URL**: `!verification_url`
5. **Configure settings**: `!config`

## 📋 Commands

### 🔧 Setup Commands
- `!setup` - Initialize bot for your server
- `!tutorial` - Complete setup tutorial
- `!set_channel #channel` - Set verification channel
- `!set_logs #channel` - Set log channel

### ⚙️ Configuration Commands
- `!config` - Show configuration menu
- `!config auto_kick true/false` - Enable/disable auto-kick for duplicates
- `!config risk_threshold <0-100>` - Set risk threshold for blocking
- `!config invite_tracking true/false` - Enable/disable invite tracking
- `!config welcome_message "text"` - Set custom welcome message

### 📊 Monitoring Commands
- `!stats` - View verification statistics
- `!check_user @user` - Check user's verification status
- `!verification_url` - Get your verification URL
- `!settings` - View current server settings

### 🔐 Admin Commands
- `!export_data` - Export all verification data (Owner/Whitelisted only)
- `!whitelist @user` - Whitelist user for data export (Owner only)

## 🔧 Configuration

### Website Configuration

Edit `verification.js` to configure:

```javascript
class SecurityVerification {
    constructor() {
        // Replace with your Discord webhook URL
        this.discordWebhookUrl = 'https://discord.com/api/webhooks/YOUR_WEBHOOK_URL';
        
        // Optional: Add VPN detection API key
        this.vpnApiKey = 'YOUR_VPN_API_KEY';
    }
}
```

### Bot Configuration

Edit `discord_bot.py` to configure:

```python
class VerificationBot(commands.Bot):
    def __init__(self):
        # Bot configuration
        self.verification_url = "https://yourusername.github.io/verification"
        self.owner_id = 945344266404782140  # Your Discord user ID
        
        # Other settings...
```

## 🛡️ Security Settings

### Risk Scoring System

The system assigns risk scores based on:
- **VPN/Proxy Detection**: +40 points
- **Automation Tools**: +30 points
- **Headless Browser**: +25 points
- **Spoofing Attempts**: +20 points
- **Browser Modifications**: +15 points
- **Developer Tools**: +10 points

### Default Thresholds
- **Block Threshold**: 70+ (configurable)
- **Auto-kick Duplicates**: Enabled (configurable)
- **Data Retention**: 30 days (configurable)

## 📊 Data Collection

The system collects comprehensive data including:

### Hardware Information
- Hardware ID (HWID) generated from device characteristics
- Screen resolution and color depth
- CPU cores and memory information
- Device pixel ratio and touch capabilities

### Browser Fingerprinting
- Canvas fingerprint
- WebGL renderer information
- Audio context fingerprint
- Font detection
- Plugin enumeration

### Network Information
- IP address and geolocation
- VPN/Proxy detection results
- WebRTC leak detection
- DNS over HTTPS detection

### System Information
- Operating system and platform
- Browser version and capabilities
- Language and timezone settings
- Performance metrics

## 🔐 Privacy & Security

### Data Encryption
- Sensitive data is encrypted using Fernet (AES 128)
- Hardware IDs are hashed using SHA-256
- Database includes encrypted backup of full verification data

### Data Access
- Only the bot owner (ID: 945344266404782140) can export data by default
- Whitelist system allows authorized users to access data
- All data access is logged with timestamps

### Data Retention
- Verification data is automatically cleaned up after 30 days
- Blocked attempts are logged for security analysis
- Invite tracking data is preserved for audit purposes

## 🚨 How It Works

1. **User joins server** → Bot sends verification link
2. **User visits website** → Comprehensive security analysis begins
3. **Data collection** → Hardware ID, fingerprints, network analysis
4. **Risk assessment** → Automated scoring based on security flags
5. **Decision making** → Block high-risk users, allow legitimate users
6. **Duplicate detection** → Check hardware ID against existing users
7. **Action taken** → Auto-kick duplicates or flag for manual review

## 🛠️ Troubleshooting

### Common Issues

**Bot not responding**:
- Check bot token is correct
- Ensure bot has Administrator permissions
- Verify bot is online in Discord

**Verification not working**:
- Check Discord webhook URL is correct
- Ensure GitHub Pages is enabled and accessible
- Verify webhook server is running (port 8080)

**Data not saving**:
- Check database file permissions
- Ensure SQLite is properly installed
- Verify encryption key is generated

### Debug Mode

Enable debug logging in the bot:
```python
logging.basicConfig(level=logging.DEBUG)
```

## 📈 Statistics Dashboard

The bot provides comprehensive statistics:
- Total verifications completed
- Blocked attempts and reasons
- Average risk scores
- Invite usage tracking
- Duplicate detection events

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This verification system is designed for legitimate security purposes. Users should be informed about data collection and comply with applicable privacy laws (GDPR, CCPA, etc.). The system should not be used to collect data without proper consent and legal basis.

## 🆘 Support

For support and questions:
- Create an issue in this repository
- Contact the bot owner
- Check the troubleshooting section

---

**Made with ❤️ for Discord server security**
