import discord
from discord.ext import commands, tasks
import aiohttp
import asyncio
import json
import sqlite3
import hashlib
import datetime
from typing import Dict, List, Optional
import logging
import os
from cryptography.fernet import Fernet
import base64

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VerificationBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.members = True
        intents.guilds = True
        intents.invites = True
        
        super().__init__(
            command_prefix='!',
            intents=intents,
            help_command=None  # We'll create a custom help command
        )
        
        # Configuration
        self.verification_url = "YOUR_GITHUB_PAGES_URL_HERE"  # Replace with your GitHub Pages URL
        self.webhook_port = 8080
        self.database_path = "verification_data.db"
        self.encryption_key = self.generate_encryption_key()
        self.owner_id = 945344266404782140  # Bot owner ID
        
        # Data storage
        self.pending_verifications: Dict[str, Dict] = {}
        self.server_codes: Dict[int, str] = {}  # guild_id -> verification_code
        self.verified_users: Dict[int, List[str]] = {}  # guild_id -> [hwid_list]
        self.guild_invites: Dict[int, Dict[str, discord.Invite]] = {}  # guild_id -> {code: invite}
        self.whitelisted_users: List[int] = []  # Users who can export data
        
        # Initialize database
        self.init_database()
        
        # Start webhook server
        self.loop.create_task(self.start_webhook_server())

    def generate_encryption_key(self) -> bytes:
        """Generate or load encryption key for sensitive data"""
        key_file = "encryption.key"
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            return key

    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        f = Fernet(self.encryption_key)
        return f.encrypt(data.encode()).decode()

    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        f = Fernet(self.encryption_key)
        return f.decrypt(encrypted_data.encode()).decode()

    def init_database(self):
        """Initialize SQLite database for storing verification data"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                user_id TEXT NOT NULL,
                discord_id TEXT NOT NULL,
                hwid TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                user_agent TEXT NOT NULL,
                timestamp DATETIME NOT NULL,
                security_flags TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                status TEXT NOT NULL,
                encrypted_data TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER,
                ip_address TEXT NOT NULL,
                hwid TEXT NOT NULL,
                security_flags TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                timestamp DATETIME NOT NULL,
                user_agent TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS server_settings (
                guild_id INTEGER PRIMARY KEY,
                verification_code TEXT NOT NULL,
                verification_channel INTEGER,
                log_channel INTEGER,
                auto_kick BOOLEAN DEFAULT 1,
                risk_threshold INTEGER DEFAULT 70,
                invite_tracking BOOLEAN DEFAULT 1,
                welcome_message TEXT DEFAULT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS invite_tracking (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                invite_code TEXT NOT NULL,
                inviter_id INTEGER NOT NULL,
                inviter_name TEXT NOT NULL,
                used_by_id INTEGER NOT NULL,
                used_by_name TEXT NOT NULL,
                timestamp DATETIME NOT NULL,
                verification_status TEXT DEFAULT 'PENDING'
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS whitelisted_users (
                user_id INTEGER PRIMARY KEY,
                added_by INTEGER NOT NULL,
                added_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()

    async def on_ready(self):
        """Called when bot is ready"""
        logger.info(f'{self.user} has connected to Discord!')
        logger.info(f'Bot is in {len(self.guilds)} guilds')
        
        # Load server settings
        await self.load_server_settings()
        
        # Load whitelisted users
        await self.load_whitelisted_users()
        
        # Cache invites for all guilds
        await self.cache_invites()
        
        # Start periodic cleanup
        self.cleanup_old_data.start()

    async def load_server_settings(self):
        """Load server settings from database"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT guild_id, verification_code FROM server_settings')
        rows = cursor.fetchall()
        
        for guild_id, code in rows:
            self.server_codes[guild_id] = code
            
        conn.close()

    async def load_whitelisted_users(self):
        """Load whitelisted users from database"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT user_id FROM whitelisted_users')
        rows = cursor.fetchall()
        
        self.whitelisted_users = [row[0] for row in rows]
        
        conn.close()

    async def cache_invites(self):
        """Cache all guild invites for tracking"""
        for guild in self.guilds:
            try:
                invites = await guild.invites()
                self.guild_invites[guild.id] = {invite.code: invite for invite in invites}
            except discord.Forbidden:
                logger.warning(f"Cannot access invites for guild {guild.name} ({guild.id})")
            except Exception as e:
                logger.error(f"Error caching invites for guild {guild.name}: {e}")

    @tasks.loop(hours=24)
    async def cleanup_old_data(self):
        """Clean up old verification data"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Remove verification data older than 30 days
        cutoff_date = datetime.datetime.now() - datetime.timedelta(days=30)
        cursor.execute('DELETE FROM verifications WHERE timestamp < ?', (cutoff_date,))
        cursor.execute('DELETE FROM blocked_attempts WHERE timestamp < ?', (cutoff_date,))
        
        conn.commit()
        conn.close()
        
        logger.info("Cleaned up old verification data")

    @commands.command(name='help')
    async def help_command(self, ctx):
        """Custom help command with setup tutorial"""
        embed = discord.Embed(
            title="🛡️ Verification Bot Help",
            description="Advanced verification system to protect your Discord server",
            color=0x667eea
        )
        
        embed.add_field(
            name="📋 Setup Tutorial",
            value="""
            **Step 1:** Use `!setup` to initialize the bot for your server
            **Step 2:** Set verification channel with `!set_channel #channel`
            **Step 3:** Configure log channel with `!set_logs #channel`
            **Step 4:** Share your verification URL with new members
            **Step 5:** Monitor logs and adjust settings as needed
            """,
            inline=False
        )
        
        embed.add_field(
            name="🔧 Commands",
            value="""
            `!setup` - Initialize bot for this server
            `!tutorial` - Complete setup tutorial
            `!config` - Server configuration menu
            `!set_channel #channel` - Set verification channel
            `!set_logs #channel` - Set log channel
            `!verification_url` - Get verification URL
            `!stats` - View verification statistics
            `!check_user @user` - Check user verification status
            `!settings` - View current server settings
            `!export_data` - Export verification data (Owner/Whitelisted)
            `!whitelist @user` - Whitelist user for data export (Owner only)
            """,
            inline=False
        )
        
        embed.add_field(
            name="🔒 Security Features",
            value="""
            ✅ VPN/Proxy Detection
            ✅ Hardware ID Tracking
            ✅ Browser Fingerprinting
            ✅ Duplicate Account Detection
            ✅ Spoofing Attempt Detection
            ✅ Automated Risk Assessment
            """,
            inline=False
        )
        
        embed.add_field(
            name="⚙️ Configuration",
            value="""
            **Risk Threshold:** Users with risk scores above this value are blocked
            **Auto Kick:** Automatically kick users detected as duplicates
            **Verification Channel:** Where users get verification instructions
            **Log Channel:** Where security events are logged
            """,
            inline=False
        )
        
        embed.add_field(
            name="🚨 How It Works",
            value="""
            1. New members join your server
            2. Bot sends them verification link
            3. They complete verification on secure webpage
            4. System analyzes their device fingerprint and network
            5. Bot checks for duplicate accounts using HWID matching
            6. Suspicious users are automatically handled based on settings
            """,
            inline=False
        )
        
        embed.set_footer(text="Need more help? Contact the bot developer")
        
        await ctx.send(embed=embed)

    @commands.command(name='setup')
    @commands.has_permissions(administrator=True)
    async def setup_server(self, ctx):
        """Initialize bot for the server"""
        guild_id = ctx.guild.id
        
        # Generate unique verification code for this server
        verification_code = hashlib.sha256(f"{guild_id}{datetime.datetime.now()}".encode()).hexdigest()[:16]
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Insert or update server settings
        cursor.execute('''
            INSERT OR REPLACE INTO server_settings 
            (guild_id, verification_code, verification_channel, log_channel) 
            VALUES (?, ?, ?, ?)
        ''', (guild_id, verification_code, ctx.channel.id, ctx.channel.id))
        
        conn.commit()
        conn.close()
        
        self.server_codes[guild_id] = verification_code
        
        embed = discord.Embed(
            title="✅ Server Setup Complete",
            description="Verification system has been initialized for this server!",
            color=0x00ff00
        )
        
        embed.add_field(
            name="🔑 Server Verification Code",
            value=f"`{verification_code}`",
            inline=False
        )
        
        embed.add_field(
            name="🔗 Verification URL",
            value=f"{self.verification_url}?server={verification_code}",
            inline=False
        )
        
        embed.add_field(
            name="📋 Next Steps",
            value="""
            1. Set verification channel: `!set_channel #channel`
            2. Set log channel: `!set_logs #channel`
            3. Share verification URL with new members
            """,
            inline=False
        )
        
        await ctx.send(embed=embed)

    @commands.command(name='set_channel')
    @commands.has_permissions(administrator=True)
    async def set_verification_channel(self, ctx, channel: discord.TextChannel):
        """Set the verification channel"""
        guild_id = ctx.guild.id
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute(
            'UPDATE server_settings SET verification_channel = ? WHERE guild_id = ?',
            (channel.id, guild_id)
        )
        
        conn.commit()
        conn.close()
        
        embed = discord.Embed(
            title="✅ Verification Channel Set",
            description=f"Verification channel set to {channel.mention}",
            color=0x00ff00
        )
        
        await ctx.send(embed=embed)

    @commands.command(name='set_logs')
    @commands.has_permissions(administrator=True)
    async def set_log_channel(self, ctx, channel: discord.TextChannel):
        """Set the log channel"""
        guild_id = ctx.guild.id
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute(
            'UPDATE server_settings SET log_channel = ? WHERE guild_id = ?',
            (channel.id, guild_id)
        )
        
        conn.commit()
        conn.close()
        
        embed = discord.Embed(
            title="✅ Log Channel Set",
            description=f"Log channel set to {channel.mention}",
            color=0x00ff00
        )
        
        await ctx.send(embed=embed)

    @commands.command(name='verification_url')
    @commands.has_permissions(administrator=True)
    async def get_verification_url(self, ctx):
        """Get the verification URL for this server"""
        guild_id = ctx.guild.id
        
        if guild_id not in self.server_codes:
            await ctx.send("❌ Server not set up! Use `!setup` first.")
            return
        
        verification_code = self.server_codes[guild_id]
        url = f"{self.verification_url}?server={verification_code}"
        
        embed = discord.Embed(
            title="🔗 Verification URL",
            description=f"Share this URL with new members:\n{url}",
            color=0x667eea
        )
        
        await ctx.send(embed=embed)

    @commands.command(name='stats')
    @commands.has_permissions(administrator=True)
    async def verification_stats(self, ctx):
        """Show verification statistics"""
        guild_id = ctx.guild.id
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Get verification stats
        cursor.execute(
            'SELECT COUNT(*) FROM verifications WHERE guild_id = ? AND status = "VERIFIED"',
            (guild_id,)
        )
        verified_count = cursor.fetchone()[0]
        
        cursor.execute(
            'SELECT COUNT(*) FROM blocked_attempts WHERE guild_id = ?',
            (guild_id,)
        )
        blocked_count = cursor.fetchone()[0]
        
        cursor.execute(
            'SELECT AVG(risk_score) FROM verifications WHERE guild_id = ?',
            (guild_id,)
        )
        avg_risk = cursor.fetchone()[0] or 0
        
        conn.close()
        
        embed = discord.Embed(
            title="📊 Verification Statistics",
            color=0x667eea
        )
        
        embed.add_field(name="✅ Verified Users", value=str(verified_count), inline=True)
        embed.add_field(name="🚫 Blocked Attempts", value=str(blocked_count), inline=True)
        embed.add_field(name="📈 Average Risk Score", value=f"{avg_risk:.1f}", inline=True)
        
        await ctx.send(embed=embed)

    @commands.command(name='check_user')
    @commands.has_permissions(administrator=True)
    async def check_user_verification(self, ctx, user: discord.Member):
        """Check a user's verification status"""
        guild_id = ctx.guild.id
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT discord_id, hwid, risk_score, timestamp, security_flags 
            FROM verifications 
            WHERE guild_id = ? AND discord_id = ? AND status = "VERIFIED"
            ORDER BY timestamp DESC LIMIT 1
        ''', (guild_id, str(user.id)))
        
        result = cursor.fetchone()
        
        if result:
            discord_id, hwid, risk_score, timestamp, security_flags = result
            
            embed = discord.Embed(
                title=f"🔍 Verification Status: {user.display_name}",
                color=0x00ff00 if risk_score < 50 else 0xff9900 if risk_score < 80 else 0xff0000
            )
            
            embed.add_field(name="✅ Status", value="Verified", inline=True)
            embed.add_field(name="📊 Risk Score", value=f"{risk_score}/100", inline=True)
            embed.add_field(name="🕒 Verified At", value=timestamp, inline=True)
            embed.add_field(name="🔒 HWID", value=hwid[:16] + "...", inline=True)
            embed.add_field(name="⚠️ Security Flags", value=security_flags or "None", inline=False)
            
        else:
            embed = discord.Embed(
                title=f"❌ Verification Status: {user.display_name}",
                description="User is not verified",
                color=0xff0000
            )
        
        conn.close()
        await ctx.send(embed=embed)

    @commands.command(name='risk_threshold')
    @commands.has_permissions(administrator=True)
    async def set_risk_threshold(self, ctx, threshold: int):
        """Set the risk threshold for blocking users"""
        if not 0 <= threshold <= 100:
            await ctx.send("❌ Risk threshold must be between 0 and 100")
            return
        
        guild_id = ctx.guild.id
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute(
            'UPDATE server_settings SET risk_threshold = ? WHERE guild_id = ?',
            (threshold, guild_id)
        )
        
        conn.commit()
        conn.close()
        
        embed = discord.Embed(
            title="✅ Risk Threshold Updated",
            description=f"Risk threshold set to {threshold}",
            color=0x00ff00
        )
        
        await ctx.send(embed=embed)

    async def on_member_join(self, member):
        """Handle new member joins"""
        guild_id = member.guild.id
        
        if guild_id not in self.server_codes:
            return  # Server not set up
        
        # Get verification channel
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT verification_channel FROM server_settings WHERE guild_id = ?',
            (guild_id,)
        )
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return
        
        verification_channel_id = result[0]
        channel = self.get_channel(verification_channel_id)
        
        if not channel:
            return
        
        verification_code = self.server_codes[guild_id]
        verification_url = f"{self.verification_url}?server={verification_code}"
        
        embed = discord.Embed(
            title=f"🛡️ Welcome {member.display_name}!",
            description="Please complete verification to access the server",
            color=0x667eea
        )
        
        embed.add_field(
            name="🔗 Verification Link",
            value=f"[Click here to verify]({verification_url})",
            inline=False
        )
        
        embed.add_field(
            name="📋 Instructions",
            value="""
            1. Click the verification link above
            2. Complete the security checks
            3. Enter your Discord User ID and server code
            4. Wait for verification to complete
            """,
            inline=False
        )
        
        embed.add_field(
            name="ℹ️ Your Discord User ID",
            value=f"`{member.id}`",
            inline=True
        )
        
        embed.add_field(
            name="🔑 Server Code",
            value=f"`{verification_code}`",
            inline=True
        )
        
        embed.set_footer(text="This verification helps protect the server from malicious users")
        
        try:
            await member.send(embed=embed)
        except discord.Forbidden:
            # If we can't DM the user, send to verification channel
            await channel.send(f"{member.mention}", embed=embed)

    async def handle_verification_webhook(self, data):
        """Handle incoming verification data from webhook"""
        try:
            event_type = data.get('event')
            user_data = data.get('userData', {})
            security_flags = data.get('securityFlags', [])
            
            if event_type == 'BLOCKED':
                await self.handle_blocked_attempt(data)
            elif event_type == 'VERIFIED':
                await self.handle_successful_verification(data)
                
        except Exception as e:
            logger.error(f"Error handling webhook data: {e}")

    async def handle_blocked_attempt(self, data):
        """Handle blocked verification attempt"""
        user_data = data.get('userData', {})
        security_flags = data.get('securityFlags', [])
        
        # Store blocked attempt
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO blocked_attempts 
            (ip_address, hwid, security_flags, risk_score, timestamp, user_agent)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            user_data.get('ip', ''),
            user_data.get('hwid', ''),
            json.dumps(security_flags),
            user_data.get('riskScore', 0),
            datetime.datetime.now(),
            user_data.get('userAgent', '')
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Blocked verification attempt: {security_flags}")

    async def handle_successful_verification(self, data):
        """Handle successful verification"""
        user_data = data.get('userData', {})
        security_flags = data.get('securityFlags', [])
        
        discord_id = user_data.get('discordId')
        server_code = user_data.get('serverCode')
        hwid = user_data.get('hwid')
        
        if not all([discord_id, server_code, hwid]):
            logger.error("Missing required verification data")
            return
        
        # Find guild by server code
        guild_id = None
        for gid, code in self.server_codes.items():
            if code == server_code:
                guild_id = gid
                break
        
        if not guild_id:
            logger.error(f"Unknown server code: {server_code}")
            return
        
        guild = self.get_guild(guild_id)
        if not guild:
            logger.error(f"Guild not found: {guild_id}")
            return
        
        # Check for duplicate HWID
        duplicate_user = await self.check_duplicate_hwid(guild_id, hwid, discord_id)
        
        if duplicate_user:
            await self.handle_duplicate_detection(guild, discord_id, duplicate_user, hwid)
            return
        
        # Store verification data
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        encrypted_data = self.encrypt_data(json.dumps(user_data))
        
        cursor.execute('''
            INSERT INTO verifications 
            (guild_id, user_id, discord_id, hwid, ip_address, fingerprint, user_agent, 
             timestamp, security_flags, risk_score, status, encrypted_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            guild_id,
            user_data.get('sessionId', ''),
            discord_id,
            hwid,
            user_data.get('ip', ''),
            user_data.get('fingerprintHash', ''),
            user_data.get('userAgent', ''),
            datetime.datetime.now(),
            json.dumps(security_flags),
            user_data.get('riskScore', 0),
            'VERIFIED',
            encrypted_data
        ))
        
        conn.commit()
        conn.close()
        
        # Log successful verification
        await self.log_verification_event(guild, discord_id, user_data, security_flags, 'VERIFIED')
        
        logger.info(f"Successful verification for user {discord_id} in guild {guild_id}")

    async def check_duplicate_hwid(self, guild_id: int, hwid: str, current_discord_id: str) -> Optional[str]:
        """Check if HWID already exists for a different user"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT discord_id FROM verifications 
            WHERE guild_id = ? AND hwid = ? AND discord_id != ? AND status = "VERIFIED"
            ORDER BY timestamp DESC LIMIT 1
        ''', (guild_id, hwid, current_discord_id))
        
        result = cursor.fetchone()
        conn.close()
        
        return result[0] if result else None

    async def handle_duplicate_detection(self, guild: discord.Guild, new_discord_id: str, 
                                       existing_discord_id: str, hwid: str):
        """Handle duplicate HWID detection"""
        try:
            new_member = guild.get_member(int(new_discord_id))
            existing_member = guild.get_member(int(existing_discord_id))
            
            # Get server settings
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute(
                'SELECT auto_kick, log_channel FROM server_settings WHERE guild_id = ?',
                (guild.id,)
            )
            result = cursor.fetchone()
            conn.close()
            
            auto_kick, log_channel_id = result if result else (True, None)
            
            # Create log embed
            embed = discord.Embed(
                title="🚨 Duplicate Account Detected",
                description="Same hardware fingerprint detected for multiple accounts",
                color=0xff0000,
                timestamp=datetime.datetime.now()
            )
            
            embed.add_field(
                name="👤 New Account",
                value=f"{new_member.mention if new_member else 'Unknown'} ({new_discord_id})",
                inline=True
            )
            
            embed.add_field(
                name="👤 Existing Account", 
                value=f"{existing_member.mention if existing_member else 'Unknown'} ({existing_discord_id})",
                inline=True
            )
            
            embed.add_field(
                name="🔒 Hardware ID",
                value=hwid[:16] + "...",
                inline=True
            )
            
            # Auto-kick if enabled
            if auto_kick and new_member:
                try:
                    await new_member.kick(reason="Duplicate account detected (same HWID)")
                    embed.add_field(
                        name="⚡ Action Taken",
                        value="User automatically kicked",
                        inline=False
                    )
                except discord.Forbidden:
                    embed.add_field(
                        name="❌ Action Failed",
                        value="Unable to kick user (insufficient permissions)",
                        inline=False
                    )
            else:
                embed.add_field(
                    name="⚠️ Action Required",
                    value="Manual review recommended",
                    inline=False
                )
            
            # Send to log channel
            if log_channel_id:
                log_channel = guild.get_channel(log_channel_id)
                if log_channel:
                    await log_channel.send(embed=embed)
            
            logger.info(f"Duplicate HWID detected in guild {guild.id}: {new_discord_id} matches {existing_discord_id}")
            
        except Exception as e:
            logger.error(f"Error handling duplicate detection: {e}")

    async def log_verification_event(self, guild: discord.Guild, discord_id: str, 
                                   user_data: dict, security_flags: list, event_type: str):
        """Log verification events to the designated channel"""
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute(
                'SELECT log_channel FROM server_settings WHERE guild_id = ?',
                (guild.id,)
            )
            result = cursor.fetchone()
            conn.close()
            
            if not result or not result[0]:
                return
            
            log_channel = guild.get_channel(result[0])
            if not log_channel:
                return
            
            member = guild.get_member(int(discord_id))
            
            embed = discord.Embed(
                title=f"🔒 Verification Event: {event_type}",
                timestamp=datetime.datetime.now()
            )
            
            if event_type == 'VERIFIED':
                embed.color = 0x00ff00
                embed.add_field(
                    name="👤 User",
                    value=f"{member.mention if member else 'Unknown'} ({discord_id})",
                    inline=True
                )
            else:
                embed.color = 0xff0000
            
            embed.add_field(
                name="📊 Risk Score",
                value=f"{user_data.get('riskScore', 0)}/100",
                inline=True
            )
            
            embed.add_field(
                name="🌐 IP Address",
                value=user_data.get('ip', 'Unknown'),
                inline=True
            )
            
            if security_flags:
                embed.add_field(
                    name="⚠️ Security Flags",
                    value='\n'.join([f"• {flag}" for flag in security_flags[:5]]),
                    inline=False
                )
            
            embed.add_field(
                name="🔒 Hardware ID",
                value=user_data.get('hwid', 'Unknown')[:16] + "...",
                inline=True
            )
            
            await log_channel.send(embed=embed)
            
        except Exception as e:
            logger.error(f"Error logging verification event: {e}")

    async def start_webhook_server(self):
        """Start webhook server to receive verification data"""
        from aiohttp import web
        
        async def webhook_handler(request):
            try:
                data = await request.json()
                await self.handle_verification_webhook(data)
                return web.Response(text="OK")
            except Exception as e:
                logger.error(f"Webhook error: {e}")
                return web.Response(text="Error", status=500)
        
        app = web.Application()
        app.router.add_post('/webhook', webhook_handler)
        
        runner = web.AppRunner(app)
        await runner.setup()
        
        site = web.TCPSite(runner, 'localhost', self.webhook_port)
        await site.start()
        
        logger.info(f"Webhook server started on port {self.webhook_port}")

# Bot token and configuration
BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"  # Replace with your bot token

if __name__ == "__main__":
    bot = VerificationBot()
    
    try:
        bot.run(BOT_TOKEN)
    except KeyboardInterrupt:
        logger.info("Bot stopped by user")
    except Exception as e:
        logger.error(f"Bot error: {e}")