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
        self.ip_bans: Dict[int, List[str]] = {}  # guild_id -> [banned_ips]
        
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
                verified_role_id INTEGER DEFAULT NULL,
                unverified_role_id INTEGER DEFAULT NULL,
                auto_role BOOLEAN DEFAULT 1,
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
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_bans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                banned_user_id TEXT,
                banned_user_name TEXT,
                reason TEXT NOT NULL,
                banned_by INTEGER NOT NULL,
                banned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(guild_id, ip_address)
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
        
        # Load IP bans
        await self.load_ip_bans()
        
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

    async def load_ip_bans(self):
        """Load IP bans from database"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT guild_id, ip_address FROM ip_bans')
        rows = cursor.fetchall()
        
        for guild_id, ip_address in rows:
            if guild_id not in self.ip_bans:
                self.ip_bans[guild_id] = []
            self.ip_bans[guild_id].append(ip_address)
        
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
            `!setup_roles` - Create verification roles automatically
            `!set_verified_role @role` - Set verified user role
            `!set_unverified_role @role` - Set unverified user role
            `!toggle_autorole` - Toggle automatic role assignment
            `!verification_url` - Get verification URL
            `!stats` - View verification statistics
            `!invites` - View invite tracking statistics
            `!check_user @user` - Check user verification status
            `!generate_verification [@user]` - Generate verification in current channel
            `!quick_verify @user` - Quick verification generation
            `!mass_verify @user1 @user2...` - Generate for multiple users
            `!verification_panel` - Create permanent verification panel
            `!send_verification @user` - Send verification via DM
            `!ipban @user` - Ban user's IP address
            `!ipunban <ip>` - Remove IP ban
            `!ipbans` - List all IP bans
            `!checkip <ip>` - Check IP status and users
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

    @commands.command(name='tutorial')
    async def tutorial_command(self, ctx):
        """Complete setup tutorial with step-by-step guide"""
        embed = discord.Embed(
            title="📚 Complete Setup Tutorial",
            description="Follow this step-by-step guide to set up the verification system",
            color=0x667eea
        )
        
        embed.add_field(
            name="🚀 Step 1: Initialize the Bot",
            value="""
            Run the command: `!setup`
            This creates your server's unique verification code and sets up the database.
            """,
            inline=False
        )
        
        embed.add_field(
            name="📝 Step 2: Configure Channels & Roles",
            value="""
            • Set verification channel: `!set_channel #verification`
            • Set log channel: `!set_logs #security-logs`
            • Create verification roles: `!setup_roles`
            
            The verification channel is where new members will see verification instructions.
            The log channel is where all security events will be recorded.
            The roles help manage verified/unverified members automatically.
            """,
            inline=False
        )
        
        embed.add_field(
            name="🔗 Step 3: Get Your Verification URL",
            value="""
            Use `!verification_url` to get your unique verification link.
            This link will be automatically sent to new members when they join.
            """,
            inline=False
        )
        
        embed.add_field(
            name="⚙️ Step 4: Configure Settings",
            value="""
            • Adjust risk threshold: `!config risk_threshold 75`
            • Enable/disable auto-kick: `!config auto_kick true`
            • Set welcome message: `!config welcome_message "Welcome!"`
            • Toggle invite tracking: `!config invite_tracking true`
            • Enable/disable auto-roles: `!config auto_role true`
            • Set custom roles: `!set_verified_role @Verified` / `!set_unverified_role @Unverified`
            """,
            inline=False
        )
        
        embed.add_field(
            name="🛡️ Step 5: Test the System",
            value="""
            1. Create a test invite and join with an alt account
            2. Or use `!generate_verification @user` to create verification in any channel
            3. Complete the verification process
            4. Check the logs to see if everything is working
            5. Use `!stats` to view verification statistics
            """,
            inline=False
        )
        
        embed.add_field(
            name="📊 Monitoring & Generation Commands",
            value="""
            • `!stats` - View verification statistics
            • `!check_user @user` - Check specific user's verification
            • `!generate_verification [@user]` - Generate verification in any channel
            • `!verification_panel` - Create permanent verification panel
            • `!quick_verify @user` - Quick verification for specific user
            • `!mass_verify @user1 @user2` - Generate for multiple users
            • `!export_data` - Export all verification data (Admin only)
            """,
            inline=False
        )
        
        embed.set_footer(text="Need help? Use !help for more commands")
        
        await ctx.send(embed=embed)

    @commands.command(name='config')
    @commands.has_permissions(administrator=True)
    async def config_command(self, ctx, setting: str = None, value: str = None):
        """Interactive configuration menu"""
        guild_id = ctx.guild.id
        
        if not setting:
            # Show configuration menu
            embed = discord.Embed(
                title="⚙️ Server Configuration",
                description="Use `!config <setting> <value>` to change settings",
                color=0x667eea
            )
            
            # Get current settings
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT verification_channel, log_channel, auto_kick, risk_threshold, 
                       invite_tracking, welcome_message, verified_role_id, unverified_role_id, auto_role
                FROM server_settings WHERE guild_id = ?
            ''', (guild_id,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                ver_ch, log_ch, auto_kick, risk_thresh, inv_track, welcome_msg, verified_role_id, unverified_role_id, auto_role = result
                
                verified_role = ctx.guild.get_role(verified_role_id) if verified_role_id else None
                unverified_role = ctx.guild.get_role(unverified_role_id) if unverified_role_id else None
                
                embed.add_field(
                    name="📋 Available Settings",
                    value=f"""
                    **verification_channel** - Current: {f'<#{ver_ch}>' if ver_ch else 'Not set'}
                    **log_channel** - Current: {f'<#{log_ch}>' if log_ch else 'Not set'}
                    **auto_kick** - Current: {'Enabled' if auto_kick else 'Disabled'}
                    **risk_threshold** - Current: {risk_thresh}
                    **invite_tracking** - Current: {'Enabled' if inv_track else 'Disabled'}
                    **welcome_message** - Current: {welcome_msg or 'Default'}
                    **auto_role** - Current: {'Enabled' if auto_role else 'Disabled'}
                    **verified_role** - Current: {verified_role.mention if verified_role else 'Not set'}
                    **unverified_role** - Current: {unverified_role.mention if unverified_role else 'Not set'}
                    """,
                    inline=False
                )
                
                embed.add_field(
                    name="📝 Usage Examples",
                    value="""
                    `!config auto_kick false` - Disable auto-kick
                    `!config risk_threshold 80` - Set risk threshold to 80
                    `!config welcome_message "Welcome to our server!"` - Set custom welcome
                    """,
                    inline=False
                )
            
            await ctx.send(embed=embed)
            return
        
        # Handle specific setting changes
        setting = setting.lower()
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        if setting == 'auto_kick':
            auto_kick = value.lower() in ['true', '1', 'yes', 'on', 'enable']
            cursor.execute(
                'UPDATE server_settings SET auto_kick = ? WHERE guild_id = ?',
                (auto_kick, guild_id)
            )
            await ctx.send(f"✅ Auto-kick {'enabled' if auto_kick else 'disabled'}")
            
        elif setting == 'risk_threshold':
            try:
                threshold = int(value)
                if 0 <= threshold <= 100:
                    cursor.execute(
                        'UPDATE server_settings SET risk_threshold = ? WHERE guild_id = ?',
                        (threshold, guild_id)
                    )
                    await ctx.send(f"✅ Risk threshold set to {threshold}")
                else:
                    await ctx.send("❌ Risk threshold must be between 0 and 100")
            except ValueError:
                await ctx.send("❌ Risk threshold must be a number")
                
        elif setting == 'invite_tracking':
            inv_track = value.lower() in ['true', '1', 'yes', 'on', 'enable']
            cursor.execute(
                'UPDATE server_settings SET invite_tracking = ? WHERE guild_id = ?',
                (inv_track, guild_id)
            )
            await ctx.send(f"✅ Invite tracking {'enabled' if inv_track else 'disabled'}")
            
        elif setting == 'welcome_message':
            cursor.execute(
                'UPDATE server_settings SET welcome_message = ? WHERE guild_id = ?',
                (value, guild_id)
            )
            await ctx.send(f"✅ Welcome message updated")
            
        elif setting == 'auto_role':
            auto_role = value.lower() in ['true', '1', 'yes', 'on', 'enable']
            cursor.execute(
                'UPDATE server_settings SET auto_role = ? WHERE guild_id = ?',
                (auto_role, guild_id)
            )
            await ctx.send(f"✅ Auto-role {'enabled' if auto_role else 'disabled'}")
            
        else:
            await ctx.send("❌ Unknown setting. Use `!config` to see available options.")
        
        conn.commit()
        conn.close()

    @commands.command(name='export_data')
    async def export_data(self, ctx):
        """Export all verification data (Owner and whitelisted users only)"""
        user_id = ctx.author.id
        
        # Check if user is owner or whitelisted
        if user_id != self.owner_id and user_id not in self.whitelisted_users:
            await ctx.send("❌ You don't have permission to export data. Contact the bot owner for access.")
            return
        
        try:
            guild_id = ctx.guild.id
            
            # Collect all data
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            export_data = {
                'export_info': {
                    'timestamp': datetime.datetime.now().isoformat(),
                    'guild_id': guild_id,
                    'guild_name': ctx.guild.name,
                    'exported_by': str(ctx.author),
                    'exported_by_id': user_id
                },
                'verifications': [],
                'blocked_attempts': [],
                'invite_tracking': [],
                'server_settings': {}
            }
            
            # Get verifications
            cursor.execute('''
                SELECT * FROM verifications WHERE guild_id = ?
                ORDER BY timestamp DESC
            ''', (guild_id,))
            
            columns = [description[0] for description in cursor.description]
            for row in cursor.fetchall():
                verification = dict(zip(columns, row))
                # Decrypt sensitive data if needed
                try:
                    if verification['encrypted_data']:
                        verification['decrypted_data'] = json.loads(
                            self.decrypt_data(verification['encrypted_data'])
                        )
                except:
                    verification['decrypted_data'] = 'Failed to decrypt'
                export_data['verifications'].append(verification)
            
            # Get blocked attempts
            cursor.execute('''
                SELECT * FROM blocked_attempts WHERE guild_id = ?
                ORDER BY timestamp DESC
            ''', (guild_id,))
            
            columns = [description[0] for description in cursor.description]
            for row in cursor.fetchall():
                export_data['blocked_attempts'].append(dict(zip(columns, row)))
            
            # Get invite tracking
            cursor.execute('''
                SELECT * FROM invite_tracking WHERE guild_id = ?
                ORDER BY timestamp DESC
            ''', (guild_id,))
            
            columns = [description[0] for description in cursor.description]
            for row in cursor.fetchall():
                export_data['invite_tracking'].append(dict(zip(columns, row)))
            
            # Get server settings
            cursor.execute('''
                SELECT * FROM server_settings WHERE guild_id = ?
            ''', (guild_id,))
            
            result = cursor.fetchone()
            if result:
                columns = [description[0] for description in cursor.description]
                export_data['server_settings'] = dict(zip(columns, result))
            
            conn.close()
            
            # Create JSON file
            json_data = json.dumps(export_data, indent=2, default=str)
            
            # Send to user's DMs
            try:
                # Create file
                import io
                file_buffer = io.StringIO(json_data)
                file = discord.File(file_buffer, filename=f'verification_data_{guild_id}_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
                
                embed = discord.Embed(
                    title="📊 Verification Data Export",
                    description=f"Complete verification data for **{ctx.guild.name}**",
                    color=0x00ff00,
                    timestamp=datetime.datetime.now()
                )
                
                embed.add_field(
                    name="📈 Statistics",
                    value=f"""
                    **Verifications:** {len(export_data['verifications'])}
                    **Blocked Attempts:** {len(export_data['blocked_attempts'])}
                    **Invite Tracking:** {len(export_data['invite_tracking'])}
                    """,
                    inline=False
                )
                
                embed.set_footer(text="This data is sensitive - handle with care")
                
                await ctx.author.send(embed=embed, file=file)
                await ctx.send("✅ Verification data has been sent to your DMs")
                
            except discord.Forbidden:
                await ctx.send("❌ Could not send data to your DMs. Please enable DMs from server members.")
            
        except Exception as e:
            logger.error(f"Error exporting data: {e}")
            await ctx.send(f"❌ Error exporting data: {str(e)}")

    @commands.command(name='whitelist')
    async def whitelist_user(self, ctx, user: discord.Member):
        """Whitelist a user for data export (Owner only)"""
        if ctx.author.id != self.owner_id:
            await ctx.send("❌ Only the bot owner can whitelist users.")
            return
        
        user_id = user.id
        
        if user_id in self.whitelisted_users:
            await ctx.send(f"ℹ️ {user.mention} is already whitelisted.")
            return
        
        # Add to database
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO whitelisted_users (user_id, added_by)
            VALUES (?, ?)
        ''', (user_id, ctx.author.id))
        
        conn.commit()
        conn.close()
        
        # Add to memory
        self.whitelisted_users.append(user_id)
        
        embed = discord.Embed(
            title="✅ User Whitelisted",
            description=f"{user.mention} has been whitelisted for data export",
            color=0x00ff00
        )
        
        await ctx.send(embed=embed)

    @commands.command(name='set_verified_role')
    @commands.has_permissions(administrator=True)
    async def set_verified_role(self, ctx, role: discord.Role):
        """Set the role given to verified users"""
        guild_id = ctx.guild.id
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE server_settings SET verified_role_id = ? WHERE guild_id = ?
        ''', (role.id, guild_id))
        
        conn.commit()
        conn.close()
        
        embed = discord.Embed(
            title="✅ Verified Role Set",
            description=f"Verified users will now receive the {role.mention} role",
            color=0x00ff00
        )
        
        await ctx.send(embed=embed)

    @commands.command(name='set_unverified_role')
    @commands.has_permissions(administrator=True)
    async def set_unverified_role(self, ctx, role: discord.Role):
        """Set the role given to unverified users"""
        guild_id = ctx.guild.id
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE server_settings SET unverified_role_id = ? WHERE guild_id = ?
        ''', (role.id, guild_id))
        
        conn.commit()
        conn.close()
        
        embed = discord.Embed(
            title="✅ Unverified Role Set",
            description=f"New members will now receive the {role.mention} role until they verify",
            color=0x00ff00
        )
        
        await ctx.send(embed=embed)

    @commands.command(name='toggle_autorole')
    @commands.has_permissions(administrator=True)
    async def toggle_autorole(self, ctx):
        """Toggle automatic role assignment on/off"""
        guild_id = ctx.guild.id
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Get current setting
        cursor.execute('''
            SELECT auto_role FROM server_settings WHERE guild_id = ?
        ''', (guild_id,))
        
        result = cursor.fetchone()
        current_setting = result[0] if result else True
        new_setting = not current_setting
        
        cursor.execute('''
            UPDATE server_settings SET auto_role = ? WHERE guild_id = ?
        ''', (new_setting, guild_id))
        
        conn.commit()
        conn.close()
        
        embed = discord.Embed(
            title="⚙️ Auto-Role Updated",
            description=f"Automatic role assignment is now {'**enabled**' if new_setting else '**disabled**'}",
            color=0x00ff00 if new_setting else 0xff9900
        )
        
        if new_setting:
            embed.add_field(
                name="📋 What this means",
                value="• New members will automatically get the unverified role\n• Verified users will automatically get the verified role\n• Unverified role will be removed upon verification",
                inline=False
            )
        else:
            embed.add_field(
                name="📋 What this means",
                value="• No automatic role assignment will occur\n• You'll need to manage roles manually",
                inline=False
            )
        
        await ctx.send(embed=embed)

    @commands.command(name='setup_roles')
    @commands.has_permissions(administrator=True)
    async def setup_roles(self, ctx):
        """Automatically create and configure verification roles"""
        guild = ctx.guild
        guild_id = guild.id
        
        try:
            # Create verified role
            verified_role = await guild.create_role(
                name="✅ Verified",
                color=discord.Color.green(),
                reason="Verification system - verified users"
            )
            
            # Create unverified role
            unverified_role = await guild.create_role(
                name="❌ Unverified",
                color=discord.Color.red(),
                reason="Verification system - unverified users"
            )
            
            # Update database
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE server_settings 
                SET verified_role_id = ?, unverified_role_id = ?, auto_role = 1
                WHERE guild_id = ?
            ''', (verified_role.id, unverified_role.id, guild_id))
            
            conn.commit()
            conn.close()
            
            embed = discord.Embed(
                title="🎭 Roles Created Successfully",
                description="Verification roles have been created and configured!",
                color=0x00ff00
            )
            
            embed.add_field(
                name="✅ Verified Role",
                value=f"{verified_role.mention}\nGiven to users who complete verification",
                inline=True
            )
            
            embed.add_field(
                name="❌ Unverified Role", 
                value=f"{unverified_role.mention}\nGiven to new members until they verify",
                inline=True
            )
            
            embed.add_field(
                name="⚙️ Next Steps",
                value="• Configure channel permissions for these roles\n• Use `!config` to adjust other settings\n• Test with `!send_verification @user`",
                inline=False
            )
            
            await ctx.send(embed=embed)
            
        except discord.Forbidden:
            await ctx.send("❌ I don't have permission to create roles. Please ensure I have the 'Manage Roles' permission.")
        except discord.HTTPException as e:
            await ctx.send(f"❌ Failed to create roles: {str(e)}")

    @commands.command(name='generate_verification')
    async def generate_verification(self, ctx, user: discord.Member = None):
        """Generate a verification link for a user or general use (Owner/Admin only)"""
        # Check permissions - Owner or Administrator only
        if ctx.author.id != self.owner_id and not ctx.author.guild_permissions.administrator:
            await ctx.send("❌ This command requires Administrator permissions or bot ownership.")
            return
        
        guild_id = ctx.guild.id
        
        if guild_id not in self.server_codes:
            await ctx.send("❌ Server not set up! Use `!setup` first.")
            return
        
        verification_code = self.server_codes[guild_id]
        verification_url = f"{self.verification_url}?server={verification_code}"
        
        if user:
            # Generate for specific user
            embed = discord.Embed(
                title=f"🔗 Verification Generated for {user.display_name}",
                description=f"Verification link generated in {ctx.channel.mention}",
                color=0x667eea,
                timestamp=datetime.datetime.now()
            )
            
            embed.add_field(
                name="👤 Target User",
                value=f"{user.mention} ({user.id})",
                inline=True
            )
            
            embed.add_field(
                name="🔑 Server Code",
                value=f"`{verification_code}`",
                inline=True
            )
            
            embed.add_field(
                name="📍 Generated By",
                value=f"{ctx.author.mention}",
                inline=True
            )
            
            embed.add_field(
                name="🔗 Verification Link",
                value=f"[Click here to verify]({verification_url})",
                inline=False
            )
            
            embed.add_field(
                name="📋 User Instructions",
                value=f"""
                {user.mention}, please complete verification:
                1. Click the verification link above
                2. Complete the security checks
                3. Enter your Discord User ID: `{user.id}`
                4. Enter the server code: `{verification_code}`
                5. Wait for verification to complete
                """,
                inline=False
            )
            
            embed.set_footer(text="This verification helps protect the server from malicious users")
            
            await ctx.send(embed=embed)
            
            # Log the generation
            logger.info(f"Verification link generated for {user} ({user.id}) by {ctx.author} in {ctx.channel}")
            
        else:
            # Generate general verification info for the channel
            embed = discord.Embed(
                title="🛡️ Server Verification System",
                description=f"Verification link generated for {ctx.guild.name}",
                color=0x667eea,
                timestamp=datetime.datetime.now()
            )
            
            embed.add_field(
                name="🔗 Verification Link",
                value=f"[Click here to verify]({verification_url})",
                inline=False
            )
            
            embed.add_field(
                name="🔑 Server Code",
                value=f"`{verification_code}`",
                inline=True
            )
            
            embed.add_field(
                name="📍 Generated By",
                value=f"{ctx.author.mention}",
                inline=True
            )
            
            embed.add_field(
                name="📋 How to Verify",
                value="""
                1. Click the verification link above
                2. Complete the security checks
                3. Enter your Discord User ID (found in your profile)
                4. Enter the server code shown above
                5. Wait for verification to complete
                """,
                inline=False
            )
            
            embed.add_field(
                name="ℹ️ Need Help?",
                value="• Enable Developer Mode in Discord settings to see your User ID\n• Contact an administrator if you have issues\n• Make sure to complete all security checks",
                inline=False
            )
            
            embed.set_footer(text="This verification helps protect the server from malicious users")
            
            await ctx.send(embed=embed)
            
            # Log the generation
            logger.info(f"General verification link generated by {ctx.author} in {ctx.channel}")

    @commands.command(name='quick_verify')
    async def quick_verify(self, ctx, user: discord.Member):
        """Quick verification generation with minimal embed (Owner/Admin only)"""
        # Check permissions - Owner or Administrator only
        if ctx.author.id != self.owner_id and not ctx.author.guild_permissions.administrator:
            await ctx.send("❌ This command requires Administrator permissions or bot ownership.")
            return
        
        guild_id = ctx.guild.id
        
        if guild_id not in self.server_codes:
            await ctx.send("❌ Server not set up! Use `!setup` first.")
            return
        
        verification_code = self.server_codes[guild_id]
        verification_url = f"{self.verification_url}?server={verification_code}"
        
        # Simple, clean verification message
        embed = discord.Embed(
            title="🔒 Verification Required",
            description=f"{user.mention}, please verify your account to access the server.",
            color=0x667eea
        )
        
        embed.add_field(
            name="🔗 Verify Here",
            value=f"[**Click to Verify**]({verification_url})",
            inline=False
        )
        
        embed.add_field(
            name="📝 Your Info",
            value=f"**User ID:** `{user.id}`\n**Server Code:** `{verification_code}`",
            inline=False
        )
        
        embed.set_footer(text=f"Generated by {ctx.author.display_name}")
        
        await ctx.send(embed=embed)
        
        # Log the generation
        logger.info(f"Quick verification generated for {user} ({user.id}) by {ctx.author} in {ctx.channel}")

    @commands.command(name='mass_verify')
    async def mass_verify(self, ctx, *users: discord.Member):
        """Generate verification for multiple users at once (Owner/Admin only)"""
        # Check permissions - Owner or Administrator only
        if ctx.author.id != self.owner_id and not ctx.author.guild_permissions.administrator:
            await ctx.send("❌ This command requires Administrator permissions or bot ownership.")
            return
        
        if not users:
            await ctx.send("❌ Please mention at least one user to generate verification for.")
            return
        
        if len(users) > 10:
            await ctx.send("❌ Maximum 10 users per mass verification to avoid spam.")
            return
        
        guild_id = ctx.guild.id
        
        if guild_id not in self.server_codes:
            await ctx.send("❌ Server not set up! Use `!setup` first.")
            return
        
        verification_code = self.server_codes[guild_id]
        verification_url = f"{self.verification_url}?server={verification_code}"
        
        embed = discord.Embed(
            title="🛡️ Mass Verification Generated",
            description=f"Verification required for {len(users)} users",
            color=0x667eea,
            timestamp=datetime.datetime.now()
        )
        
        embed.add_field(
            name="🔗 Verification Link",
            value=f"[**Click here to verify**]({verification_url})",
            inline=False
        )
        
        embed.add_field(
            name="🔑 Server Code",
            value=f"`{verification_code}`",
            inline=True
        )
        
        embed.add_field(
            name="📍 Generated By",
            value=f"{ctx.author.mention}",
            inline=True
        )
        
        # List users who need to verify
        user_list = []
        for i, user in enumerate(users, 1):
            user_list.append(f"{i}. {user.mention} (ID: `{user.id}`)")
        
        embed.add_field(
            name="👥 Users to Verify",
            value="\n".join(user_list),
            inline=False
        )
        
        embed.add_field(
            name="📋 Instructions",
            value="1. Click the verification link above\n2. Complete security checks\n3. Enter your User ID and Server Code\n4. Wait for completion",
            inline=False
        )
        
        embed.set_footer(text="All users mentioned above need to complete verification")
        
        await ctx.send(embed=embed)
        
        # Log the mass generation
        user_names = [str(user) for user in users]
        logger.info(f"Mass verification generated for {len(users)} users by {ctx.author} in {ctx.channel}: {', '.join(user_names)}")

    @commands.command(name='verification_panel')
    async def verification_panel(self, ctx):
        """Create a permanent verification panel in the channel (Owner/Admin only)"""
        # Check permissions - Owner or Administrator only
        if ctx.author.id != self.owner_id and not ctx.author.guild_permissions.administrator:
            await ctx.send("❌ This command requires Administrator permissions or bot ownership.")
            return
        
        guild_id = ctx.guild.id
        
        if guild_id not in self.server_codes:
            await ctx.send("❌ Server not set up! Use `!setup` first.")
            return
        
        verification_code = self.server_codes[guild_id]
        verification_url = f"{self.verification_url}?server={verification_code}"
        
        embed = discord.Embed(
            title="🛡️ Server Verification Panel",
            description=f"**{ctx.guild.name}** requires verification for all members",
            color=0x667eea
        )
        
        embed.add_field(
            name="🔗 Verification Link",
            value=f"[**🔒 Click Here to Verify**]({verification_url})",
            inline=False
        )
        
        embed.add_field(
            name="📋 How to Verify",
            value="""
            **Step 1:** Click the verification link above
            **Step 2:** Complete the security analysis
            **Step 3:** Enter your Discord User ID
            **Step 4:** Enter the server code below
            **Step 5:** Wait for verification to complete
            """,
            inline=False
        )
        
        embed.add_field(
            name="🔑 Server Code",
            value=f"`{verification_code}`",
            inline=True
        )
        
        embed.add_field(
            name="❓ Need Your User ID?",
            value="Enable Developer Mode in Discord settings, then right-click your profile",
            inline=True
        )
        
        embed.add_field(
            name="🛡️ Security Features",
            value="• VPN/Proxy Detection\n• Hardware Fingerprinting\n• Duplicate Account Prevention\n• Automated Risk Assessment",
            inline=False
        )
        
        embed.add_field(
            name="⚠️ Important Notes",
            value="• Verification is required to access the server\n• Your data is encrypted and secure\n• Contact staff if you need help\n• Multiple accounts will be detected",
            inline=False
        )
        
        embed.set_footer(text=f"Verification Panel • {ctx.guild.name}")
        embed.set_thumbnail(url=ctx.guild.icon.url if ctx.guild.icon else None)
        
        await ctx.send(embed=embed)
        
        # Log the panel creation
        logger.info(f"Verification panel created by {ctx.author} in {ctx.channel}")

    @commands.command(name='send_verification')
    @commands.has_permissions(administrator=True)
    async def send_verification_manual(self, ctx, user: discord.Member):
        """Manually send verification instructions to a user"""
        guild_id = ctx.guild.id
        
        if guild_id not in self.server_codes:
            await ctx.send("❌ Server not set up! Use `!setup` first.")
            return
        
        verification_code = self.server_codes[guild_id]
        verification_url = f"{self.verification_url}?server={verification_code}"
        
        embed = discord.Embed(
            title=f"🛡️ Verification Required - {ctx.guild.name}",
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
            value=f"`{user.id}`",
            inline=True
        )
        
        embed.add_field(
            name="🔑 Your Server Code",
            value=f"`{verification_code}`",
            inline=True
        )
        
        embed.set_footer(text=f"Sent by {ctx.author} • This verification helps protect the server")
        
        try:
            await user.send(embed=embed)
            
            success_embed = discord.Embed(
                title="✅ Verification Sent",
                description=f"Verification instructions have been sent to {user.mention}'s DMs",
                color=0x00ff00
            )
            success_embed.add_field(
                name="📋 Details",
                value=f"**User:** {user.mention}\n**Server Code:** `{verification_code}`\n**User ID:** `{user.id}`",
                inline=False
            )
            
            await ctx.send(embed=success_embed)
            
        except discord.Forbidden:
            error_embed = discord.Embed(
                title="❌ Cannot Send DM",
                description=f"Could not send verification instructions to {user.mention}",
                color=0xff0000
            )
            error_embed.add_field(
                name="📋 Manual Verification Info",
                value=f"**Verification URL:** {verification_url}\n**Server Code:** `{verification_code}`\n**User ID:** `{user.id}`",
                inline=False
            )
            error_embed.set_footer(text="User has DMs disabled or blocked the bot")
            
            await ctx.send(embed=error_embed)
            
        except discord.HTTPException as e:
            await ctx.send(f"❌ Failed to send DM: {str(e)}")

    @commands.command(name='resend_verification')
    @commands.has_permissions(administrator=True)
    async def resend_verification(self, ctx, user: discord.Member):
        """Resend verification instructions to a user (alias for send_verification)"""
        await self.send_verification_manual(ctx, user)

    @commands.command(name='ipban')
    @commands.has_permissions(administrator=True)
    async def ip_ban(self, ctx, user: discord.Member, *, reason="No reason provided"):
        """Ban a user's IP address based on their verification data"""
        guild_id = ctx.guild.id
        user_id = str(user.id)
        
        # Get user's IP from verification data
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT ip_address FROM verifications 
            WHERE guild_id = ? AND discord_id = ? AND status = "VERIFIED"
            ORDER BY timestamp DESC LIMIT 1
        ''', (guild_id, user_id))
        
        result = cursor.fetchone()
        
        if not result:
            await ctx.send(f"❌ No verification data found for {user.mention}")
            conn.close()
            return
        
        ip_address = result[0]
        
        # Check if IP is already banned
        cursor.execute('''
            SELECT banned_user_name FROM ip_bans 
            WHERE guild_id = ? AND ip_address = ?
        ''', (guild_id, ip_address))
        
        existing_ban = cursor.fetchone()
        
        if existing_ban:
            await ctx.send(f"❌ IP `{ip_address}` is already banned (previously banned user: {existing_ban[0]})")
            conn.close()
            return
        
        # Add IP ban
        cursor.execute('''
            INSERT INTO ip_bans 
            (guild_id, ip_address, banned_user_id, banned_user_name, reason, banned_by)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (guild_id, ip_address, user_id, str(user), reason, ctx.author.id))
        
        conn.commit()
        conn.close()
        
        # Update memory cache
        if guild_id not in self.ip_bans:
            self.ip_bans[guild_id] = []
        self.ip_bans[guild_id].append(ip_address)
        
        # Try to kick/ban the user
        try:
            await user.kick(reason=f"IP banned: {reason}")
            action_taken = "User kicked from server"
        except discord.Forbidden:
            action_taken = "Unable to kick user (insufficient permissions)"
        except discord.HTTPException:
            action_taken = "Failed to kick user"
        
        embed = discord.Embed(
            title="🚫 IP Ban Applied",
            color=0xff0000,
            timestamp=datetime.datetime.now()
        )
        
        embed.add_field(name="👤 User", value=f"{user.mention} ({user.id})", inline=True)
        embed.add_field(name="🌐 IP Address", value=f"`{ip_address}`", inline=True)
        embed.add_field(name="📝 Reason", value=reason, inline=False)
        embed.add_field(name="⚡ Action", value=action_taken, inline=False)
        embed.set_footer(text=f"Banned by {ctx.author}")
        
        await ctx.send(embed=embed)
        
        # Log to security channel
        await self.log_ip_ban_event(ctx.guild, user, ip_address, reason, ctx.author, "BANNED")

    @commands.command(name='ipunban')
    @commands.has_permissions(administrator=True)
    async def ip_unban(self, ctx, ip_address: str):
        """Remove an IP ban"""
        guild_id = ctx.guild.id
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Check if IP is banned
        cursor.execute('''
            SELECT banned_user_name, reason FROM ip_bans 
            WHERE guild_id = ? AND ip_address = ?
        ''', (guild_id, ip_address))
        
        result = cursor.fetchone()
        
        if not result:
            await ctx.send(f"❌ IP `{ip_address}` is not banned")
            conn.close()
            return
        
        banned_user_name, reason = result
        
        # Remove IP ban
        cursor.execute('''
            DELETE FROM ip_bans 
            WHERE guild_id = ? AND ip_address = ?
        ''', (guild_id, ip_address))
        
        conn.commit()
        conn.close()
        
        # Update memory cache
        if guild_id in self.ip_bans and ip_address in self.ip_bans[guild_id]:
            self.ip_bans[guild_id].remove(ip_address)
        
        embed = discord.Embed(
            title="✅ IP Ban Removed",
            color=0x00ff00,
            timestamp=datetime.datetime.now()
        )
        
        embed.add_field(name="🌐 IP Address", value=f"`{ip_address}`", inline=True)
        embed.add_field(name="👤 Previously Banned User", value=banned_user_name, inline=True)
        embed.add_field(name="📝 Original Reason", value=reason, inline=False)
        embed.set_footer(text=f"Unbanned by {ctx.author}")
        
        await ctx.send(embed=embed)

    @commands.command(name='ipbans')
    @commands.has_permissions(administrator=True)
    async def list_ip_bans(self, ctx):
        """List all IP bans for this server"""
        guild_id = ctx.guild.id
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT ip_address, banned_user_name, reason, banned_at 
            FROM ip_bans WHERE guild_id = ?
            ORDER BY banned_at DESC
        ''', (guild_id,))
        
        bans = cursor.fetchall()
        conn.close()
        
        if not bans:
            await ctx.send("ℹ️ No IP bans found for this server")
            return
        
        embed = discord.Embed(
            title="🚫 IP Bans List",
            description=f"Total IP bans: {len(bans)}",
            color=0xff0000
        )
        
        ban_list = []
        for ip, user_name, reason, banned_at in bans[:10]:  # Show first 10
            ban_list.append(f"**IP:** `{ip}`\n**User:** {user_name}\n**Reason:** {reason}\n**Date:** {banned_at}\n")
        
        embed.add_field(
            name="Recent Bans",
            value="\n".join(ban_list) if ban_list else "None",
            inline=False
        )
        
        if len(bans) > 10:
            embed.set_footer(text=f"Showing 10 of {len(bans)} bans. Use !export_data for full list.")
        
        await ctx.send(embed=embed)

    @commands.command(name='checkip')
    @commands.has_permissions(administrator=True)
    async def check_ip(self, ctx, ip_address: str):
        """Check if an IP is banned and show associated users"""
        guild_id = ctx.guild.id
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Check if IP is banned
        cursor.execute('''
            SELECT banned_user_name, reason, banned_at, banned_by 
            FROM ip_bans WHERE guild_id = ? AND ip_address = ?
        ''', (guild_id, ip_address))
        
        ban_info = cursor.fetchone()
        
        # Get all users who have used this IP
        cursor.execute('''
            SELECT discord_id, timestamp, risk_score, security_flags 
            FROM verifications 
            WHERE guild_id = ? AND ip_address = ? 
            ORDER BY timestamp DESC
        ''', (guild_id, ip_address))
        
        users = cursor.fetchall()
        conn.close()
        
        embed = discord.Embed(
            title=f"🔍 IP Address Analysis: `{ip_address}`",
            color=0xff0000 if ban_info else 0x667eea
        )
        
        if ban_info:
            banned_user, reason, banned_at, banned_by = ban_info
            embed.add_field(
                name="🚫 Ban Status",
                value=f"**BANNED**\nUser: {banned_user}\nReason: {reason}\nDate: {banned_at}",
                inline=False
            )
        else:
            embed.add_field(
                name="✅ Ban Status",
                value="Not banned",
                inline=True
            )
        
        if users:
            user_list = []
            for discord_id, timestamp, risk_score, security_flags in users[:5]:
                user_list.append(f"<@{discord_id}> - Risk: {risk_score} - {timestamp}")
            
            embed.add_field(
                name=f"👥 Associated Users ({len(users)} total)",
                value="\n".join(user_list) if user_list else "None",
                inline=False
            )
            
            if len(users) > 5:
                embed.set_footer(text=f"Showing 5 of {len(users)} users")
        else:
            embed.add_field(
                name="👥 Associated Users",
                value="No verification data found",
                inline=False
            )
        
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

    @commands.command(name='invites')
    @commands.has_permissions(administrator=True)
    async def invite_stats(self, ctx):
        """Show invite tracking statistics"""
        guild_id = ctx.guild.id
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Get invite statistics
        cursor.execute('''
            SELECT inviter_id, inviter_name, COUNT(*) as invite_count
            FROM invite_tracking 
            WHERE guild_id = ? 
            GROUP BY inviter_id, inviter_name
            ORDER BY invite_count DESC
            LIMIT 10
        ''', (guild_id,))
        
        top_inviters = cursor.fetchall()
        
        # Get recent invites
        cursor.execute('''
            SELECT inviter_name, used_by_name, invite_code, timestamp, verification_status
            FROM invite_tracking 
            WHERE guild_id = ? 
            ORDER BY timestamp DESC 
            LIMIT 10
        ''', (guild_id,))
        
        recent_invites = cursor.fetchall()
        
        # Get total stats
        cursor.execute('''
            SELECT COUNT(*) as total_invites,
                   COUNT(CASE WHEN verification_status = 'VERIFIED' THEN 1 END) as verified_count,
                   COUNT(CASE WHEN verification_status = 'BLOCKED' THEN 1 END) as blocked_count
            FROM invite_tracking 
            WHERE guild_id = ?
        ''', (guild_id,))
        
        total_stats = cursor.fetchone()
        conn.close()
        
        embed = discord.Embed(
            title="📨 Invite Tracking Statistics",
            color=0x667eea,
            timestamp=datetime.datetime.now()
        )
        
        if total_stats:
            total_invites, verified_count, blocked_count = total_stats
            embed.add_field(
                name="📊 Overall Statistics",
                value=f"""
                **Total Invites Used:** {total_invites}
                **Successfully Verified:** {verified_count}
                **Blocked/Failed:** {blocked_count}
                **Success Rate:** {(verified_count/total_invites*100) if total_invites > 0 else 0:.1f}%
                """,
                inline=False
            )
        
        if top_inviters:
            inviter_list = []
            for inviter_id, inviter_name, count in top_inviters:
                member = ctx.guild.get_member(int(inviter_id))
                display_name = member.mention if member else inviter_name
                inviter_list.append(f"{display_name}: **{count}** invites")
            
            embed.add_field(
                name="🏆 Top Inviters",
                value="\n".join(inviter_list),
                inline=True
            )
        
        if recent_invites:
            recent_list = []
            for inviter_name, used_by_name, invite_code, timestamp, status in recent_invites[:5]:
                status_emoji = "✅" if status == "VERIFIED" else "❌" if status == "BLOCKED" else "⏳"
                recent_list.append(f"{status_emoji} **{inviter_name}** → {used_by_name}")
            
            embed.add_field(
                name="🕒 Recent Invites",
                value="\n".join(recent_list),
                inline=True
            )
        
        embed.set_footer(text="Use !check_user @user to see who invited a specific user")
        
        await ctx.send(embed=embed)

    @commands.command(name='check_user')
    @commands.has_permissions(administrator=True)
    async def check_user_verification(self, ctx, user: discord.Member):
        """Check a user's verification status and invite information"""
        guild_id = ctx.guild.id
        user_id = str(user.id)
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Get verification data
        cursor.execute('''
            SELECT discord_id, hwid, risk_score, timestamp, security_flags, ip_address 
            FROM verifications 
            WHERE guild_id = ? AND discord_id = ? AND status = "VERIFIED"
            ORDER BY timestamp DESC LIMIT 1
        ''', (guild_id, user_id))
        
        verification_result = cursor.fetchone()
        
        # Get invite information
        cursor.execute('''
            SELECT inviter_name, inviter_id, invite_code, timestamp, verification_status
            FROM invite_tracking 
            WHERE guild_id = ? AND used_by_id = ?
            ORDER BY timestamp DESC LIMIT 1
        ''', (guild_id, int(user.id)))
        
        invite_result = cursor.fetchone()
        
        # Check for other users with same IP or HWID
        if verification_result:
            _, hwid, _, _, _, ip_address = verification_result
            
            # Check for HWID duplicates
            cursor.execute('''
                SELECT discord_id, timestamp FROM verifications 
                WHERE guild_id = ? AND hwid = ? AND discord_id != ? AND status = "VERIFIED"
                ORDER BY timestamp DESC
            ''', (guild_id, hwid, user_id))
            
            hwid_duplicates = cursor.fetchall()
            
            # Check for IP duplicates
            cursor.execute('''
                SELECT discord_id, timestamp FROM verifications 
                WHERE guild_id = ? AND ip_address = ? AND discord_id != ? AND status = "VERIFIED"
                ORDER BY timestamp DESC
            ''', (guild_id, ip_address, user_id))
            
            ip_duplicates = cursor.fetchall()
        else:
            hwid_duplicates = []
            ip_duplicates = []
        
        conn.close()
        
        if verification_result:
            discord_id, hwid, risk_score, timestamp, security_flags, ip_address = verification_result
            
            embed = discord.Embed(
                title=f"🔍 User Analysis: {user.display_name}",
                color=0x00ff00 if risk_score < 50 else 0xff9900 if risk_score < 80 else 0xff0000,
                timestamp=datetime.datetime.now()
            )
            
            embed.add_field(name="✅ Verification Status", value="Verified", inline=True)
            embed.add_field(name="📊 Risk Score", value=f"{risk_score}/100", inline=True)
            embed.add_field(name="🕒 Verified At", value=timestamp, inline=True)
            
            # Invite information
            if invite_result:
                inviter_name, inviter_id, invite_code, invite_timestamp, verification_status = invite_result
                inviter_member = ctx.guild.get_member(int(inviter_id))
                inviter_display = inviter_member.mention if inviter_member else inviter_name
                
                embed.add_field(
                    name="📨 Invited By",
                    value=f"{inviter_display}\nCode: `{invite_code}`\nDate: {invite_timestamp}",
                    inline=True
                )
            else:
                embed.add_field(name="📨 Invited By", value="Unknown/Direct join", inline=True)
            
            embed.add_field(name="🌐 IP Address", value=f"`{ip_address}`", inline=True)
            embed.add_field(name="🔒 HWID", value=hwid[:16] + "...", inline=True)
            
            if security_flags and security_flags != "[]":
                embed.add_field(name="⚠️ Security Flags", value=security_flags, inline=False)
            
            # Show duplicates if any
            if hwid_duplicates:
                duplicate_list = []
                for dup_id, dup_timestamp in hwid_duplicates[:3]:
                    dup_member = ctx.guild.get_member(int(dup_id))
                    dup_name = dup_member.mention if dup_member else f"<@{dup_id}>"
                    duplicate_list.append(f"{dup_name} ({dup_timestamp})")
                
                embed.add_field(
                    name="🚨 HWID Duplicates",
                    value="\n".join(duplicate_list) + (f"\n+{len(hwid_duplicates)-3} more" if len(hwid_duplicates) > 3 else ""),
                    inline=False
                )
            
            if ip_duplicates:
                ip_duplicate_list = []
                for dup_id, dup_timestamp in ip_duplicates[:3]:
                    dup_member = ctx.guild.get_member(int(dup_id))
                    dup_name = dup_member.mention if dup_member else f"<@{dup_id}>"
                    ip_duplicate_list.append(f"{dup_name} ({dup_timestamp})")
                
                embed.add_field(
                    name="🚨 IP Duplicates",
                    value="\n".join(ip_duplicate_list) + (f"\n+{len(ip_duplicates)-3} more" if len(ip_duplicates) > 3 else ""),
                    inline=False
                )
            
        else:
            embed = discord.Embed(
                title=f"❌ User Analysis: {user.display_name}",
                description="User is not verified",
                color=0xff0000,
                timestamp=datetime.datetime.now()
            )
            
            # Still show invite info if available
            if invite_result:
                inviter_name, inviter_id, invite_code, invite_timestamp, verification_status = invite_result
                inviter_member = ctx.guild.get_member(int(inviter_id))
                inviter_display = inviter_member.mention if inviter_member else inviter_name
                
                embed.add_field(
                    name="📨 Invited By",
                    value=f"{inviter_display}\nCode: `{invite_code}`\nDate: {invite_timestamp}\nStatus: {verification_status}",
                    inline=False
                )
        
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
        
        # Track invite usage
        invite_info = await self.track_invite_usage(member)
        
        # Get server settings
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT verification_channel, welcome_message, invite_tracking, 
                   unverified_role_id, auto_role
            FROM server_settings WHERE guild_id = ?
        ''', (guild_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return
        
        verification_channel_id, welcome_msg, invite_tracking, unverified_role_id, auto_role = result
        channel = self.get_channel(verification_channel_id)
        
        # Assign unverified role if auto_role is enabled
        if auto_role and unverified_role_id:
            unverified_role = member.guild.get_role(unverified_role_id)
            if unverified_role:
                try:
                    await member.add_roles(unverified_role, reason="Auto-assigned unverified role")
                    logger.info(f"Assigned unverified role to {member} ({member.id}) in guild {guild_id}")
                except discord.Forbidden:
                    logger.warning(f"Cannot assign unverified role in guild {guild_id} - insufficient permissions")
                except discord.HTTPException as e:
                    logger.error(f"Failed to assign unverified role: {e}")
            else:
                logger.warning(f"Unverified role {unverified_role_id} not found in guild {guild_id}")
        
        if not channel:
            return
        
        verification_code = self.server_codes[guild_id]
        verification_url = f"{self.verification_url}?server={verification_code}"
        
        embed = discord.Embed(
            title=f"🛡️ Welcome {member.display_name}!",
            description=welcome_msg or "Please complete verification to access the server",
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
            name="🔑 Your Server Code",
            value=f"`{verification_code}`",
            inline=True
        )
        
        # Add invite info if tracking is enabled
        if invite_tracking and invite_info:
            embed.add_field(
                name="📨 Invited by",
                value=f"{invite_info['inviter_name']} ({invite_info['invite_code']})",
                inline=True
            )
        
        embed.set_footer(text="This verification helps protect the server from malicious users")
        
        # Always try to DM the user first
        dm_sent = False
        try:
            await member.send(embed=embed)
            dm_sent = True
            logger.info(f"Sent verification DM to {member} ({member.id}) in guild {guild_id}")
        except discord.Forbidden:
            logger.warning(f"Could not DM {member} ({member.id}) - DMs disabled")
        except discord.HTTPException as e:
            logger.error(f"Failed to DM {member} ({member.id}): {e}")
        
        # Also send to verification channel as backup or if DM failed
        if channel:
            try:
                if dm_sent:
                    # Create a simpler message for the channel since user got DM
                    channel_embed = discord.Embed(
                        title=f"👋 Welcome {member.display_name}!",
                        description=f"Please check your DMs for verification instructions.\n\nIf you didn't receive a DM, here's your verification info:",
                        color=0x667eea
                    )
                    channel_embed.add_field(
                        name="🔗 Verification Link",
                        value=f"[Click here to verify]({verification_url})",
                        inline=False
                    )
                    channel_embed.add_field(
                        name="🔑 Your Server Code",
                        value=f"`{verification_code}`",
                        inline=True
                    )
                    channel_embed.add_field(
                        name="ℹ️ Your Discord User ID",
                        value=f"`{member.id}`",
                        inline=True
                    )
                    await channel.send(f"{member.mention}", embed=channel_embed)
                else:
                    # Send full embed since DM failed
                    await channel.send(f"{member.mention}", embed=embed)
                    
            except discord.Forbidden:
                logger.error(f"Cannot send messages to verification channel in guild {guild_id}")
            except discord.HTTPException as e:
                logger.error(f"Failed to send verification message to channel: {e}")

    async def track_invite_usage(self, member):
        """Track which invite was used"""
        guild = member.guild
        guild_id = guild.id
        
        try:
            # Get current invites
            current_invites = {invite.code: invite for invite in await guild.invites()}
            
            # Compare with cached invites
            if guild_id in self.guild_invites:
                old_invites = self.guild_invites[guild_id]
                
                # Find the invite that was used
                for code, invite in current_invites.items():
                    if code in old_invites:
                        if invite.uses > old_invites[code].uses:
                            # This invite was used
                            invite_info = {
                                'invite_code': code,
                                'inviter_id': invite.inviter.id,
                                'inviter_name': str(invite.inviter),
                                'used_by_id': member.id,
                                'used_by_name': str(member)
                            }
                            
                            # Store in database
                            conn = sqlite3.connect(self.database_path)
                            cursor = conn.cursor()
                            
                            cursor.execute('''
                                INSERT INTO invite_tracking 
                                (guild_id, invite_code, inviter_id, inviter_name, 
                                 used_by_id, used_by_name, timestamp)
                                VALUES (?, ?, ?, ?, ?, ?, ?)
                            ''', (
                                guild_id, code, invite.inviter.id, str(invite.inviter),
                                member.id, str(member), datetime.datetime.now()
                            ))
                            
                            conn.commit()
                            conn.close()
                            
                            # Update cache
                            self.guild_invites[guild_id] = current_invites
                            
                            return invite_info
            
            # Update cache even if no match found
            self.guild_invites[guild_id] = current_invites
            
        except discord.Forbidden:
            logger.warning(f"Cannot access invites for guild {guild.name}")
        except Exception as e:
            logger.error(f"Error tracking invite usage: {e}")
        
        return None

    async def on_invite_create(self, invite):
        """Handle new invite creation"""
        guild_id = invite.guild.id
        if guild_id in self.guild_invites:
            self.guild_invites[guild_id][invite.code] = invite

    async def on_invite_delete(self, invite):
        """Handle invite deletion"""
        guild_id = invite.guild.id
        if guild_id in self.guild_invites and invite.code in self.guild_invites[guild_id]:
            del self.guild_invites[guild_id][invite.code]

    async def handle_verification_webhook(self, data):
        """Handle incoming verification data from webhook"""
        try:
            # Handle both direct JSON data and Discord webhook format
            if 'embeds' in data:
                # Extract JSON from Discord webhook content
                content = data.get('content', '')
                if '```json' in content:
                    json_part = content.split('```json\n')[1].split('\n```')[0]
                    data = json.loads(json_part)
            
            event_type = data.get('event')
            user_data = data.get('userData', {})
            security_flags = data.get('securityFlags', [])
            
            logger.info(f"Processing verification webhook: {event_type} for user {user_data.get('discordId', 'unknown')}")
            
            if event_type == 'BLOCKED':
                await self.handle_blocked_attempt(data)
            elif event_type == 'VERIFIED':
                await self.handle_successful_verification(data)
            else:
                logger.warning(f"Unknown event type: {event_type}")
                
        except Exception as e:
            logger.error(f"Error handling webhook data: {e}")
            logger.error(f"Raw data: {data}")

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
        
        # Check if IP is banned
        ip_address = user_data.get('ip', '')
        if await self.check_ip_banned(guild_id, ip_address):
            await self.handle_ip_ban_attempt(guild, discord_id, ip_address)
            return
        
        # Check for duplicate HWID
        duplicate_user = await self.check_duplicate_hwid(guild_id, hwid, discord_id)
        
        if duplicate_user:
            await self.handle_duplicate_detection(guild, discord_id, duplicate_user, hwid)
            return
        
        # Check for duplicate IP
        duplicate_ip_user = await self.check_duplicate_ip(guild_id, ip_address, discord_id)
        
        if duplicate_ip_user:
            await self.handle_ip_duplicate_detection(guild, discord_id, duplicate_ip_user, ip_address)
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
        
        # Update invite tracking status and handle role management
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE invite_tracking 
            SET verification_status = 'VERIFIED'
            WHERE guild_id = ? AND used_by_id = ?
        ''', (guild_id, int(discord_id)))
        
        # Get role settings
        cursor.execute('''
            SELECT verified_role_id, unverified_role_id, auto_role
            FROM server_settings WHERE guild_id = ?
        ''', (guild_id,))
        
        role_settings = cursor.fetchone()
        conn.commit()
        conn.close()
        
        # Handle role assignment
        if role_settings:
            verified_role_id, unverified_role_id, auto_role = role_settings
            
            if auto_role:
                member = guild.get_member(int(discord_id))
                if member:
                    try:
                        # Add verified role
                        if verified_role_id:
                            verified_role = guild.get_role(verified_role_id)
                            if verified_role and verified_role not in member.roles:
                                await member.add_roles(verified_role, reason="Verification completed")
                                logger.info(f"Assigned verified role to {member} ({member.id})")
                        
                        # Remove unverified role
                        if unverified_role_id:
                            unverified_role = guild.get_role(unverified_role_id)
                            if unverified_role and unverified_role in member.roles:
                                await member.remove_roles(unverified_role, reason="Verification completed")
                                logger.info(f"Removed unverified role from {member} ({member.id})")
                                
                    except discord.Forbidden:
                        logger.warning(f"Cannot manage roles for {member} - insufficient permissions")
                    except discord.HTTPException as e:
                        logger.error(f"Failed to manage roles for {member}: {e}")
        
        # Log successful verification
        await self.log_verification_event(guild, discord_id, user_data, security_flags, 'VERIFIED')
        
        logger.info(f"Successful verification for user {discord_id} in guild {guild_id}")

    async def check_ip_banned(self, guild_id: int, ip_address: str) -> bool:
        """Check if an IP address is banned"""
        if guild_id in self.ip_bans:
            return ip_address in self.ip_bans[guild_id]
        return False

    async def check_duplicate_ip(self, guild_id: int, ip_address: str, current_discord_id: str) -> Optional[str]:
        """Check if IP already exists for a different user"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT discord_id FROM verifications 
            WHERE guild_id = ? AND ip_address = ? AND discord_id != ? AND status = "VERIFIED"
            ORDER BY timestamp DESC LIMIT 1
        ''', (guild_id, ip_address, current_discord_id))
        
        result = cursor.fetchone()
        conn.close()
        
        return result[0] if result else None

    async def handle_ip_ban_attempt(self, guild: discord.Guild, discord_id: str, ip_address: str):
        """Handle attempt to verify with banned IP"""
        try:
            member = guild.get_member(int(discord_id))
            
            # Get ban info
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT banned_user_name, reason FROM ip_bans 
                WHERE guild_id = ? AND ip_address = ?
            ''', (guild.id, ip_address))
            
            ban_info = cursor.fetchone()
            conn.close()
            
            banned_user_name, reason = ban_info if ban_info else ("Unknown", "IP banned")
            
            # Try to kick the user
            if member:
                try:
                    await member.kick(reason=f"Banned IP attempt: {ip_address}")
                    action_taken = "User kicked automatically"
                except discord.Forbidden:
                    action_taken = "Unable to kick user (insufficient permissions)"
                except discord.HTTPException:
                    action_taken = "Failed to kick user"
            else:
                action_taken = "User not found in server"
            
            # Log the attempt
            await self.log_ip_ban_event(guild, member, ip_address, f"Banned IP verification attempt - Original ban: {reason}", None, "BLOCKED_ATTEMPT")
            
            logger.info(f"Blocked banned IP verification attempt: {discord_id} using IP {ip_address} in guild {guild.id}")
            
        except Exception as e:
            logger.error(f"Error handling IP ban attempt: {e}")

    async def handle_ip_duplicate_detection(self, guild: discord.Guild, new_discord_id: str, 
                                          existing_discord_id: str, ip_address: str):
        """Handle duplicate IP detection"""
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
                title="🚨 Duplicate IP Detected",
                description="Same IP address detected for multiple accounts",
                color=0xff9900,  # Orange for IP duplicates (less severe than HWID)
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
                name="🌐 IP Address",
                value=f"`{ip_address}`",
                inline=True
            )
            
            # Auto-kick if enabled
            if auto_kick and new_member:
                try:
                    await new_member.kick(reason="Duplicate IP detected")
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
            
            logger.info(f"Duplicate IP detected in guild {guild.id}: {new_discord_id} matches {existing_discord_id} (IP: {ip_address})")
            
        except Exception as e:
            logger.error(f"Error handling IP duplicate detection: {e}")

    async def log_ip_ban_event(self, guild: discord.Guild, user, ip_address: str, reason: str, banned_by, event_type: str):
        """Log IP ban events to the designated channel"""
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
            
            embed = discord.Embed(
                title=f"🚫 IP Ban Event: {event_type}",
                timestamp=datetime.datetime.now()
            )
            
            if event_type == 'BANNED':
                embed.color = 0xff0000
                embed.add_field(
                    name="👤 User Banned",
                    value=f"{user.mention if user else 'Unknown'} ({user.id if user else 'Unknown'})",
                    inline=True
                )
                embed.add_field(
                    name="👮 Banned By",
                    value=f"{banned_by.mention if banned_by else 'System'}",
                    inline=True
                )
            else:
                embed.color = 0xff9900
                embed.add_field(
                    name="🚨 Blocked Attempt",
                    value=f"User: {user.mention if user else 'Unknown'}",
                    inline=True
                )
            
            embed.add_field(
                name="🌐 IP Address",
                value=f"`{ip_address}`",
                inline=True
            )
            
            embed.add_field(
                name="📝 Reason",
                value=reason,
                inline=False
            )
            
            await log_channel.send(embed=embed)
            
        except Exception as e:
            logger.error(f"Error logging IP ban event: {e}")

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
                logger.info(f"Received webhook data: {data}")
                await self.handle_verification_webhook(data)
                return web.Response(text="OK")
            except Exception as e:
                logger.error(f"Webhook error: {e}")
                return web.Response(text="Error", status=500)
        
        async def health_check(request):
            return web.Response(text="Webhook server is running")
        
        app = web.Application()
        app.router.add_post('/webhook', webhook_handler)
        app.router.add_get('/health', health_check)
        app.router.add_get('/', health_check)
        
        runner = web.AppRunner(app)
        await runner.setup()
        
        site = web.TCPSite(runner, '0.0.0.0', self.webhook_port)
        await site.start()
        
        logger.info(f"Webhook server started on port {self.webhook_port}")
        logger.info(f"Webhook endpoint: http://localhost:{self.webhook_port}/webhook")

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