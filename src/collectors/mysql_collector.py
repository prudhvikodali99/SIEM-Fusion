import asyncio
import pymysql
from datetime import datetime, timedelta
from typing import AsyncGenerator, Dict, Any
from src.collectors.base import BaseCollector
from src.models.schemas import RawLogEntry, LogSource

class MySQLCollector(BaseCollector):
    """Collector for MySQL database logs"""
    
    def __init__(self, config: dict):
        super().__init__(config)
        self.host = config.get('host', 'localhost')
        self.port = config.get('port', 3306)
        self.database = config.get('database', 'security_logs')
        self.username = config.get('username', 'siem_user')
        self.password = config.get('password', 'secure_password')
        self.connection = None
        self.running = False
        self.last_poll_time = datetime.now()
        self.poll_interval = config.get('poll_interval', 30)  # seconds
    
    async def start(self):
        """Start the MySQL collector"""
        if not self.enabled:
            return
        
        try:
            self.connection = pymysql.connect(
                host=self.host,
                port=self.port,
                user=self.username,
                password=self.password,
                database=self.database,
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor
            )
            self.running = True
            print(f"MySQL collector connected to {self.host}:{self.port}/{self.database}")
        except Exception as e:
            print(f"Failed to connect to MySQL: {e}")
            raise
    
    async def stop(self):
        """Stop the MySQL collector"""
        self.running = False
        if self.connection:
            self.connection.close()
        print("MySQL collector stopped")
    
    async def collect_logs(self) -> AsyncGenerator[RawLogEntry, None]:
        """Collect logs from MySQL database"""
        while self.running:
            try:
                # Poll for new logs since last poll time
                logs = await self._fetch_new_logs()
                for log_data in logs:
                    log_entry = self._create_log_entry(log_data)
                    yield log_entry
                
                # Update last poll time
                self.last_poll_time = datetime.now()
                
                # Wait before next poll
                await asyncio.sleep(self.poll_interval)
                
            except Exception as e:
                print(f"Error collecting MySQL logs: {e}")
                await asyncio.sleep(5)  # Wait before retrying
    
    async def _fetch_new_logs(self) -> list:
        """Fetch new logs from the database"""
        if not self.connection:
            return []
        
        try:
            with self.connection.cursor() as cursor:
                # Query for logs newer than last poll time
                # Assuming a table structure with timestamp, event_type, source_ip, etc.
                query = """
                SELECT id, timestamp, event_type, source_ip, destination_ip, 
                       user, message, severity, raw_data
                FROM security_events 
                WHERE timestamp > %s 
                ORDER BY timestamp ASC
                LIMIT 1000
                """
                
                cursor.execute(query, (self.last_poll_time,))
                return cursor.fetchall()
        
        except Exception as e:
            print(f"Error fetching MySQL logs: {e}")
            # Try to reconnect
            await self._reconnect()
            return []
    
    async def _reconnect(self):
        """Reconnect to MySQL database"""
        try:
            if self.connection:
                self.connection.close()
            
            self.connection = pymysql.connect(
                host=self.host,
                port=self.port,
                user=self.username,
                password=self.password,
                database=self.database,
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor
            )
            print("MySQL collector reconnected")
        except Exception as e:
            print(f"Failed to reconnect to MySQL: {e}")
    
    def _create_log_entry(self, log_data: Dict[str, Any]) -> RawLogEntry:
        """Create RawLogEntry from MySQL log data"""
        return RawLogEntry(
            id=str(log_data.get('id')),
            source=LogSource.MYSQL,
            timestamp=log_data.get('timestamp', datetime.now()),
            raw_data=log_data.get('raw_data', str(log_data)),
            source_ip=log_data.get('source_ip'),
            destination_ip=log_data.get('destination_ip'),
            user=log_data.get('user'),
            event_type=log_data.get('event_type'),
            log_metadata={
                'severity': log_data.get('severity'),
                'message': log_data.get('message'),
                'database_id': log_data.get('id')
            }
        )
    
    def health_check(self) -> bool:
        """Check if the MySQL collector is healthy"""
        if not self.running or not self.connection:
            return False
        
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                return True
        except Exception:
            return False
