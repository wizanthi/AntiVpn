import * as fs from 'fs';
import * as path from 'path';

// Log levels enum
export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  CRITICAL = 4
}

// Logger - singleton pattern with file and console output
export class Logger {
  private static instance: Logger;
  private logDir: string;
  private logPath: string;
  private level: LogLevel;
  private stream: fs.WriteStream;
  // Date-stamp of the currently open file, so writes crossing midnight roll
  // over to a fresh dated file instead of appending forever to one.
  private currentDay: string;
  // Console echo is synchronous under a redirected/piped stdout (common
  // under a process manager/systemd unit), which is the more expensive
  // half of every log call - file logging (async WriteStream) always
  // stays on. Toggle off via LOG_CONSOLE=0 for a production deployment
  // that only cares about the log file.
  private consoleEnabled: boolean = process.env.LOG_CONSOLE !== '0';

  private constructor() {
    this.logDir = path.join(process.cwd(), 'logs');
    this.level = LogLevel.INFO;

    // Create logs directory if not exists
    if (!fs.existsSync(this.logDir)) {
      fs.mkdirSync(this.logDir, { recursive: true });
    }

    this.currentDay = Logger.today();
    this.logPath = path.join(this.logDir, `bot-${this.currentDay}.log`);
    this.stream = this.openStream();
  }

  private static today(): string {
    return new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  }

  // Opens the active log stream and, critically, attaches an 'error' handler:
  // a WriteStream emits 'error' on any I/O failure (ENOSPC/disk full, EACCES,
  // write-after-close). With no listener, Node re-throws it as an uncaught
  // exception and takes the whole bot down - a logging failure must never do
  // that. We degrade to console instead.
  private openStream(): fs.WriteStream {
    const stream = fs.createWriteStream(this.logPath, { flags: 'a' });
    stream.on('error', (err) => {
      if (this.consoleEnabled) console.error('Logger stream error:', err);
    });
    return stream;
  }

  // Rolls over to a new dated file when the calendar day changes. Dated
  // files (unlike the old single bot.log, whose mtime was always fresh) age
  // out correctly under LogCleaner's max_age_days / keep_only_today rules,
  // so the log corpus is now bounded by the configured retention window
  // instead of growing without limit.
  private rotateIfNeeded(): void {
    const day = Logger.today();
    if (day === this.currentDay) return;
    this.currentDay = day;
    const old = this.stream;
    this.logPath = path.join(this.logDir, `bot-${day}.log`);
    this.stream = this.openStream();
    try { old.end(); } catch { /* ignore */ }
  }

  // Lets a hot call site skip building an expensive `data` payload
  // (formatting an object, computing a breakdown string, etc.) for a level
  // that would be discarded anyway - e.g.
  // `if (logger.isLevelEnabled(LogLevel.DEBUG)) logger.debug(expensiveMsg())`.
  // write() below already skips formatting/serialization for a suppressed
  // level; this just lets the call site avoid computing the message itself.
  isLevelEnabled(level: LogLevel): boolean {
    return level >= this.level;
  }

  static getInstance(): Logger {
    if (!Logger.instance) {
      Logger.instance = new Logger();
    }
    return Logger.instance;
  }

  // Format log message with timestamp
  private formatMessage(level: string, message: string, data?: any): string {
    const timestamp = new Date().toISOString();
    const base = `[${timestamp}] [${level}] ${message}`;
    
    if (data) {
      try {
        return `${base} | ${this.serializeData(data)}`;
      } catch {
        return `${base} | [Unserializable data]`;
      }
    }
    
    return base;
  }

  private serializeData(data: any): string {
    if (data instanceof Error) {
      return JSON.stringify({
        name: data.name,
        message: data.message,
        stack: data.stack
      });
    }

    return JSON.stringify(data, (_key, value) => {
      if (value instanceof Error) {
        return {
          name: value.name,
          message: value.message,
          stack: value.stack
        };
      }
      return value;
    });
  }

  // Write log entry to console and file
  private write(level: LogLevel, levelStr: string, message: string, data?: any): void {
    if (level < this.level) return;

    const formatted = this.formatMessage(levelStr, message, data);

    if (this.consoleEnabled) {
      // Console output with colors
      const colors: Record<string, string> = {
        'DEBUG': '\x1b[36m',
        'INFO': '\x1b[32m',
        'WARN': '\x1b[33m',
        'ERROR': '\x1b[31m',
        'CRITICAL': '\x1b[35m'
      };
      console.log(`${colors[levelStr] || ''}${formatted}\x1b[0m`);
    }

    // File output (roll the dated file over first if the day changed)
    this.rotateIfNeeded();
    this.stream.write(formatted + '\n');
  }

  // Debug level log
  debug(message: string, data?: any): void {
    this.write(LogLevel.DEBUG, 'DEBUG', message, data);
  }

  // Info level log
  info(message: string, data?: any): void {
    this.write(LogLevel.INFO, 'INFO', message, data);
  }

  // Warning level log
  warn(message: string, data?: any): void {
    this.write(LogLevel.WARN, 'WARN', message, data);
  }

  // Error level log
  error(message: string, data?: any): void {
    this.write(LogLevel.ERROR, 'ERROR', message, data);
  }

  // Critical level log
  critical(message: string, data?: any): void {
    this.write(LogLevel.CRITICAL, 'CRITICAL', message, data);
  }

  // Set minimum log level
  setLevel(level: LogLevel): void {
    this.level = level;
  }

  // Close log stream
  close(): void {
    this.stream.end();
  }
}
