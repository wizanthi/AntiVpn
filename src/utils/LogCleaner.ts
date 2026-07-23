import * as fs from 'fs';
import * as path from 'path';
import { Logger } from './Logger';
import { ConfigManager } from '../config/ConfigManager';

// Log cleaner - manages automatic log file cleanup - singleton pattern
export class LogCleaner {
  private static instance: LogCleaner;
  private logger: Logger;
  private config: any;
  private cleanupInterval: NodeJS.Timeout | null = null;

  private constructor() {
    this.logger = Logger.getInstance();
    this.config = ConfigManager.getInstance().getAll();
  }

  static getInstance(): LogCleaner {
    if (!LogCleaner.instance) {
      LogCleaner.instance = new LogCleaner();
    }
    return LogCleaner.instance;
  }

  // Start automatic log cleanup
  startAutoCleanup(): void {
    const intervalHours = this.config.logs?.cleanup_interval_hours ?? 2;
    const intervalMs = intervalHours * 60 * 60 * 1000;
    
    this.logger.info(`Auto log cleanup every ${intervalHours}h`);
    
    // Initial cleanup
    this.cleanup();
    
    // Periodic cleanup
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, intervalMs);
  }

  // Stop automatic log cleanup
  stopAutoCleanup(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }

  // Perform log cleanup
  cleanup(): void {
    const startTime = Date.now();
    const logsDir = path.join(process.cwd(), 'logs');
    const dataDir = path.join(process.cwd(), 'data');
    
    let deletedFiles = 0;
    let freedSpace = 0;

    // Clean log files
    if (fs.existsSync(logsDir)) {
      const files = fs.readdirSync(logsDir);
      const maxAgeDays = this.config.logs?.max_age_days ?? 7;
      const maxAgeMs = maxAgeDays * 24 * 60 * 60 * 1000;
      const keepOnlyToday = this.config.logs?.keep_only_today || false;
      
      for (const file of files) {
        const filePath = path.join(logsDir, file);
        
        try {
          const stats = fs.statSync(filePath);
          const fileAge = Date.now() - stats.mtimeMs;
          
          // Delete files older than max age
          if (fileAge > maxAgeMs) {
            const size = stats.size;
            fs.unlinkSync(filePath);
            deletedFiles++;
            freedSpace += size;
          }
          // Keep only today's files if enabled
          else if (keepOnlyToday) {
            const fileDate = new Date(stats.mtimeMs).toDateString();
            const todayDate = new Date().toDateString();
            if (fileDate !== todayDate) {
              const size = stats.size;
              fs.unlinkSync(filePath);
              deletedFiles++;
              freedSpace += size;
            }
          }
        } catch (error) {
          // Ignore errors for individual files
        }
      }
    }

    // Clean old temporary data files
    if (fs.existsSync(dataDir)) {
      const dataFiles = fs.readdirSync(dataDir);
      
      for (const file of dataFiles) {
        // Skip important files
        if (file === 'whitelist.json' || file === 'blacklist.json' || file === 'checked_ips.json') continue;
        
        const filePath = path.join(dataDir, file);
        
        try {
          const stats = fs.statSync(filePath);
          const fileAge = Date.now() - stats.mtimeMs;
          
          // Delete temp files older than 3 days
          if (fileAge > 3 * 24 * 60 * 60 * 1000 && file.endsWith('.tmp')) {
            const size = stats.size;
            fs.unlinkSync(filePath);
            deletedFiles++;
            freedSpace += size;
          }
        } catch (error) {
          // Ignore errors
        }
      }
    }

    const duration = Date.now() - startTime;
    const freedMB = (freedSpace / 1024 / 1024).toFixed(2);
    
    if (deletedFiles > 0) {
      this.logger.info(`Cleaned ${deletedFiles} files, freed ${freedMB}MB (${duration}ms)`);
    }
  }

  // Get log directory statistics
  getLogStats(): { totalFiles: number; totalSize: number; oldestFile: string } {
    const logsDir = path.join(process.cwd(), 'logs');
    
    if (!fs.existsSync(logsDir)) {
      return { totalFiles: 0, totalSize: 0, oldestFile: 'none' };
    }

    const files = fs.readdirSync(logsDir);
    let totalSize = 0;
    let oldestDate = Date.now();
    let oldestFile = '';

    for (const file of files) {
      try {
        const stats = fs.statSync(path.join(logsDir, file));
        totalSize += stats.size;
        
        if (stats.mtimeMs < oldestDate) {
          oldestDate = stats.mtimeMs;
          oldestFile = file;
        }
      } catch {}
    }

    return {
      totalFiles: files.length,
      totalSize,
      oldestFile: oldestFile || 'none'
    };
  }
}