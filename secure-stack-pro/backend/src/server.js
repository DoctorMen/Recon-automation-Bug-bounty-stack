const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { createServer } = require('http');
const { Server } = require('socket.io');
require('dotenv').config();

const logger = require('./utils/logger');
const database = require('./config/database');
const redis = require('./config/redis');
const errorHandler = require('./middleware/errorHandler');
const authMiddleware = require('./middleware/auth');

// Import routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const organizationRoutes = require('./routes/organizations');
const scanRoutes = require('./routes/scans');
const snapshotRoutes = require('./routes/snapshots');
const dashboardRoutes = require('./routes/dashboard');
const complianceRoutes = require('./routes/compliance');
const webhookRoutes = require('./routes/webhooks');

// Import services
const SnapshotService = require('./services/SnapshotService');
const ScanEngine = require('./services/ScanEngine');
const AIInsightsService = require('./services/AIInsightsService');

class SecureStackProServer {
  constructor() {
    this.app = express();
    this.server = createServer(this.app);
    this.io = new Server(this.server, {
      cors: {
        origin: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
        methods: ['GET', 'POST'],
        credentials: true
      }
    });
    
    this.port = process.env.PORT || 3001;
    this.host = process.env.HOST || 'localhost';
  }

  async initialize() {
    try {
      // Initialize database
      await database.initialize();
      logger.info('Database initialized successfully');

      // Initialize Redis
      await redis.initialize();
      logger.info('Redis initialized successfully');

      // Initialize services
      await this.initializeServices();
      
      // Setup middleware
      this.setupMiddleware();
      
      // Setup routes
      this.setupRoutes();
      
      // Setup WebSocket handlers
      this.setupWebSocketHandlers();
      
      // Setup error handling
      this.setupErrorHandling();
      
      logger.info('Server initialization completed');
    } catch (error) {
      logger.error('Failed to initialize server:', error);
      process.exit(1);
    }
  }

  async initializeServices() {
    // Initialize Snapshot Service with cryptographic signing
    this.snapshotService = new SnapshotService({
      signingKey: process.env.SNAPSHOT_SIGNING_KEY,
      encryptionKey: process.env.ENCRYPTION_KEY
    });

    // Initialize Scan Engine with idempotent operations
    this.scanEngine = new ScanEngine({
      nucleiPath: process.env.NUCLEI_PATH,
      subfinderPath: process.env.SUBFINDER_PATH,
      httpxPath: process.env.HTTPX_PATH,
      nmapPath: process.env.NMAP_PATH
    });

    // Initialize AI Insights Service
    this.aiInsightsService = new AIInsightsService({
      openaiApiKey: process.env.OPENAI_API_KEY,
      model: process.env.OPENAI_MODEL,
      pineconeApiKey: process.env.PINECONE_API_KEY,
      pineconeIndexName: process.env.PINECONE_INDEX_NAME
    });

    // Make services available globally
    this.app.locals.services = {
      snapshot: this.snapshotService,
      scanEngine: this.scanEngine,
      aiInsights: this.aiInsightsService
    };

    logger.info('All services initialized successfully');
  }

  setupMiddleware() {
    // Security middleware
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: ["'self'", "wss:", "https:"]
        }
      },
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
      }
    }));

    // CORS configuration
    this.app.use(cors({
      origin: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
    }));

    // Rate limiting
    const limiter = rateLimit({
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
      max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
      message: {
        error: 'Too many requests from this IP, please try again later.',
        retryAfter: Math.ceil((parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000) / 1000)
      },
      standardHeaders: true,
      legacyHeaders: false
    });
    this.app.use('/api/', limiter);

    // Body parsing middleware
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // Request logging
    this.app.use((req, res, next) => {
      logger.info(`${req.method} ${req.path}`, {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        requestId: req.id
      });
      next();
    });
  }

  setupRoutes() {
    // Health check endpoint
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        version: require('../package.json').version
      });
    });

    // API routes
    this.app.use('/api/auth', authRoutes);
    this.app.use('/api/users', authMiddleware, userRoutes);
    this.app.use('/api/organizations', authMiddleware, organizationRoutes);
    this.app.use('/api/scans', authMiddleware, scanRoutes);
    this.app.use('/api/snapshots', authMiddleware, snapshotRoutes);
    this.app.use('/api/dashboard', authMiddleware, dashboardRoutes);
    this.app.use('/api/compliance', authMiddleware, complianceRoutes);
    
    // Webhook routes (no auth required)
    this.app.use('/webhooks', webhookRoutes);

    // 404 handler
    this.app.use('*', (req, res) => {
      res.status(404).json({
        error: 'Endpoint not found',
        path: req.originalUrl,
        method: req.method
      });
    });
  }

  setupWebSocketHandlers() {
    this.io.use((socket, next) => {
      // WebSocket authentication
      const token = socket.handshake.auth.token;
      if (!token) {
        return next(new Error('Authentication error'));
      }
      
      // Verify JWT token here
      // ... token verification logic
      
      next();
    });

    this.io.on('connection', (socket) => {
      logger.info(`Client connected: ${socket.id}`);

      // Join organization room for real-time updates
      socket.on('join-organization', (organizationId) => {
        socket.join(`org-${organizationId}`);
        logger.info(`Socket ${socket.id} joined organization ${organizationId}`);
      });

      // Handle scan status subscriptions
      socket.on('subscribe-scan', (scanId) => {
        socket.join(`scan-${scanId}`);
        logger.info(`Socket ${socket.id} subscribed to scan ${scanId}`);
      });

      socket.on('disconnect', () => {
        logger.info(`Client disconnected: ${socket.id}`);
      });
    });

    // Make socket.io available to routes
    this.app.locals.io = this.io;
  }

  setupErrorHandling() {
    this.app.use(errorHandler);

    // Unhandled promise rejections
    process.on('unhandledRejection', (reason, promise) => {
      logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
    });

    // Uncaught exceptions
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught Exception:', error);
      process.exit(1);
    });

    // Graceful shutdown
    process.on('SIGTERM', () => {
      logger.info('SIGTERM received, shutting down gracefully');
      this.shutdown();
    });

    process.on('SIGINT', () => {
      logger.info('SIGINT received, shutting down gracefully');
      this.shutdown();
    });
  }

  async shutdown() {
    try {
      logger.info('Starting graceful shutdown...');
      
      // Close HTTP server
      await new Promise((resolve) => {
        this.server.close(resolve);
      });
      
      // Close database connections
      await database.close();
      
      // Close Redis connections
      await redis.close();
      
      logger.info('Graceful shutdown completed');
      process.exit(0);
    } catch (error) {
      logger.error('Error during shutdown:', error);
      process.exit(1);
    }
  }

  async start() {
    await this.initialize();
    
    this.server.listen(this.port, this.host, () => {
      logger.info(`SecureStack Pro server running on ${this.host}:${this.port}`);
      logger.info(`Environment: ${process.env.NODE_ENV}`);
      logger.info(`Process ID: ${process.pid}`);
    });
  }
}

// Start the server
if (require.main === module) {
  const server = new SecureStackProServer();
  server.start().catch((error) => {
    logger.error('Failed to start server:', error);
    process.exit(1);
  });
}

module.exports = SecureStackProServer;

