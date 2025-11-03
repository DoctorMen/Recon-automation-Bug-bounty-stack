const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const logger = require('../utils/logger');
const database = require('../config/database');

/**
 * SnapshotService - Implements immutable security state snapshots with cryptographic signing
 * 
 * Key Features:
 * - Immutable snapshots with cryptographic signatures
 * - Time-travel debugging between any two states
 * - Complete audit trail with tamper detection
 * - Automatic state reconciliation and drift detection
 */
class SnapshotService {
  constructor(options = {}) {
    this.signingKey = options.signingKey || this.generateSigningKey();
    this.encryptionKey = options.encryptionKey || this.generateEncryptionKey();
    this.algorithm = 'aes-256-gcm';
    this.signatureAlgorithm = 'sha256';
    
    logger.info('SnapshotService initialized with cryptographic signing');
  }

  /**
   * Create a new immutable snapshot of security state
   * @param {Object} data - The security state data to snapshot
   * @param {string} organizationId - Organization ID
   * @param {string} scanId - Associated scan ID
   * @param {Object} metadata - Additional metadata
   * @returns {Object} Created snapshot with signature
   */
  async createSnapshot(data, organizationId, scanId, metadata = {}) {
    try {
      const snapshotId = uuidv4();
      const timestamp = new Date().toISOString();
      
      // Create snapshot structure
      const snapshot = {
        id: snapshotId,
        organizationId,
        scanId,
        timestamp,
        version: '1.0.0',
        metadata: {
          ...metadata,
          createdBy: metadata.userId || 'system',
          source: metadata.source || 'scan',
          environment: process.env.NODE_ENV || 'development'
        },
        data: this.normalizeData(data),
        integrity: {
          checksums: this.calculateChecksums(data),
          itemCount: this.countItems(data),
          dataSize: JSON.stringify(data).length
        }
      };

      // Encrypt sensitive data
      const encryptedData = this.encryptData(snapshot.data);
      
      // Create cryptographic signature
      const signature = this.signSnapshot({
        ...snapshot,
        data: encryptedData
      });

      // Store in database
      const storedSnapshot = await this.storeSnapshot({
        ...snapshot,
        data: encryptedData,
        signature
      });

      logger.info(`Snapshot created: ${snapshotId}`, {
        organizationId,
        scanId,
        dataSize: snapshot.integrity.dataSize,
        itemCount: snapshot.integrity.itemCount
      });

      return {
        id: snapshotId,
        timestamp,
        signature,
        metadata: snapshot.metadata,
        integrity: snapshot.integrity
      };

    } catch (error) {
      logger.error('Failed to create snapshot:', error);
      throw new Error(`Snapshot creation failed: ${error.message}`);
    }
  }

  /**
   * Retrieve and verify a snapshot by ID
   * @param {string} snapshotId - Snapshot ID to retrieve
   * @param {string} organizationId - Organization ID for security
   * @returns {Object} Verified snapshot data
   */
  async getSnapshot(snapshotId, organizationId) {
    try {
      const snapshot = await this.retrieveSnapshot(snapshotId, organizationId);
      
      if (!snapshot) {
        throw new Error('Snapshot not found');
      }

      // Verify signature
      const isValid = this.verifySnapshot(snapshot);
      if (!isValid) {
        logger.error(`Snapshot signature verification failed: ${snapshotId}`);
        throw new Error('Snapshot integrity verification failed');
      }

      // Decrypt data
      const decryptedData = this.decryptData(snapshot.data);

      return {
        ...snapshot,
        data: decryptedData,
        verified: true
      };

    } catch (error) {
      logger.error(`Failed to retrieve snapshot ${snapshotId}:`, error);
      throw error;
    }
  }

  /**
   * Compare two snapshots to detect changes and drift
   * @param {string} beforeSnapshotId - Earlier snapshot ID
   * @param {string} afterSnapshotId - Later snapshot ID
   * @param {string} organizationId - Organization ID
   * @returns {Object} Detailed comparison results
   */
  async compareSnapshots(beforeSnapshotId, afterSnapshotId, organizationId) {
    try {
      const [beforeSnapshot, afterSnapshot] = await Promise.all([
        this.getSnapshot(beforeSnapshotId, organizationId),
        this.getSnapshot(afterSnapshotId, organizationId)
      ]);

      const comparison = {
        id: uuidv4(),
        beforeSnapshot: {
          id: beforeSnapshot.id,
          timestamp: beforeSnapshot.timestamp
        },
        afterSnapshot: {
          id: afterSnapshot.id,
          timestamp: afterSnapshot.timestamp
        },
        timeDelta: new Date(afterSnapshot.timestamp) - new Date(beforeSnapshot.timestamp),
        changes: this.detectChanges(beforeSnapshot.data, afterSnapshot.data),
        drift: this.calculateDrift(beforeSnapshot.data, afterSnapshot.data),
        riskAssessment: this.assessRiskChanges(beforeSnapshot.data, afterSnapshot.data)
      };

      logger.info(`Snapshot comparison completed: ${beforeSnapshotId} -> ${afterSnapshotId}`, {
        changesCount: comparison.changes.length,
        driftScore: comparison.drift.score,
        riskLevel: comparison.riskAssessment.level
      });

      return comparison;

    } catch (error) {
      logger.error('Failed to compare snapshots:', error);
      throw error;
    }
  }

  /**
   * Get snapshot history for time-travel debugging
   * @param {string} organizationId - Organization ID
   * @param {Object} options - Query options
   * @returns {Array} Array of snapshot summaries
   */
  async getSnapshotHistory(organizationId, options = {}) {
    try {
      const {
        scanId,
        startDate,
        endDate,
        limit = 50,
        offset = 0
      } = options;

      const snapshots = await this.querySnapshots({
        organizationId,
        scanId,
        startDate,
        endDate,
        limit,
        offset
      });

      return snapshots.map(snapshot => ({
        id: snapshot.id,
        timestamp: snapshot.timestamp,
        scanId: snapshot.scanId,
        metadata: snapshot.metadata,
        integrity: snapshot.integrity,
        verified: this.verifySnapshot(snapshot)
      }));

    } catch (error) {
      logger.error('Failed to retrieve snapshot history:', error);
      throw error;
    }
  }

  /**
   * Detect configuration drift from baseline
   * @param {string} baselineSnapshotId - Baseline snapshot ID
   * @param {string} currentSnapshotId - Current snapshot ID
   * @param {string} organizationId - Organization ID
   * @returns {Object} Drift analysis results
   */
  async detectDrift(baselineSnapshotId, currentSnapshotId, organizationId) {
    try {
      const comparison = await this.compareSnapshots(baselineSnapshotId, currentSnapshotId, organizationId);
      
      const driftAnalysis = {
        ...comparison.drift,
        recommendations: this.generateDriftRecommendations(comparison.changes),
        autoFixable: this.identifyAutoFixableItems(comparison.changes),
        complianceImpact: this.assessComplianceImpact(comparison.changes)
      };

      return driftAnalysis;

    } catch (error) {
      logger.error('Failed to detect drift:', error);
      throw error;
    }
  }

  // Private helper methods

  generateSigningKey() {
    return crypto.randomBytes(32).toString('hex');
  }

  generateEncryptionKey() {
    return crypto.randomBytes(32);
  }

  normalizeData(data) {
    // Normalize data structure for consistent snapshots
    if (Array.isArray(data)) {
      return data.sort((a, b) => {
        const aKey = a.id || a.url || a.name || JSON.stringify(a);
        const bKey = b.id || b.url || b.name || JSON.stringify(b);
        return aKey.localeCompare(bKey);
      });
    }
    
    if (typeof data === 'object' && data !== null) {
      const normalized = {};
      Object.keys(data).sort().forEach(key => {
        normalized[key] = this.normalizeData(data[key]);
      });
      return normalized;
    }
    
    return data;
  }

  calculateChecksums(data) {
    const jsonString = JSON.stringify(this.normalizeData(data));
    return {
      sha256: crypto.createHash('sha256').update(jsonString).digest('hex'),
      md5: crypto.createHash('md5').update(jsonString).digest('hex')
    };
  }

  countItems(data) {
    if (Array.isArray(data)) {
      return data.length;
    }
    if (typeof data === 'object' && data !== null) {
      return Object.keys(data).length;
    }
    return 1;
  }

  encryptData(data) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher(this.algorithm, this.encryptionKey);
    cipher.setAAD(Buffer.from('snapshot-data'));
    
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex')
    };
  }

  decryptData(encryptedData) {
    const decipher = crypto.createDecipher(this.algorithm, this.encryptionKey);
    decipher.setAAD(Buffer.from('snapshot-data'));
    decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
    
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return JSON.parse(decrypted);
  }

  signSnapshot(snapshot) {
    const dataToSign = JSON.stringify({
      id: snapshot.id,
      timestamp: snapshot.timestamp,
      organizationId: snapshot.organizationId,
      data: snapshot.data,
      integrity: snapshot.integrity
    });

    return crypto
      .createHmac(this.signatureAlgorithm, this.signingKey)
      .update(dataToSign)
      .digest('hex');
  }

  verifySnapshot(snapshot) {
    const expectedSignature = this.signSnapshot(snapshot);
    return crypto.timingSafeEqual(
      Buffer.from(snapshot.signature, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    );
  }

  detectChanges(beforeData, afterData) {
    // Implementation of deep diff algorithm
    const changes = [];
    this.deepDiff(beforeData, afterData, '', changes);
    return changes;
  }

  deepDiff(obj1, obj2, path, changes) {
    const keys = new Set([...Object.keys(obj1 || {}), ...Object.keys(obj2 || {})]);
    
    for (const key of keys) {
      const currentPath = path ? `${path}.${key}` : key;
      const val1 = obj1?.[key];
      const val2 = obj2?.[key];
      
      if (val1 === undefined && val2 !== undefined) {
        changes.push({ type: 'added', path: currentPath, value: val2 });
      } else if (val1 !== undefined && val2 === undefined) {
        changes.push({ type: 'removed', path: currentPath, value: val1 });
      } else if (typeof val1 === 'object' && typeof val2 === 'object') {
        this.deepDiff(val1, val2, currentPath, changes);
      } else if (val1 !== val2) {
        changes.push({ type: 'modified', path: currentPath, oldValue: val1, newValue: val2 });
      }
    }
  }

  calculateDrift(beforeData, afterData) {
    const changes = this.detectChanges(beforeData, afterData);
    const totalItems = this.countItems(beforeData) + this.countItems(afterData);
    
    return {
      score: totalItems > 0 ? (changes.length / totalItems) : 0,
      changeCount: changes.length,
      totalItems,
      severity: this.categorizeDriftSeverity(changes)
    };
  }

  categorizeDriftSeverity(changes) {
    const criticalChanges = changes.filter(c => 
      c.path.includes('vulnerability') || 
      c.path.includes('exposure') ||
      c.path.includes('credential')
    );
    
    if (criticalChanges.length > 0) return 'critical';
    if (changes.length > 10) return 'high';
    if (changes.length > 5) return 'medium';
    return 'low';
  }

  assessRiskChanges(beforeData, afterData) {
    const changes = this.detectChanges(beforeData, afterData);
    
    const riskFactors = {
      newVulnerabilities: 0,
      removedProtections: 0,
      exposureIncrease: 0,
      complianceIssues: 0
    };

    changes.forEach(change => {
      if (change.type === 'added' && change.path.includes('vulnerability')) {
        riskFactors.newVulnerabilities++;
      }
      if (change.type === 'removed' && change.path.includes('protection')) {
        riskFactors.removedProtections++;
      }
      if (change.path.includes('exposure') && change.type === 'modified') {
        riskFactors.exposureIncrease++;
      }
    });

    const totalRisk = Object.values(riskFactors).reduce((sum, count) => sum + count, 0);
    
    return {
      level: totalRisk > 5 ? 'high' : totalRisk > 2 ? 'medium' : 'low',
      factors: riskFactors,
      score: totalRisk
    };
  }

  generateDriftRecommendations(changes) {
    return changes.map(change => ({
      change,
      recommendation: this.getRecommendationForChange(change),
      priority: this.getPriorityForChange(change),
      autoFixable: this.isAutoFixable(change)
    }));
  }

  getRecommendationForChange(change) {
    if (change.path.includes('vulnerability')) {
      return 'Review and remediate new vulnerability findings';
    }
    if (change.path.includes('exposure')) {
      return 'Investigate exposure changes and update security controls';
    }
    return 'Review change and update security configuration if needed';
  }

  getPriorityForChange(change) {
    if (change.path.includes('vulnerability') || change.path.includes('exposure')) {
      return 'high';
    }
    return 'medium';
  }

  isAutoFixable(change) {
    // Define which changes can be automatically fixed
    const autoFixablePatterns = [
      'configuration.ssl',
      'headers.security',
      'permissions.default'
    ];
    
    return autoFixablePatterns.some(pattern => change.path.includes(pattern));
  }

  identifyAutoFixableItems(changes) {
    return changes.filter(change => this.isAutoFixable(change));
  }

  assessComplianceImpact(changes) {
    const complianceFrameworks = ['SOC2', 'ISO27001', 'GDPR', 'HIPAA'];
    const impacts = {};
    
    complianceFrameworks.forEach(framework => {
      impacts[framework] = this.calculateComplianceImpact(changes, framework);
    });
    
    return impacts;
  }

  calculateComplianceImpact(changes, framework) {
    // Simplified compliance impact calculation
    const impactfulChanges = changes.filter(change => 
      change.path.includes('encryption') ||
      change.path.includes('access') ||
      change.path.includes('audit') ||
      change.path.includes('data')
    );
    
    return {
      affected: impactfulChanges.length > 0,
      changeCount: impactfulChanges.length,
      riskLevel: impactfulChanges.length > 3 ? 'high' : impactfulChanges.length > 0 ? 'medium' : 'low'
    };
  }

  // Database operations (to be implemented based on your database choice)
  async storeSnapshot(snapshot) {
    // Implementation depends on database choice (PostgreSQL, etc.)
    // This is a placeholder for the actual database storage
    logger.info('Storing snapshot in database', { id: snapshot.id });
    return snapshot;
  }

  async retrieveSnapshot(snapshotId, organizationId) {
    // Implementation depends on database choice
    logger.info('Retrieving snapshot from database', { id: snapshotId, organizationId });
    return null; // Placeholder
  }

  async querySnapshots(criteria) {
    // Implementation depends on database choice
    logger.info('Querying snapshots with criteria', criteria);
    return []; // Placeholder
  }
}

module.exports = SnapshotService;

