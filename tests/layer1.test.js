const { describe, test, expect, beforeEach, jest } = require('@jest/globals');

// ============================================================
// Mock implementations for Layer 1 sanitization modules
// ============================================================

// Image metadata stripping module
class ImageMetadataStripper {
  strip(buffer) {
    if (!buffer || buffer.length === 0) {
      throw new Error('Empty buffer provided');
    }
    if (!(buffer instanceof Buffer)) {
      throw new Error('Input must be a Buffer');
    }
    // Simulate stripping EXIF, GPS, IPTC, XMP metadata
    const metadata = this.extractMetadata(buffer);
    const cleanBuffer = this.removeMetadataChunks(buffer);
    return {
      cleanBuffer,
      strippedFields: metadata,
      originalSize: buffer.length,
      cleanSize: cleanBuffer.length,
    };
  }

  extractMetadata(buffer) {
    const fields = [];
    const bufStr = buffer.toString('binary');
    if (bufStr.includes('Exif')) fields.push('EXIF');
    if (bufStr.includes('GPS')) fields.push('GPS');
    if (bufStr.includes('IPTC')) fields.push('IPTC');
    if (bufStr.includes('XMP')) fields.push('XMP');
    if (bufStr.includes('MakerNote')) fields.push('MakerNote');
    return fields;
  }

  removeMetadataChunks(buffer) {
    let cleaned = buffer.toString('binary');
    const metaTags = ['Exif', 'GPS', 'IPTC', 'XMP', 'MakerNote'];
    for (const tag of metaTags) {
      cleaned = cleaned.split(tag).join('');
    }
    return Buffer.from(cleaned, 'binary');
  }
}

// Prompt injection detection module
class PromptInjectionDetector {
  constructor(options = {}) {
    this.patterns = [
      /ignore\s+(all\s+)?previous\s+instructions/i,
      /disregard\s+(all\s+)?(prior|previous|above)\s+(instructions|prompts|rules)/i,
      /you\s+are\s+now\s+(a|an)\s+/i,
      /system\s*:\s*/i,
      /\[INST\]/i,
      /<<SYS>>/i,
      /\{\{.*system.*\}\}/i,
      /pretend\s+you\s+are/i,
      /act\s+as\s+(if\s+you\s+are|a)\s+/i,
      /forget\s+(all\s+)?(your|previous)\s+(instructions|rules|training)/i,
      /override\s+(your|all|the)\s+(instructions|rules|safety)/i,
      /jailbreak/i,
      /DAN\s+mode/i,
      /do\s+anything\s+now/i,
      /bypass\s+(your|the|all)\s+(filter|safety|restriction)/i,
      /\bROLE:\s*system\b/i,
      /