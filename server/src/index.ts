import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { apiRouter, runAnalysisPipeline } from './routes/api.js';
import { GeminiClient } from './ai/geminiClient.js';


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables
dotenv.config({ path: path.resolve(__dirname, '../.env') });

const app = express();
const PORT = process.env.PORT || 5000;

// Security & Middleware
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

// Initialize AI Client
GeminiClient.initialize();

import fs from 'node:fs';

// Mount API routes
app.use('/api', apiRouter);

// Serve static client assets if built
const clientDist = path.resolve(__dirname, '../../client/dist');
if (fs.existsSync(clientDist)) {
  app.use(express.static(clientDist));
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api')) return next();
    res.sendFile(path.join(clientDist, 'index.html'));
  });
} else {
  // Root healthcheck fallback if client is not built
  app.get('/', (_req, res) => {
    res.json({
      app: 'MailTrace AI Server',
      status: 'READY',
      docs: '/api/status',
    });
  });
}



// Start Server
app.listen(PORT, async () => {
  console.log(`=======================================================`);
  console.log(` 🛡️  MailTrace AI Server running on http://localhost:${PORT}`);
  console.log(` 🔑  Gemini API Key: ${process.env.GEMINI_API_KEY ? 'CONFIGURED' : 'NOT SET (Fallback Active)'}`);
  console.log(` 📦  Database: SQLite (node:sqlite) — Ready for incoming user investigations`);
  console.log(`=======================================================`);
});
