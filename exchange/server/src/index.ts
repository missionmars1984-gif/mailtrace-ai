import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { mailRouter } from './routes/mailRoutes.js';
import { MailboxService } from './services/mailboxService.js';
import { SmtpService } from './services/smtpService.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load .env
dotenv.config({ path: path.resolve(__dirname, '../.env') });
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const app = express();
const PORT = process.env.PORT || 5001;

// Middleware
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

// API Routes
app.use('/api', mailRouter);

// Serve built frontend if available
const clientDist = path.resolve(__dirname, '../../client/dist');
if (fs.existsSync(clientDist)) {
  app.use(express.static(clientDist));
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api')) return next();
    res.sendFile(path.join(clientDist, 'index.html'));
  });
} else {
  app.get('/', (_req, res) => {
    res.json({
      application: 'MailTrace Exchange',
      status: 'ONLINE',
      mode: 'Enterprise Mail Client Backend',
      apiDocs: '/api/status',
    });
  });
}

// Start Server
app.listen(PORT, async () => {
  console.log('=======================================================');
  console.log(` ✉️  MailTrace Exchange Server running on http://localhost:${PORT}`);
  console.log(` 📤 SMTP Relay: ${SmtpService.isConfigured() ? process.env.SMTP_HOST + ':' + (process.env.SMTP_PORT || '1025') : 'NOT CONFIGURED'}`);
  console.log(` 📥 Mailbox Receiver: ${MailboxService.getMode()}`);
  console.log(` 🛡️  SOC Forwarding Bridge: ${process.env.SOC_BACKEND_URL ? 'ACTIVE (' + process.env.SOC_BACKEND_URL + ')' : 'DISABLED'}`);
  console.log('=======================================================');

  // Initial Sync & Background Polling Loop (every 10s)
  MailboxService.sync().catch(() => {});
  setInterval(() => {
    MailboxService.sync().catch(() => {});
  }, 10000);
});
