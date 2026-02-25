#!/usr/bin/env node
// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Temporal worker for Shannon pentest pipeline.
 *
 * Polls the 'shannon-pipeline' task queue and executes activities.
 * Handles up to 25 concurrent activities to support multiple parallel workflows.
 *
 * Usage:
 *   npm run temporal:worker
 *   # or
 *   node dist/temporal/worker.js
 *
 * Environment:
 *   TEMPORAL_ADDRESS - Temporal server address (default: localhost:7233)
 */

import { NativeConnection, Worker, bundleWorkflowCode } from '@temporalio/worker';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import dotenv from 'dotenv';
import * as activities from './activities.js';

dotenv.config();

const CREDENTIALS_PATH = '/app/.claude/.credentials.json';
const TOKEN_POLL_INTERVAL_MS = 60_000;

async function refreshOAuthToken(): Promise<void> {
  try {
    const raw = await readFile(CREDENTIALS_PATH, 'utf-8');
    const creds = JSON.parse(raw) as { claudeAiOauth?: { accessToken?: string } };
    const token = creds.claudeAiOauth?.accessToken;
    if (token && token !== process.env.CLAUDE_CODE_OAUTH_TOKEN) {
      process.env.CLAUDE_CODE_OAUTH_TOKEN = token;
      console.log('OAuth token refreshed from credentials file');
    }
  } catch {
    // File missing or temporarily unreadable — keep using existing token
  }
}

function startCredentialsWatcher(): void {
  void refreshOAuthToken();
  setInterval(() => void refreshOAuthToken(), TOKEN_POLL_INTERVAL_MS);
  console.log('OAuth token watcher started (60s poll interval)');
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function runWorker(): Promise<void> {
  const address = process.env.TEMPORAL_ADDRESS || 'localhost:7233';
  console.log(`Connecting to Temporal at ${address}...`);

  const connection = await NativeConnection.connect({ address });

  // Bundle workflows for Temporal's V8 isolate
  console.log('Bundling workflows...');
  const workflowBundle = await bundleWorkflowCode({
    workflowsPath: path.join(__dirname, 'workflows.js'),
  });

  const worker = await Worker.create({
    connection,
    namespace: 'default',
    workflowBundle,
    activities,
    taskQueue: 'shannon-pipeline',
    maxConcurrentActivityTaskExecutions: 25, // Support multiple parallel workflows (5 agents × ~5 workflows)
  });

  // Graceful shutdown handling
  const shutdown = async (): Promise<void> => {
    console.log('\nShutting down worker...');
    worker.shutdown();
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  startCredentialsWatcher();

  console.log('Shannon worker started');
  console.log('Task queue: shannon-pipeline');
  console.log('Press Ctrl+C to stop\n');

  try {
    await worker.run();
  } finally {
    await connection.close();
    console.log('Worker stopped');
  }
}

runWorker().catch((err) => {
  console.error('Worker failed:', err);
  process.exit(1);
});
