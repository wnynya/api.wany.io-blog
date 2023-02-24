import config from './config.mjs';
const dev = process.argv.includes('-dev');
config.logger.dir = dev
  ? './logs'
  : '/data/logs/' + process.env.npm_package_name;
config.logger.log.dir = config.logger.dir;
config.logger.req.dir = config.logger.dir;

/* Logger (override console) */
import Logger from '@wnynya/logger';
Logger.setDefaultLogger(new Logger(config.logger.log));
global.console = Logger.getDefaultLogger();

/* MySQLClient */
import MySQLClient from '@wnynya/mysql-client';
MySQLClient.setDefaultClient(new MySQLClient(config.database));

/* Auth */
import auth from '@wnynya/auth';
auth.setMySQLClient(MySQLClient.getDefaultClient());

/* Blog */
import blog from '@wnynya/blog';
blog.setMySQLClient(MySQLClient.getDefaultClient());

import express from './express.mjs';

import http from 'http';
import { exec } from 'child_process';

let port = 80;
for (let i = 0; i < process.argv.length; i++) {
  if (
    process.argv[i] == '-p' &&
    process.argv.length > i + 1 &&
    process.argv[i + 1]
  ) {
    port = process.argv[i + 1];
    i++;
  }
}

exec('kill -9 $(lsof -t -i:' + port + ')', () => {
  console.log(`Server start on port ${port}`);
  http.createServer(express).listen(port);
});
