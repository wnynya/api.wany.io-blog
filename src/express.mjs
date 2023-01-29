import config from './config.mjs';

import express from 'express';

const app = express();

/* Body (JSON) parser */
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: 104857600 }));

/* Set middlewares */
import middlewares from '@wnynya/express-middlewares';
import auth from '@wnynya/auth';
import { Logger, console } from '@wnynya/logger';

app.use(middlewares.headers(config.headers)); // Custom response headers
app.use(middlewares.cookies()); // Cookie parser
app.use(middlewares.client()); // Client infomations
app.use(middlewares.JSONResponses()); // JSON response functions
app.use(auth.session(config.session)); // Auth session (req.session)
app.use(auth.account()); // Auth account (req.account)
app.use(middlewares.logger(new Logger(config.logger.req))); // Log request

/* __dirname and __filename */
import path from 'path';
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* Set blog router */
import router from './routes/api-blog.mjs';
app.use('/blog', router);

/* Set 404 */
app.options('*', (req, res) => {
  res.sendStatus(200);
});
app.all('*', (req, res) => {
  res.error('default404');
});

export default app;
