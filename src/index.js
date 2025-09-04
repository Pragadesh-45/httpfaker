const express = require('express');
const bodyParser = require('body-parser');
const swaggerUi = require('swagger-ui-express');
const openApiSpecification = require('./openapi');
const oauth2ClientCredentials = require('./auth/oauth2/client-credentials');
const bearerAuth = require('./auth/bearer');
const digestAuth = require('./auth/digest');

const echo = require('./echo');
const echoRaw = require('./echo/raw');
const echoCustom = require('./echo/custom');
const generateRandomJson = require('./random/json');

const app = express();
const PORT = 8080;

const saveRawBody = (req, res, buf) => {
  req.rawBuffer = Buffer.from(buf);
  req.rawBody = buf.toString();
};

app.use(bodyParser.json({ verify: saveRawBody }));
app.use(bodyParser.urlencoded({ extended: true, verify: saveRawBody }));
app.use(bodyParser.text({ verify: saveRawBody }));
app.use(express.raw({ type: '*/*', limit: '100mb', verify: saveRawBody }));

app.post('/api/echo', echo);
app.post('/api/echo/raw', echoRaw);
app.post('/api/echo/custom', echoCustom);
app.get('/api/random/json', generateRandomJson);

app.use('/api/auth/oauth2/client-credentials', oauth2ClientCredentials);
app.use('/api/auth/bearer', bearerAuth);
app.use('/api/auth/digest', digestAuth);
app.use('/', swaggerUi.serve);
app.get('/', swaggerUi.setup(openApiSpecification));

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
