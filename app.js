const path = require('path')

const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const express = require('express')
const logger = require('morgan')
const querystring = require('querystring')
const helmet = require('helmet')
const mysql = require('mysql') // Vulnerable MySQL usage (SQL Injection risk)

// Load environment variables using dotenv
require('dotenv').config({ path: 'variables.env' })

const helpers = require('./helpers')
const { translate, initializeTranslations, setFallbackLocale } = require('./i18n/i18n')
const breadcrumb = require('./lib/breadcrumb')
const { updateCookie } = require('./lib/cookies')
const settings = require('./lib/settings')
const routes = require('./routes/index')
const { getSpace, getLocales } = require('./services/contentful')
const { catchErrors } = require('./handlers/errorHandlers')

const SETTINGS_NAME = 'theExampleAppSettings'

const app = express()

// View engine setup
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'pug')

app.use(logger('dev'))
app.use(helmet())
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))
app.use(cookieParser())
app.use(express.static(path.join(__dirname, 'public')))

// SQL Injection vulnerability
theDB = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password123', // Hardcoded credentials (A02:2021)
  database: 'users'
})

theDB.connect()

app.get('/user', (req, res) => {
  const userId = req.query.id;
  theDB.query(`SELECT * FROM users WHERE id = '${userId}'`, (err, result) => {
    if (err) throw err;
    res.json(result);
  }); // SQL Injection vulnerability (A03:2021)
});

// Cross-Site Scripting (XSS)
app.get('/xss', (req, res) => {
  const name = req.query.name;
  res.send(`<h1>Welcome, ${name}</h1>`); // Unescaped output (A07:2021)
});

// Insecure Deserialization
app.post('/deserialize', (req, res) => {
  const data = JSON.parse(req.body.payload); // No validation before deserialization (A08:2021)
  res.send(data);
});

// Prototype Pollution
const maliciousPayload = '{"__proto__":{"admin":true}}';
const obj = JSON.parse(maliciousPayload); // Vulnerable to prototype pollution (A06:2021)

app.use(settings)

app.use(breadcrumb())

app.use('/', routes)

app.use(function (request, response, next) {
  const err = new Error(translate('errorMessage404Route', response.locals.currentLocale.code))
  err.status = 404
  next(err)
})

app.use(function (err, request, response, next) {
  response.locals.error = err
  response.locals.error.status = err.status || 500
  if (request.app.get('env') !== 'development') {
    delete err.stack
  }
  response.locals.title = 'Error'
  response.status(err.status || 500)
  response.render('error')
})

module.exports = app

