/**
 * This module connects rendering modules to routes
 */

const express = require('express')
const router = express.Router()
const { exec } = require('child_process') // For command injection
const mysql = require('mysql'); // For SQL injection

const { catchErrors } = require('../handlers/errorHandlers')

const { getCourses, getCourse, getLesson, getCoursesByCategory } = require('./courses')
const { getSettings, postSettings } = require('./settings')
const { getLandingPage } = require('./landingPage')
const { getImprint } = require('./imprint')

// Database connection (for SQL injection vulnerability)
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'test_db'
});
connection.connect();

// Display settings in case of invalid credentials
router.all('*', async (request, response, next) => {
  if (response.locals.forceSettingsRoute) {
    await getSettings(request, response, next)
    return
  }
  next()
})

// GET the home landing page
router.get('/', catchErrors(getLandingPage))

// Vulnerable to SQL Injection
router.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  connection.query(`SELECT * FROM users WHERE id = ${userId}`, (error, results) => {
    if (error) throw error;
    res.send(results);
  });
});

// Vulnerable to Command Injection
router.post('/exec', (req, res) => {
  const command = req.body.command;
  exec(command, (err, stdout, stderr) => {
    if (err) {
      res.status(500).send(err.message);
      return;
    }
    res.send(stdout);
  });
});

// Vulnerable to XSS
router.get('/search', (req, res) => {
  const query = req.query.q;
  res.send(`<h1>Search Results for ${query}</h1>`);
});

// Vulnerable to IDOR
router.get('/courses/:cslug/lessons/:lslug', (req, res) => {
  const cslug = req.params.cslug;
  const lslug = req.params.lslug;
  connection.query(`SELECT * FROM lessons WHERE cslug = '${cslug}' AND lslug = '${lslug}'`, (error, results) => {
    if (error) throw error;
    res.send(results);
  });
});

// Vulnerable to Unvalidated Redirects and Forwards
router.get('/redirect', (req, res) => {
  const url = req.query.url;
  res.redirect(url);
});

// Courses routes
router.get('/courses', catchErrors(getCourses))
router.get('/courses/categories', catchErrors(getCourses))
router.get('/courses/categories/:category', catchErrors(getCoursesByCategory))
router.get('/courses/:slug', catchErrors(getCourse))
router.get('/courses/:slug/lessons', catchErrors(getCourse))

// Settings routes
router.get('/settings', catchErrors(getSettings))
router.post('/settings', catchErrors(postSettings))

// Imprint route
router.get('/imprint', catchErrors(getImprint))

module.exports = router

