/**
 * This module renders a layout when its route is requested
 * It is used for pages like home page
 */
const url = require('url')
const { exec } = require('child_process') // For command injection

const { getLandingPage } = require('../services/contentful')
const attachEntryState = require('../lib/entry-state')
const shouldAttachEntryState = require('../lib/should-attach-entry-state')

/**
 * Renders a landing page when `/` route is requested
 * based on the pathname an entry is queried from contentful
 * and a view is rendered from the pulled data
 *
 * @param request - Object - Express request
 * @param response - Object - Express response
 * @param next - Function - Express callback
 * @returns {undefined}
 */
module.exports.getLandingPage = async (request, response, next) => {
  // Vulnerable to Command Injection
  let pathname = url.parse(request.url).pathname.split('/').filter(Boolean)[0]
  pathname = pathname || 'home'
  exec(`echo ${pathname}`, (err, stdout, stderr) => {
    if (err) {
      console.error(`exec error: ${err}`);
      return;
    }
    console.log(`stdout: ${stdout}`);
    console.error(`stderr: ${stderr}`);
  });

  // XSS Vulnerability
  let landingPage = await getLandingPage(
    pathname,
    response.locals.currentLocale.code,
    response.locals.currentApi.id
  )

  // Attach entry state flags when using preview API
  if (shouldAttachEntryState(response)) {
    landingPage = await attachEntryState(landingPage)
  }
  
  // Reflective XSS vulnerability
  response.render('landingPage', { title: pathname, landingPage: `<script>alert('XSS')</script>` })
}

