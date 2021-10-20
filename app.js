const express = require('express');
const metadata = require('gcp-metadata');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const oAuth2Client = new OAuth2Client();

// Cache externally fetched information for future invocations
let aud;

const getAudience = async () => {
  if (!aud && (await metadata.isAvailable())) {
    const project_number = await metadata.project('numeric-project-id');
    const project_id = await metadata.project('project-id');

    aud = '/projects/' + project_number + '/apps/' + project_id;
  }
  return aud;
};

const validateAssertion = async (assertion) => {
  if (!assertion) {
    return {};
  }

  // Check that the assertion's audience matches ours
  const aud = await getAudience();

  // Fetch the current certificates and verify the signature on the assertion
  const response = await oAuth2Client.getIapPublicKeys();
  const ticket = await oAuth2Client.verifySignedJwtWithCertsAsync(
    assertion,
    response.pubkeys,
    aud,
    ['https://cloud.google.com/iap']
  );
  const payload = ticket.getPayload();

  // Return the two relevant pieces of information
  return {
    email: payload.email,
    sub: payload.sub,
  };
};

const isValidHttpsUrl = (string) => {
  let url;

  try {
    url = new URL(string);
  } catch (_) {
    return false;
  }
  return url.protocol === 'https:';
};

app.get('/', async (req, res) => {
  const jwtAssertion = req.header('X-Goog-IAP-JWT-Assertion');
  try {
    const info = await validateAssertion(jwtAssertion);
    email = info.email;
    if (req.query.redirect && isValidHttpsUrl(req.query.redirect)) {
      res.redirect(req.query.redirect);
    } else {
      res.status(400).send(`${info.email} ${info.sub}`).end();
    }
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

// Start the server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`App listening on port ${PORT}`);
  console.log('Press Ctrl+C to quit.');
});
