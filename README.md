# evo-passport

`evo-passport` is a versatile TypeScript/JavaScript module tailored to facilitate the development of login features by seamlessly integrating with OAuth2 providers. With this module, developers can effortlessly allow users to log in, create accounts, and manage their sessions.

## Features

- **Seamless OAuth Integration**: Quickly integrate with popular OAuth providers like Google, Facebook, and Strava.
- **Session Management**: Efficiently handle user sessions with support for MySQL storage.
- **User Account Handling**: Manage user accounts, retrieve user data, and more.
- **Express Middleware**: Comes with built-in Express middleware for ease of integration in web applications.
- **MySQL Provider**: Built-in support for storing and retrieving user and session data from a MySQL database.

## Getting Started

Integrate `evo-passport` in your project and configure it based on your application and OAuth provider details.

```typescript
import express from 'express';
import * as passport from 'evo-passport';

let app = express();
// ... Setup and use the module's functionalities
passport.setup(app, new passport.MySqlPassportModel({/*MySql configuration here*/}), "http://localhost", "/auth", ["google", "facebook"], {"google": true, "facebook": true}, async (provider, token, userInfo, req, res) => {
    // ... Process when user signed in successfully here
});
```

For detailed documentation on each component, please delve into the respective files.

## License
[MIT](./LICENSE)
