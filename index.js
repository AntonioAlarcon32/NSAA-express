const express = require('express')
const logger = require('morgan')
const jwt = require('jsonwebtoken')
const passport = require('passport')
const cookieParser = require('cookie-parser')
const LocalStrategy = require('passport-local').Strategy
const JwtStrategy = require('passport-jwt').Strategy
const GitHubStrategy = require('passport-github2').Strategy
const CustomStrategy = require('passport-custom').Strategy
const OpenIDConnectStrategy = require('openid-client').Strategy
const { Issuer, custom } = require('openid-client');
const { Sequelize } = require('sequelize')
const { Model, DataTypes } = require('sequelize')
const { hash, verify } =  require('scrypt-mcf')
const fs = require('fs')
const https = require('https')
const SQLite = require('sqlite3')
const Client = require('node-radius-client');

custom.setHttpOptionsDefaults({
  timeout: 10000,
});

const {
  dictionaries: {
    rfc2865: {
      file,
      attributes,
    },
  },
} = require('node-radius-utils');


const app = express()
const jwtSecret = require('crypto').randomBytes(16)

require('dotenv').config();

app.use(session({
  secret: 'secret', // You should use a long, random, and secure string.
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: true, // Ensuring cookies are only used over HTTPS
    httpOnly: true // Ensuring cookies do not get accessed via client-side scripts
  }
}));

const radius = new Client({
  host: process.env.RADIUS_IP,
})

const sequelize = new Sequelize('expressapp', 'root', 'passw', {
    host: 'localhost',
    dialect: 'sqlite',
    storage: './database.sqlite', // or ':memory:'
    dialectOptions: {
      // Your sqlite3 options here
      // for instance, this is how you can configure the database opening mode:
      mode: SQLite.OPEN_READWRITE | SQLite.OPEN_CREATE | SQLite.OPEN_FULLMUTEX,
    },
  });


app.use(logger('dev'))

class User extends Model {}

User.init({
  username: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  password: {
    type: DataTypes.STRING,
    allowNull: true,
  }
}, {
  // Other model options go here
  sequelize, // We need to pass the connection instance
  modelName: 'User' // We need to choose the model name
})
console.log(User === sequelize.models.User); // true


sequelize.sync({ force: true }).then(() => {
    console.log("Database & tables created")
}).then(() => {
    const mcfString = hash('walrus', { derivedKeyLength: 64, scryptParams: { logN: 19, r: 8, p: 2 } }).then((mcfString) => {
        console.log(mcfString);
        User.create({
            username: 'walrus',
            password: mcfString,
          }).then(user => {
            console.log(user.id);
          });
    })  
}).then(() => { 
  const mcfString = hash('exam', { derivedKeyLength: 64, scryptParams: { logN: 19, r: 8, p: 2 } }).then((mcfString) => {
    console.log(mcfString);
    User.create({
        username: 'alanis',
        password: mcfString,
      }).then(user => {
        console.log(user.id);
      });
})  
})

/*
Configure the local strategy for using it in Passport.
The local strategy requires a `verify` function which receives the credentials
(`username` and `password`) submitted by the user.  The function must verify
that the username and password are correct and then invoke `done` with a user
object, which will be set at `req.user` in route handlers after authentication.
*/
passport.use('username-password', new LocalStrategy(
  {
    usernameField: 'username',  // it MUST match the name of the input field for the username in the login HTML formulary
    passwordField: 'password',  // it MUST match the name of the input field for the password in the login HTML formulary
    session: false // we will store a JWT in the cookie with all the required session data. Our server does not need to keep a session, it's going to be stateless
  },
  function (username, password, done) {

    const user = User.findOne({ where: { username: username } }).then((user) => {
        if (!user) {
            return done(null, false);
        }
        const isPasswordCorrect = verify(password, user.password).then((isPasswordCorrect) => {
            if (isPasswordCorrect) {
                return done(null, user)
            }
            return done(null, false)
        })
    }) 
  }
))

passport.use('jwtCookie', new JwtStrategy(
    {
      jwtFromRequest: (req) => {
        if (req && req.cookies) { return req.cookies.jwt }
        return null
      },
      secretOrKey: jwtSecret
    },
    function (jwtPayload, done) {
      if (jwtPayload.sub) {
        const user = { 
          username: jwtPayload.sub,
          description: 'one of the users that deserve to get to this server',
          role: jwtPayload.role ?? 'user'
        }
        return done(null, user)
      }
      return done(null, false)
    }
))

passport.use('jwtExaminers', new JwtStrategy(
  {
    jwtFromRequest: (req) => {
      if (req && req.cookies) { return req.cookies.jwt }
      return null
    },
    secretOrKey: jwtSecret
  },
  function (jwtPayload, done) {
    if (jwtPayload.sub) {
      const user = { 
        username: jwtPayload.sub,
        description: 'one of the users that deserve to get to this server',
        role: jwtPayload.role ?? 'user'
      }
      if (jwtPayload.examiner === 'true') {
        return done(null, user)
      }
      return done(null, false)
    }
    return done(null, false)
  }
))

passport.use('radius', new CustomStrategy(
  function(req, done) {
    let username = req.body.username;
    let password = req.body.password;
    radius.accessRequest({
      secret: process.env.RADIUS_SECRET,
      attributes: [
        [attributes.USER_NAME, username + "@upc.edu"],
        [attributes.USER_PASSWORD, password],
      ],
    }).then((result) => {
      if (result.code === 'Access-Accept') {
        return done(null, { username: username });
      }
      return done(null, false);
    }).catch((error) => {
      return done(null, false);
    });
  }
))

const oidcIssuer = Issuer.discover("https://accounts.google.com").then((issuer) => {
  console.log('Discovered issuer %s %O', issuer.issuer, issuer.metadata);
  const oidcClient = new issuer.Client({
    client_id: process.env.GOOGLE_CLIENT_ID,
    client_secret: process.env.GOOGLE_CLIENT_SECRET,
    redirect_uris: ['https://localhost/auth/oidc/callback'],
    response_types: ['code']
  })
  
  passport.use('oidc', new OpenIDConnectStrategy({
    client: oidcClient,
    usePKCE: false,
    params: {
      scope: 'openid email profile',  // Include scopes here
    }
    }, function verify(tokenSet, profile, done) {
      console.log(profile);
      User.findOrCreate({ where: { username: profile.email } }).then((user) => {
        return done(null, user[0]);
      })
    }))
})


passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: "https://localhost/auth/github/callback"
},
function(accessToken, refreshToken, profile, done) {
  User.findOrCreate({ where: { username: profile.username } }).then((user) => {
    return done(null, user[0]);
  })
}
));

app.use(cookieParser())
app.use(express.urlencoded({ extended: true })) // needed to retrieve html form fields (it's a requirement of the local strategy)
app.use(passport.initialize())  // we load the passport auth middleware to our express application. It should be loaded before any route.

app.get('/',passport.authenticate('jwtCookie', { session: false, failureRedirect: '/login' }),
  (req, res) => {
    res.send(`Welcome to your private page, ${req.user.username}!`) // we can get the username from the req.user object provided by the jwtCookie strategy
  }
)

app.get('/login',
  (req, res) => {
    res.sendFile('login.html', { root: __dirname })  // we created this file before, which defines an HTML form for POSTing the user's credentials to POST /login
  }
)
app.get('/radlogin',
  (req, res) => {
    res.sendFile('radlogin.html', { root: __dirname })  // we created this file before, which defines an HTML form for POSTing the user's credentials to POST /login
  }
)

app.post('/login', 
  passport.authenticate('username-password', { failureRedirect: '/login', session: false }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
  (req, res) => { 
    const jwtClaims = {
        sub: req.user.username,
        iss: 'localhost',
        aud: 'localhost',
        exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
        role: 'user' // just to show a private JWT field
    }
    if (req.user.username === 'alanis') {
        jwtClaims.examiner = 'true'
    }
    console.log(req.user)
    const token = jwt.sign(jwtClaims, jwtSecret)
    res.cookie('jwt', token, { httpOnly: true, secure: true }) // Write the token to a cookie with name 'jwt' and enable the flags httpOnly and secure.
    res.redirect('/')
  }
)

app.post('/radlogin', 
  passport.authenticate('radius', { failureRedirect: '/login', session: false }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
  (req, res) => { 
    const jwtClaims = {
        sub: req.user.username,
        iss: 'localhost',
        aud: 'localhost',
        exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
        role: 'user' // just to show a private JWT field
    }
    const token = jwt.sign(jwtClaims, jwtSecret)
    res.cookie('jwt', token, { httpOnly: true, secure: true }) // Write the token to a cookie with name 'jwt' and enable the flags httpOnly and secure.
    res.redirect('/')
  }
)

app.get('/auth/github/callback', 
  passport.authenticate('github', { failureRedirect: '/login', session: false}),
  function(req, res) {
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost',
      aud: 'localhost',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
      role: 'user' // just to show a private JWT field
  }
  const token = jwt.sign(jwtClaims, jwtSecret)
  res.cookie('jwt', token, { httpOnly: true, secure: true }) // Write the token to a cookie with name 'jwt' and enable the flags httpOnly and secure.
  res.redirect('/')
});

app.get('/auth/oidc/callback', 
  passport.authenticate('oidc', { failureRedirect: '/login', session: false}),
  function(req, res) {
    console.log(req.user.username);
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost',
      aud: 'localhost',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
      role: 'user' // just to show a private JWT field
  }
  const token = jwt.sign(jwtClaims, jwtSecret)
  res.cookie('jwt', token, { httpOnly: true, secure: true }) // Write the token to a cookie with name 'jwt' and enable the flags httpOnly and secure.
  res.redirect('/')
});

app.get('/auth/github',
  passport.authenticate('github', { scope: [ 'user:email' ] }));

app.get('/auth/oidc',
  passport.authenticate('oidc'));

app.get('/logout',
  (req, res) => {
    res.clearCookie('jwt')
    res.redirect('/login')
  }
)

app.get('/helloexaminers', passport.authenticate('jwtExaminers', { session: false, failureRedirect: '/login' }),
  (req, res) => {
    res.send('hello examiner')
  }
)

app.use(function (err, req, res, next) {
    console.error(err.stack)
    res.status(500).send('Something broke!')
  })

const options = {
  key: fs.readFileSync('./tls/server.key'),
  cert: fs.readFileSync('./tls/server.crt'),
}
  
https.createServer(options, app).listen(443, () => {
  console.log('HTTPS server running on port 443');
});