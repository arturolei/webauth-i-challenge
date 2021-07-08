const express = require('express');

//Adding sessions
const session = require('express-session');
const knexSessionsStore = require('connect-session-knex')(session);

//Session configuration
const sessionConfig = {
    name:'cookie',
    secret: 'CookiesRuleEverythingAroundMe',
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, //cookie age, how long cookie is good
      secure: false,
      httpOnly: true,
    },
    resave: false,
    saveUnitialized: false,
  
    store: new knexSessionsStore({
      knex: require('./database/dbConfig.js'),
      tablename: 'sessions',
      sidfieldname: 'sid',
      createtable:true,
      clearInterval: 1000 * 60 * 60
    })
  };

const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session(sessionConfig))


server.get('/', (req, res) => {
  res.send("It's alive!!!");
});

server.post('/api/register', (req, res) => {
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, 10)//password and number, which determines how many time hash is applied
  user.password = hash;

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;
  console.log(username, password);
  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        req.session.user = user;
        res.status(200).json({ message: `Welcome ${user.username}! You are logged-in` });
      } else {
        res.status(401).json({ message: 'You shall not pass!' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

//Let's add a logout... why not
server.get('/api/logout', (req, res) => {
    if (req.session) {
      console.log(req.session);
      req.session.destroy(err => {
        if (err) {
          res.send('error logging out');
        } else {
          res.send('good bye');
        }
      });
    } else {
      res.end();
    }
  });


server.get('/api/users', restricted, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

//MiddleWare with Authentication (Simplified now since we are using sessions)

function restricted(req, res, next) {

  //If there is is a req.session and req.session.user, it means you are logged-in properly
  //ergo, you should get access to restricted stuff. 
  if (req.session && req.session.user) {
    next();
  } else {
    res.status(400).json({ message: 'You shall not pass!' });
  }
}

const port = process.env.PORT || 6000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
