const express = require('express');
const session = require('express-session');
const flash = require('connect-flash');
const app = express();
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
require('dotenv').config();

const sessionSecret = process.env.SESSION_SECRET || 'default-secret-key';

app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true,
}));
app.use(express.json());
app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
}));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://localhost:27017/planner', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'Błąd połączenia z MongoDB:'));
db.once('open', () => {
  console.log('Połączenie z MongoDB zostało nawiązane');
});

// ------------ Definicja schematu użytkownika
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  crearedAt: Date,
});

const User = mongoose.model('User', userSchema);

// ------------ Definicja schematu dla logowania użytkownika 
const workLogsSchema = new mongoose.Schema({
  userID: String,
  projectID: String,
  startTime: Date,
  endTime: Date,
  startBreakTime: Date,
  endBreakTime: Date,
});

const Session = mongoose.model('WorkLogs', workLogsSchema);

// ------------ Definicja schematu dla projektów
const projectsSchema = new mongoose.Schema({
  userID: String,
  nameOfProject: String,
});

const Message = mongoose.model('Projects', projectsSchema);

// ---- sprawdzanie danych logowania
passport.use(new LocalStrategy(
  { usernameField: 'email' },
  async (email, password, done) => {
    try {
      const user = await User.findOne({ email });

      if (!user) {
        return done(null, false, { message: 'Invalid email' });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (!isPasswordValid) {
        return done(null, false, { message: 'Invalid password' });
      }

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// obsługa rejestracji
app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({ message: 'User with this email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
    });

    await newUser.save();

    req.login(newUser, (err) => {
      if (err) {
        return console.log(res.status(500).json({ message: 'Error logging in after registration' }));
      }
      return console.log(res.json({ message: 'Registration and login successful' }));
    });
  } catch (error) {
    console.error('Registration error:', error);
    console.log(res.status(500).json({ message: 'Error during registration' }));
  }
});

// Kod obsługi logowania użytkownika (sprawdzenie czy dany użytkownik istnieje)
app.post('/login', async (req, res, next) => {
  passport.authenticate('local', async (err, user, info) => {
    try {
      if (err) {
        return console.log(res.status(500).json({ message: 'Internal Server Error' }));
      }
      if (!user) {
        return console.log(res.status(401).json({ message: 'Invalid credentials' }));
      }
      req.logIn(user, (err) => {
        if (err) {
          return console.log(res.status(500).json({ message: 'Login failed' }));
        }
        console.log('User logged in:', req.user.username);
        return console.log(res.json({ message: 'Login successful' }));
      });
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ message: 'Error during login' });
    }
  })(req, res, next);
});

// nasłuchiwanie serwera
const port = process.env.PORT || 5000;

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
