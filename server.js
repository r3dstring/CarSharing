// server.js
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const methodOverride = require('method-override');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const validator = require('validator');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';

// View + parsing
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(methodOverride('_method'));
app.use(express.static('public'));

// Security headers
app.use(
  helmet({
    contentSecurityPolicy: false // keep simple for EJS
  })
);

// Rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 min
  max: 50,                  // 50 attempts per IP
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/login', authLimiter);
app.use('/signup', authLimiter);

// Trust proxy (for Render/Railway etc.)
if (isProd) {
  app.set('trust proxy', 1);
}

// Sessions
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'super-secret-carshare-key-change-this',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: isProd // secure cookies only when behind HTTPS
    }
  })
);

// Auth helper middleware
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  next();
}

function getCurrentUser(req) {
  if (!req.session.userId) return null;
  const stmt = db.prepare('SELECT id, name, email FROM users WHERE id = ?');
  return stmt.get(req.session.userId) || null;
}

// ---------- Home ----------

app.get('/', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/dashboard');
  }
  res.redirect('/login');
});

// ---------- Auth Routes ----------

// GET signup
app.get('/signup', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.render('signup', { error: null });
});

// POST signup
app.post('/signup', async (req, res) => {
  let { name, email, password } = req.body;
  name = (name || '').trim();
  email = (email || '').trim().toLowerCase();

  if (!name || !email || !password) {
    return res.render('signup', { error: 'All fields are required.' });
  }

  if (!validator.isEmail(email)) {
    return res.render('signup', { error: 'Please enter a valid email address.' });
  }

  if (password.length < 6) {
    return res.render('signup', { error: 'Password must be at least 6 characters.' });
  }

  try {
    const hash = await bcrypt.hash(password, 12);
    const stmt = db.prepare(
      'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)'
    );
    const info = stmt.run(name, email, hash);
    req.session.userId = info.lastInsertRowid;
    res.redirect('/dashboard');
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      return res.render('signup', { error: 'Email is already registered.' });
    }
    console.error(err);
    res.status(500).send('Server error');
  }
});

// GET login
app.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.render('login', { error: null });
});

// POST login
app.post('/login', async (req, res) => {
  let { email, password } = req.body;
  email = (email || '').trim().toLowerCase();

  if (!email || !password) {
    return res.render('login', { error: 'Email and password are required.' });
  }

  const stmt = db.prepare('SELECT * FROM users WHERE email = ?');
  const user = stmt.get(email);
  if (!user) {
    return res.render('login', { error: 'Invalid email or password.' });
  }
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) {
    return res.render('login', { error: 'Invalid email or password.' });
  }
  req.session.userId = user.id;
  res.redirect('/dashboard');
});

// POST logout
app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// ---------- Dashboard ----------

app.get('/dashboard', requireLogin, (req, res) => {
  const user = getCurrentUser(req);

  const myRidesCount = db
    .prepare('SELECT COUNT(*) AS c FROM rides WHERE driver_id = ?')
    .get(user.id).c;

  const myBookingsCount = db
    .prepare('SELECT COUNT(*) AS c FROM bookings WHERE passenger_id = ?')
    .get(user.id).c;

  res.render('dashboard', {
    user,
    myRidesCount,
    myBookingsCount
  });
});

// ---------- Rides ----------

// List all upcoming rides
app.get('/rides', requireLogin, (req, res) => {
  const user = getCurrentUser(req);
  const rides = db
    .prepare(
      `
      SELECT r.*, u.name AS driver_name
      FROM rides r
      JOIN users u ON r.driver_id = u.id
      WHERE datetime(r.departure_time) >= datetime('now')
      ORDER BY r.departure_time ASC
    `
    )
    .all();

  res.render('rides', { user, rides });
});

// Form to create a ride
app.get('/rides/new', requireLogin, (req, res) => {
  const user = getCurrentUser(req);
  res.render('ride_new', { user, error: null });
});

// Create a ride
app.post('/rides', requireLogin, (req, res) => {
  const user = getCurrentUser(req);
  let {
    start_location,
    end_location,
    departure_time,
    total_seats,
    price_per_seat,
    notes
  } = req.body;

  start_location = (start_location || '').trim();
  end_location = (end_location || '').trim();
  departure_time = (departure_time || '').trim();
  notes = (notes || '').trim();

  if (!start_location || !end_location || !departure_time || !total_seats || !price_per_seat) {
    return res.render('ride_new', {
      user,
      error: 'Please fill all required fields.'
    });
  }

  const seats = parseInt(total_seats, 10);
  const price = parseFloat(price_per_seat);

  if (!Number.isFinite(seats) || seats <= 0 || seats > 10) {
    return res.render('ride_new', {
      user,
      error: 'Seats must be between 1 and 10.'
    });
  }

  if (!Number.isFinite(price) || price < 0) {
    return res.render('ride_new', {
      user,
      error: 'Price must be a non-negative number.'
    });
  }

  const stmt = db.prepare(
    `
    INSERT INTO rides 
      (driver_id, start_location, end_location, departure_time, total_seats, available_seats, price_per_seat, notes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `
  );

  stmt.run(
    user.id,
    start_location,
    end_location,
    departure_time,
    seats,
    seats,
    price,
    notes || null
  );

  res.redirect('/rides');
});

// View ride details
app.get('/rides/:id', requireLogin, (req, res) => {
  const user = getCurrentUser(req);
  const rideId = req.params.id;

  const ride = db
    .prepare(
      `
      SELECT r.*, u.name AS driver_name, u.email AS driver_email
      FROM rides r
      JOIN users u ON r.driver_id = u.id
      WHERE r.id = ?
    `
    )
    .get(rideId);

  if (!ride) {
    return res.status(404).send('Ride not found');
  }

  const passengers = db
    .prepare(
      `
      SELECT b.*, u.name AS passenger_name, u.email AS passenger_email
      FROM bookings b
      JOIN users u ON b.passenger_id = u.id
      WHERE b.ride_id = ?
    `
    )
    .all(rideId);

  const myBooking = db
    .prepare(
      `
      SELECT * FROM bookings 
      WHERE ride_id = ? AND passenger_id = ?
    `
    )
    .get(rideId, user.id);

  res.render('ride_detail', {
    user,
    ride,
    passengers,
    myBooking
  });
});

// Book seats on a ride
app.post('/rides/:id/book', requireLogin, (req, res) => {
  const user = getCurrentUser(req);
  const rideId = req.params.id;
  const seatsRequested = parseInt(req.body.seats_booked, 10);

  const ride = db
    .prepare('SELECT * FROM rides WHERE id = ?')
    .get(rideId);

  if (!ride) {
    return res.status(404).send('Ride not found');
  }

  if (ride.driver_id === user.id) {
    return res.status(400).send("You can't book your own ride.");
  }

  if (!Number.isFinite(seatsRequested) || seatsRequested <= 0) {
    return res.status(400).send('Invalid number of seats.');
  }

  if (ride.available_seats < seatsRequested) {
    return res.status(400).send('Not enough seats available.');
  }

  const existing = db
    .prepare(
      'SELECT * FROM bookings WHERE ride_id = ? AND passenger_id = ?'
    )
    .get(rideId, user.id);

  if (existing) {
    return res.status(400).send('You have already booked this ride.');
  }

  const insertBooking = db.prepare(
    `
    INSERT INTO bookings (ride_id, passenger_id, seats_booked, status)
    VALUES (?, ?, ?, 'CONFIRMED')
  `
  );

  const updateSeats = db.prepare(
    `
    UPDATE rides SET available_seats = available_seats - ?
    WHERE id = ?
  `
  );

  const transaction = db.transaction(() => {
    insertBooking.run(rideId, user.id, seatsRequested);
    updateSeats.run(seatsRequested, rideId);
  });

  transaction();

  res.redirect('/bookings');
});

// ---------- Bookings ----------

app.get('/bookings', requireLogin, (req, res) => {
  const user = getCurrentUser(req);

  const asPassenger = db
    .prepare(
      `
      SELECT b.*, r.start_location, r.end_location, r.departure_time,
             r.price_per_seat, u.name AS driver_name
      FROM bookings b
      JOIN rides r ON b.ride_id = r.id
      JOIN users u ON r.driver_id = u.id
      WHERE b.passenger_id = ?
      ORDER BY r.departure_time DESC
    `
    )
    .all(user.id);

  const myRides = db
    .prepare(
      `
      SELECT r.*, 
             IFNULL(SUM(b.seats_booked), 0) AS seats_booked_total
      FROM rides r
      LEFT JOIN bookings b ON r.id = b.ride_id
      WHERE r.driver_id = ?
      GROUP BY r.id
      ORDER BY r.departure_time DESC
    `
    )
    .all(user.id);

  res.render('bookings', {
    user,
    asPassenger,
    myRides
  });
});

app.listen(PORT, () => {
  console.log(`CarShare app running on http://localhost:${PORT}`);
});
