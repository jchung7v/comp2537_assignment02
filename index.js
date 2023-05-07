require("./utils.js");
require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;
const app = express();
const Joi = require("joi");
const port = process.env.PORT || 3000;

const fs = require("fs");
const path = require("path");
app.set('view engine', 'ejs');

//expires after 1 hour  (hours * minutes * seconds * millis)
const expireTime = 60 * 60 * 1000; 

/* secretf information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include("databaseConnection");

const userCollection = database.db(mongodb_database).collection("users");

app.use(express.urlencoded({ extended: false }));

/* database connection */
var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    resave: true,
    saveUninitialized: false,
  })
);

/* check if users have valid session (middleware) */
function isValidSession(req) {
  if (req.session.authenticated) {
    return true;
  }
  return false;
}

function sessionValidation(req, res, next) {
  if (isValidSession(req)) {
    next();
  }
  else {
    res.redirect('/login');
  }
}

/* check if users are admin (middleware) */
async function isAdmin(req) {
  const user = await userCollection.findOne({ username: req.session.username });
  if (user && user.usertype === "admin") {
    console.log("It's true");
    return true;
  } else {
    console.log("It's false");
    return false;
  }
}

async function adminAuthorization(req, res, next) {
  if (await isAdmin(req)) {
    console.log("Admin Authorization is working properly")
    next();
  }
  else {
    res.status(403);
    res.render("errorMessage", {error: "Not Authorized"})
    return;
  }
}

/* main page */
app.get("/", (req, res) => {
  const username = req.session.username;
  res.render('index', { username });
});

app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

/* Log in page */
app.get("/login", (req, res) => {
  res.render('login');
});

/* Sign up page */
app.get("/signup", (req, res) => {
  const missingUsername = req.query.missingUsername;
  const missingEmail = req.query.missingEmail;
  const missingPassword = req.query.missingPassword;

  res.render('signup', { missingUsername, missingEmail, missingPassword });
});

/* create a user */
app.post("/submitUser", async (req, res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;

  if (!username) {
    res.redirect("/signup?missingUsername=true");
    return;
  } else if (!email) {
    res.redirect("/signup?missingEmail=true");
    return;
  } else if (!password) {
    res.redirect("/signup?missingPassword=true");
    return;
  }

  // Set up schema for validation
  var schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  // Validation of user input
  const validationResult = schema.validate({ username, email, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/signup");
    return;
  }

  // Change password to hash
  var hashedPassword = await bcrypt.hash(password, saltRounds);

  // Insert user into database
  await userCollection.insertOne({
    username: username,
    email: email,
    password: hashedPassword,
  });
  console.log("Inserted user");

  // Set session variables
  req.session.authenticated = true;
  req.session.username = username;
  req.session.email = email;
  req.session.cookie.maxAge = expireTime;

  res.redirect("/members");
});

/* log in */
app.post("/loggingin", async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  // Set up schema for validation
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });
  const validationResult = schema.validate({ email, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/login");
    return;
  }

  // Check if user exists
  const result = await userCollection
    .find({ email: email })
    .project({ email: 1, username: 1, password: 1, _id: 1 })
    .toArray();
  console.log(result);

  if (result.length != 1) {
    console.log("user not found");
    res.redirect("/login");
    return;
  }

  if (await bcrypt.compare(password, result[0].password)) {
    console.log("correct password");
    req.session.authenticated = true;
    req.session.email = email;
    req.session.username = result[0].username;
    req.session.cookie.maxAge = expireTime;
    res.redirect("/members");
    return;
  } else {
    var html = `
    <p>User and password not found</p>
    <a href='/login'>Try again</a>
    `;
    console.log("incorrect password");
    res.send(html);
    return;
  }
});

app.use(express.static(__dirname + "/public"));
app.use('/members', sessionValidation);

/* members' area */
app.get("/members", (req, res) => {
  res.render('members');
});

const {ObjectId} = require('mongodb');

app.use('/admin', adminAuthorization);

app.get("/admin", async (req, res) => {
  const result = await userCollection.find().project({username: 1, usertype: 1, _id: 1}).toArray();
  res.render('admin', { users: result });
})

/* promote a user to an admin */
app.post("/promote/:id", async (req, res) => {
  const id = req.params.id;
    await userCollection.updateOne({_id: new ObjectId(id)}, {$set: {usertype: "admin"}});
    const result = await userCollection.find().project({ _id: 1}).toArray();
    res.render('admin', { users: result});
});

/* demote an admin to a user */
app.post("/demote/:id", async (req, res) => {
  const id = req.params.id;
    await userCollection.updateOne({_id: new ObjectId(id)}, {$set: {usertype: "user"}});
    const result = await userCollection.find().project({ _id: 1}).toArray();
    res.render('admin', { users: result });
  // }
});


/* logout */
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

/* 404 page */
app.get("*", (req, res) => {
  res.status(404);
  res.render('404');
});

app.listen(port, () => {
  console.log("Example app listening on port " + port);
});
