import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import env from "dotenv";

//express session, passport and passport local are necessary to store the cookies on local strategy
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";



const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

//this is to create the sessions
app.use(
  session({
    secret: process.env.SESSION_SECRET, //should be hidden in system variables 
    resave: false, //it will be saved locally, once server is restarted it is not persistent
    saveUninitialized: true, 
    maxAge: 1000 * 60 * 60 * 24, //this makes the cookie valid for one day
  })
);

//passport has to be right after the session and has to be in this order
app.use(passport.initialize());
app.use(passport.session());


//db connection setup
const db = new pg.Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets",async (req, res) => {
  console.log(req.user);
  if (req.isAuthenticated()) { //this is taken from passport session

    try {
      const result = await db.query("SELECT secret FROM person where person.email = $1", [req.user.email]);
      let secret = result.rows[0].secret;
      if (!secret) {
          secret = "There is no secret yet, feel free to update one!";
      }
      res.render("secrets.ejs", {secret:secret});
    } catch (err) {
      console.log(err)
    }

   
  } else { 
    res.render("login.ejs");
  }
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) { //this is taken from passport session

    res.render("submit.ejs");
  } else { 
    res.render("login.ejs");
  }
})

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

//this is to set google strategy to authenticate and setup redirects
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) console.log(err);
    res.redirect("/");
  })
})


app.post("/submit", async  (req, res) => {
  //I would personaly require the req.isAuthenticated() here too, because for example postman could insert via this route secret to some known email, adding it bellow
  if (req.isAuthenticated()) { 
    const secret = req.body.secret;
    console.log(secret);
    console.log(req.user.email);

    try {
      await db.query("UPDATE person SET secret = $1 WHERE email = $2",[secret, req.user.email]);
      
    } catch (err) {
      console.log(err)
    }
    res.redirect("/secrets");
  } else {
    res.redirect("/login");
  }
})

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM person WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      //hashing the password and saving it in the database
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          console.log("Hashed Password:", hash);
          const result = await db.query(
            "INSERT INTO person (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => { //the i in the login  has to be in lower case to use the proper function!!!
            console.log(err);
            res.redirect("/secrets");
          }) 

          res.render("secrets.ejs");
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", passport.authenticate("local",{
  successRedirect: "/secrets",
  failureRedirect: "/login",
 
}));


passport.use(new Strategy(async function verify(username, password, cb) { //username and password matches with the form names and based on it passport can retrieve them automatically

  try {
    const result = await db.query("SELECT * FROM person WHERE email = $1", [
      username,
    ]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;
      bcrypt.compare(password, storedHashedPassword, (err, result) => {
        if (err) {
          return cb(err)
          console.error("Error comparing passwords:", err);
        } else {
          if (result) {
            return cb(null, user) //null is because of there is no error
            
          } else {
            return cb(null, false); //this means there is no error but the user is not authenticated
            
          }
        }
      });
    } else {//the i has to be in lower case!!! 
            return cb("user not found"); //set "user not found" as the error 
    }
  } catch (err) {
    return cb(err);
  }
}))

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        console.log(profile);
        const result = await db.query("SELECT * FROM person WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO person (email, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          //already existing user, the null is there as there is no error being processed
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => { //this allows to retrieve info about login
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
