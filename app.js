require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const { exec } = require('child_process');
const { error, log } = require('console');
const lodash = require('lodash');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const FacebookStrategy = require('passport-facebook');
const logger = require('morgan');

const app = express();

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    secret: 'Our little secret.',
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

const dbToUse=process.env.DBNAME;
mongoose.connect(`mongodb://127.0.0.1:27017/${dbToUse}`, {useNewUrlParser: true});


const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model('User', userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id)
    .then(function (user) {
      done(null, user);
    })
    .catch(function (err) {
      done(err, null);
    });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: 'http://localhost:3000/auth/google/secrets',
      userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo',
    },
    function (accessToken, refreshToken, profile, cb) {
      console.log(profile);

      User.findOrCreate({ username: profile.displayName, googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_CLIENT_ID,
      clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
      callbackURL: '/oauth2/redirect/facebook',
      state: true,
    },
    function verify(accessToken, refreshToken, profile, cb) {
        console.log(profile);
      User.findOrCreate(
        {
          username: profile.displayName,
          facebookId: profile.id,
        },
        function (err, user) {
          if (err) {
            return cb(err);
          }
          return cb(null, user);
        }
      );
    }
  )
);

app.get('/', function (req, res) {
  res.render('home');
});

app.get(
  '/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);

app.get(
  '/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  }
);

app.get('/login/federated/facebook', passport.authenticate('facebook'));

app.get('/oauth2/redirect/facebook', passport.authenticate('facebook', {
  successRedirect: '/secrets',
  failureRedirect: '/login',
}));

app.get("/login", function(req, res){
    res.render("login");
})

app.get("/register", function(req, res){
    res.render("register");
})

app.get("/secrets", function(req, res){
    if(req.isAuthenticated()){
        User.find({"secret": {$ne: null}}).then(function(users){
            if(users){
                res.render("secrets", {usersWithSecrets: users})
            }
        });
    }
    else{
        res.redirect("/login");
    }
})

app.get("/logout", function(req, res){
    req.logout(function(err) {
        if (err) {
            console.log(err);
        }
        res.redirect('/');
    });
})

app.get("/submit", function(req, res){
    if(req.isAuthenticated()){
        res.render("submit");
    }
    else{
        res.redirect("/login");
    }
});

app.post("/submit", function(req, res){
    const secret=req.body.secret;

    User.findById(req.user.id).then(function(user){
        if(user){
            user.secret=secret;
            user.save().then(function(){
                res.redirect("/secrets");
            })
        }
        else{
            res.send("No such user.")
        }
    }).catch(function(err){
        if(err){
            res.send(err);
        }
    })
})

app.post("/register", function(req, res){
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err);
            res.redirect("/register");
        }
        else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            })
        }
    })
});


app.post("/login", function(req, res){
    const user=new User({
        username: req.body.username,
        password: req.body.password
    })

    req.login(user, function(err){
        if(err){
            console.log(err);
        }
        else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            })
        }
    })

});


app.listen(process.env.PORT || 3000, function() {
    console.log("Server started on port 3000.");
    exec("start microsoft-edge:http://localhost:3000");
  });