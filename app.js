//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");
//const bcrypt = require("bcrypt");
//const saltRounds = 10;
//const md5= require("md5");
//const encrypt = require("mongoose-encryption");
const app = express();

//console.log(process.env.API_KEY);

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
  extended: true
}));

//session code must be above mongoose connect and below other connects
app.use(session({
  secret : "Our little secret.",
  resave:false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.set('useUnifiedTopology', true);
mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true
});
mongoose.set("useCreateIndex",true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId :String,
  secret : Array
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
//userSchema.plugin(encrypt,{secret : process.env.SECRET ,encryptedFields :["password"]});

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID, //from env
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"   //from google api of google develpoer console
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", (req, res) => {
  res.render("home");
});
//google login
app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] })  //Strategy and scope
);
// this get is done by google and give the route of our autherised URL
app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });


app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/secrets",(req,res)=>{
  //to see the secrets page, user should not be authenticated because it is open to all
  User.find({"secret" : {$ne:null}},function(err,foundUsers){
    if(err){
      console.log(err);
    }
    else{
      if(foundUsers){
        res.render("secrets",{usersWithSecrets : foundUsers});
      }
    }
  });
})

  //check user is authenticated, relying on passport, passportLocalMongoose
  //if the user is logged in then render to secrets page , else to redirect the to login route
  // if(req.isAuthenticated()){
  //   res.render("secrets");
  // }
  // else{
  //   res.redirect("/login");
  // }


app.get("/submit",(req,res)=>{
  //check user is authenticated, relying on passport, passportLocalMongoose
  //if the user is logged in then render to secrets page , else to redirect the to login route
  if(req.isAuthenticated()){
    res.render("submit");
  }
  else{
    res.redirect("/login");
  }
});
//when user submits a secret , they get to submit route
app.post("/submit",(req,res)=>{
  const submittedSecret = req.body.secret;
  //find user in database and save it's respective secrets
  User.findById(req.user.id, function(err, foundUsers){
    if(err){
      console.log(err);
    }
    else{
      if(foundUsers){
        foundUsers.secret = submittedSecret;
        foundUsers.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});


app.get("/logout",function(req,res){
  //deauthenticate our user and end user session
  req.logout();
  res.redirect("/");
});

app.post("/register",(req,res)=>{
  //register comes from passport-local-mongoose
  User.register({username : req.body.username},req.body.password,function(err,user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }
    else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  })
});

app.post("/login",(req,res)=>{
  const user = new User({
    username :req.body.username,
    password : req.body.password
  });
  //use passport to login and authenticate
  req.login(user, function(err){
    if(err){
      console.log(err);
    }
    else{
      //authenticate user
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  });

});


app.listen(3000, function() {
  console.log("Server started on port 3000.");
});

//hasing and salting
// app.post("/register", (req, res) => {
//   bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
//     const newUser = new User({
//       email: req.body.username, //catching whatever user typed in input of register.ejs
//       //password : md5(req.body.password) //hashing
//       password: hash
//     });
//     newUser.save(function(err) {
//       if (err) {
//         console.log(err);
//       } else {
//         res.render("secrets");
//       }
//     })
//   });
// });
//
// app.post("/login", (req, res) => {
//   const username = req.body.username;
//   //const password = md5(req.body.password);  //hashing
//   const password = req.body.password;
//   User.findOne({
//     email: username
//   }, function(err, foundUser) {
//     if (err) {
//       console.log(err);
//     } else {
//       if (foundUser) {
//         // if(foundUser.password === password){
//         //   res.render("secrets");
//         // }
//         bcrypt.compare(password, foundUser.password, function(err, result) {
//           if (result === true) {
//             res.render("secrets");
//           }
//         });
//       }
//     }
//   });
// });
