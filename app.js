//jshint esversion:6
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const app = express();
const session = require('express-session');
const passport = require('passport');
const passportlocalmongoose = require('passport-local-mongoose');
const findorcreate = require('mongoose-findorcreate');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const facebookStrategy = require('passport-facebook').Strategy;
/* const bcrypt = require('bcrypt');
const saltRounds = 12;
const md5 = require('md5');
const encrypt = require('mongoose-encryption'); */

app.use(express.static("public"));
app.set('view engine', 'ejs');

app.use(express.urlencoded({
    extended: true
  }));

  app.use(session({
    secret: 'Hello World....',
    resave: false,
    /* cookie:{ maxAge: 60000}, */
    saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secrets: {
        type: [String]
    }
});

/* userSchema.plugin(encrypt, { secret: process.env.SECRET , encryptedFields: ['password']});
 */

userSchema.plugin(passportlocalmongoose);
userSchema.plugin(findorcreate)

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user,done){
    done(null, user.id);
});
passport.deserializeUser(function(id,done){
    User.findById(id, function(err, user){
        done(err,user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile);
    User.findOrCreate({username: profile.emails[0].value ,googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",function(req,res){
    res.render('home');
})
app.get("/auth/google",
  passport.authenticate('google', { scope: ['profile', 'email'] })
  );

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login",function(req,res){
    res.render('login');
});
app.get("/register",function(req,res){
    res.render('register');
});
app.get("/secrets",function(req,res){
    if(req.isAuthenticated()){
         User.findById(req.user.id, function(err,foundUser){
            if(err){
                console.log(err);
            }
            else{
                if(foundUser){
                    res.render("secrets",{
                        userSecrets: foundUser.secrets
                    });
                }
            }
        })
    }
    else{
        res.redirect('/login');
    }
})
app.get("/submit", function(req,res){
    if(req.isAuthenticated()){
        res.render('submit');
    }
    else{
        res.redirect('/login');
    }
})

app.get("/logout",function(req,res){
   /*  req.session.destroy(function (err) {
        res.redirect('/'); //Inside a callback… bulletproof!
      }); */   // alternate method for logging out
      req.logOut();
      res.redirect('/');
});
app.post("/register", function(req,res){
    console.log(req.body.password);

/*     bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        if(err){
            console.log(err);
        }
        else{
            console.log(hash)
        const newuser = new User({
            email: req.body.username,
            password: hash
        });
        newuser.save(function(err){
            if(err) console.log(err);
            else{
                res.render("secrets");
            }
        });
    }
    });    */
    
    User.register({username: req.body.username}, req.body.password, function(err,user){
        if(err){
            console.log(err);
            res.redirect("/register");
        }
        else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    });
});
app.post("/login",function(req,res){
/* const username = req.body.username;
const password = req.body.password;
User.findOne({email: username}, function(err,founduser){
    if(err){
        console.log(err)
    }
    else{
        if(founduser){
            bcrypt.compare(password, founduser.password, function(err, result) {
            if(err){
                console.log(err)
            }
            else{
                if(result){
                    res.render("secrets");
                }
                else{
                    res.send("Incorect Password");
                }
            }
            });
        }
        else{
            res.render("register");
        }
    }
}) */

const user = new User({
    username: req.body.username,
    password: req.body.password
});
req.login(user, function(err){
    if(err){
        console.log(err);
    }
    else{
        passport.authenticate("local")(req,res,function(){
            res.redirect("/secrets");
        });
    }
});
});

app.post("/submit",function(req,res){
    const submittedSecret = req.body.secret;

    User.findById(req.user.id, function(err, foundUser){
        if(err){
            console.log(err);
        }
        else{
            if(foundUser){
                /* foundUser.secrets = submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets")
                }); */
                foundUser.secrets.push(submittedSecret);
                foundUser.save();
                res.redirect("/secrets");
            }
        }
    })
    
});


app.listen("3000", function(){
    console.log("listing at port 3000...");
})