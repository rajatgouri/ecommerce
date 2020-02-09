const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
sendGridTransport = require('nodemailer-sendgrid-transport');

const User = require('../models/user');

const transport = nodemailer.createTransport(sendGridTransport({
  auth: {
    api_key: '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'
    
  }
}))

exports.getLogin = (req, res, next) => {
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    errorMessage: message
  });
};

exports.getSignup = (req, res, next) => {
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    errorMessage: message
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  User.findOne({ email: email })
    .then(user => {
      if (!user) {
        req.flash('error', 'Invalid email or password.');
        return res.redirect('/login');
      }
      bcrypt
        .compare(password, user.password)
        .then(doMatch => {
          if (doMatch) {
            req.session.isLoggedIn = true;
            req.session.user = user;
            return req.session.save(err => {
              console.log(err);
              res.redirect('/');
            });
          }
          req.flash('error', 'Invalid email or password.');
          res.redirect('/login');
        })
        .catch(err => {
          console.log(err);
          res.redirect('/login');
        });
    })
    .catch(err => console.log(err));
};

exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const confirmPassword = req.body.confirmPassword;
  User.findOne({ email: email })
    .then(userDoc => {
      if (userDoc) {
        req.flash('error', 'E-Mail exists already, please pick a different one.');
        return res.redirect('/signup');
      }
      return bcrypt
        .hash(password, 12)
        .then(hashedPassword => {
          const user = new User({
            email: email,
            password: hashedPassword,
            cart: { items: [] }
          });
          return user.save();
        })
        .then(result => {
          transport.sendMail({
            to: email,
            from: 'shop@node-complete.com',
            subject: 'signup succeded',
            html: '<h1>you successfully signed up</h1>'
          })
          res.redirect('/login');
        });
    })
    .catch(err => {
      console.log(err);
    });
};

exports.postLogout = (req, res, next) => {
  req.session.destroy(err => {
    console.log(err);
    res.redirect('/');
  });
};


exports.getReset = ((req, res, next) => {
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/reset', {
    pageTitle: 'reset Password',
    path: '/reset',
    errorMessage: message
  });
})


exports.postReset = ((req,res,next) => {
  crypto.randomBytes(32, (err, buffer) => {
    if(err) {
      console.error(err);
      res.redirect('/reset');
    }
    const token = buffer.toString('hex');
    User.findOne({email : req.body.email})
      .then((user) => {
        if(!user) {
          req.flash('error', 'No Account for this user');
          res.redirect('/reset');
        }
        user.resetToken = token;
        user.resetTokenExpiration = Date.now() + 3600000;
        return user.save();
      })
      .then((result) => {
        res.redirect('/');
        transport.sendMail({
          to: req.body.email,
          from: 'shop@node-complete.com',
          subject: 'passsword reset',
          html: `
            <p>click this link  to reset password</p><a href="http://localhost:3000/reset/${token}">click</a>
          `
        })
      })
      .catch(error => console.error(error));
  })
})


exports.getNewPassword = ((req,res,next) => {
  const token = req.params.token;
  User.findOne({resetToken: token, resetTokenExpiration : {$gt : Date.now()}})
    .then((user) => {
      let message = req.flash('error');
      if (message.length > 0) {
        message = message[0];
      } else {
        message = null;
      }
      res.render('auth/new-password', {
        pageTitle: 'New Password',
        path: '/new-password',
        errorMessage: message,
        userId: user._id.toString(),
        passwordToken : token
      });
    })
    .catch(error => console.error(error));
})


exports.postNewPassword = ((req, res, next) => {
  const newPassword = req.body.password;
  const userId = req.body.userId;
  const passwordToken = req.body.passwordToken;
  let resetUser;
  User.findOne({resetToken : passwordToken, resetTokenExpiration : { $gt: Date.now()}, _id : userId})
    .then((user) => {
      console.log(user)

      resetUser = user;
      return bcrypt.hash(newPassword, 12)
    })
    .then((hashedPassword) => {
      resetUser.password = hashedPassword;
      resetUser.resetToken = undefined;
      resetTokenExpiration = undefined;
      return resetUser.save();
    })
    .then((result) => {
      res.redirect('/');
    })
    .catch(error => console.error(error));
})