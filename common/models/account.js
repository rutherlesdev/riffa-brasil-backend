'use strict';
var async = require("async");
var passcode = require('../../server/modules/passcode');
var datasources = require('../../server/datasources.json');
var config = require('../../server/config');

module.exports = function (Account) {


  var emailDs = datasources.emailDataSource.transports[0].auth;

  Account.beforeRemote('login', function (context, unused, next) {
    Account.findOne({
      where: {
        "email": context.args.credentials.email
      }
    }, function (err, user) {
      if (err || !user) return next(err);
      if (!user.accountVerified) return next(new Error('Email for this account not yet verified'));
      next();
    })
  })

  Account.afterRemote('login', function (context, modelInstance, next) {
    var res = context.res;
    var token = context.result.__data;
    if (!token) return next(new Error('Login Failed'));

    Account.findById(token.userId, {
      include: [{
        "contact": "preference"
      }, "roles"]
    }, function (err, user) {
      if (err || !user) return next(err);
      res.send({
        created: token.created,
        id: token.id,
        ttl: token.ttl,
        user: user,
        userId: token.userId
      });
    })
  })

  Account.afterRemote('create', function (context, modelInstance, next) {
    var req = context.req;
    var user = context.result.__data;
    var names = user.fullname ? user.fullname.split(' ') : null;
    console.log(req.headers.origin);
    async.waterfall([
      function (callback) {
        sendVerification(modelInstance, context.req.headers.origin, function (err, result) {
          if (err) next(err);
          callback(err);
        });
      },
      function (callback) {
        Account.app.models.Contact.create({
          firstName: names ? names[0] : user.firstName,
          lastName: names ? names[names.length - 1] : user.lastName,
          picture: null,
          email: user.email,
          accountId: user.id,
          createdAt: new Date(),
          createdBy: user.id,
          updatedAt: new Date(),
          updatedBy: user.id
        }, function (err, contact) {
          if (err) next(new Error(err))
          if (!err && !contact) {
            next(new Error(err))
          }
          callback(err, user, contact);
        });
      },
      function (user, contact, callback) {
        Account.app.models.Preference.create({
          contactId: contact.id,
          createdAt: new Date(),
          createdBy: contact.id,
          updatedAt: new Date(),
          updatedBy: contact.id
        }, function (err, preference) {
          if (err) next(new Error(err))
          if (!err && !preference) {
            next(new Error(err))
          }
          next(err, user);
        });
      }
    ])
  });


  function sendVerification(user, origin, cb) {

    var options = {
      to: user.email,
      from: emailDs.user,
      subject: 'Email Address Verification',
      html: `
      
      `
    }
    // <h3>Your verification code is: </h3><br/><br/><strong><h3>#!pin!#</h3></strong>

    user.sendVerification(options, function (err, response) {
      if (err) return cb(err);
      return cb(null);
    });
  };

  Account.prototype.sendVerification = function (options, cb) {
    var user = this;
    var recipients = options.to ? options.to : options.recipients.toString();
    var _passcode = passcode.generatePasscode();
    user.updateAttributes({
      "passcode": _passcode
    }, function (err, user) {
      if (err) {
        return cb(err);
      }

      options.html = options.html.replace(/\#\!pin\!\#/g, _passcode).replace(/\#\!id\!\#/g, user.id).replace(/\#\!email\!\#/g, recipients);
      Account.email.send(options, function (err, email) {
        if (err) return cb(err);
        console.log(_passcode);
        cb(null);
      });
    });
  };

  Account.verifyEmail = function (options, data, cb) {

    async.waterfall([
      function (callback) {
        Account.findOne({
          where: {
            and: [{
                "passcode": data.passcode
              },
              {
                email: data.email
              }
            ]
          }
        }, function (err, user) {
          if (err || !user) return cb(new Error('Account not found: Check passcode'));
          if (user.accountVerified) return cb(new Error('Email has already been verified'));
          callback(err, user);
        })
      },
      function (user, callback) {
        user.updateAttributes({
          "passcode": null,
          "accountVerified": true
        }, function (err, user) {
          if (err) return cb(err);
          cb(null, true);
        });
      },
    ]);
  }

  Account.remoteMethod('verifyEmail', {
    description: 'Verifies the user Email address',
    accepts: [{
      arg: 'options',
      type: 'object',
      http: 'optionsFromRequest'
    }, {
      arg: 'data',
      type: 'object',
      required: true,
      http: {
        source: 'body'
      }
    }],
    returns: {
      arg: 'success',
      type: 'boolean',
      root: true
    },
    http: {
      path: '/verify-email',
      verb: 'post',
      status: 200,
      errorStatus: 500
    }
  });

  Account.resendVerification = function (data, req, cb) {
    if (!data.email) return cb(new Error('Email not Provided'));
    Account.findOne({
      where: {
        email: data.email
      }
    }, function (err, user) {
      if (err || !user) return cb(new Error('Email is not associated to an account. Use Sign up'));
      if (user.accountVerified) return cb(new Error('Email has already been verified'));
      sendVerification(user, req, function (err, result) {
        if (err) return cb(err);
        cb(null, true);
      });
    })
  }

  Account.remoteMethod('resendVerification', {
    description: 'Resends the user verification passcode.',
    accepts: [{
        arg: 'data',
        type: 'object',
        required: true,
        http: {
          source: 'body'
        }
      },
      {
        arg: 'req',
        type: 'object',
        'http': {
          source: 'req'
        }
      }
    ],
    returns: {
      arg: 'success',
      type: 'boolean',
      root: true
    },
    http: {
      path: '/resend-verification/',
      verb: 'post',
      status: 200,
      errorStatus: 500
    }
  });

  function sendPasswordReset(user, req, cb) {

    var options = {
      to: user.email,
      from: emailDs.user,
      subject: 'Password Reset',
      html: `
           
      `
    };

    user.sendVerification(options, function (err, response) {
      if (err) return cb(err);
      return cb(null);
    });
  };

  //send password reset OTP when requested
  Account.resetPasswordRequest = function (data, req, cb) {
    Account.findOne({
        where: {
          and: [{
            email: data.email
          }]
        }
      },
      function (err, user) {
        if (!user) return cb(new Error('User Not Found'));
        if (err) return cb(new Error(err));
        sendPasswordReset(user, req, function (err, result) {
          if (err) return cb(err);
          return cb(null, true);
        });
      })
  }
  Account.remoteMethod('resetPasswordRequest', {
    description: 'Send password reset Token.',
    accepts: [{
        arg: 'credentials',
        type: 'object',
        required: true,
        http: {
          source: 'body'
        }
      },
      {
        arg: 'req',
        type: 'object',
        'http': {
          source: 'req'
        }
      }
    ],
    returns: {
      arg: 'success',
      type: 'boolean',
      root: true
    },
    http: {
      path: '/reset-password-request',
      verb: 'post',
      status: 200,
      errorStatus: 500
    }
  });

  Account.resetAccountPassword = function (data, cb) {
    async.waterfall([
      function (callback) {
        Account.findOne({
          where: {
            and: [{
              "passcode": data.passcode
            }, {
              "accountVerified": true
            }]
          }
        }, function (err, user) {
          if (err || !user) return cb(new Error('Account not found: Check passcode'));
          callback(err, user);
        })
      },
      function (user, callback) {
        user.updateAttributes({
          "passcode": null,
          'password': Account.hashPassword(data.password)
        }, function (err) {
          if (err) return cb(new Error('Error Updating Password'))
          cb(null, true);
        });
      }
    ]);
  }
  Account.remoteMethod('resetAccountPassword', {
    description: 'Resets the user password',
    accepts: [{
      arg: 'data',
      type: 'object',
      required: true,
      http: {
        source: 'body'
      }
    }],
    returns: {
      arg: 'success',
      type: 'boolean',
      root: true
    },
    http: {
      path: '/reset-account-password',
      verb: 'post',
      status: 200,
      errorStatus: 500
    }
  });

  Account.socialLogin = function (data, cb) {

    var filter = {
      or: [{
        email: data.email
      }]
    };

    Account.find({
      where: filter
    }, function (err, users) {
      var user = users[0];
      if (user) {
        if ((data.provider === 'FACEBOOK' && user.facebook === data.id) || (data.provider === 'GOOGLE' && user.google === data.id)) {
          return cb(null, true);
        }
        return cb(new Error('This user already has an account'));
      } else {
        async.waterfall([
          function (callback) {
            Account.create({
              displayName: data.name,
              firstName: data.firstName || data.givenName,
              lastName: data.lastName || data.familyName,
              picture: data.photoUrl,
              facebook: data.facebook ? data.id : null,
              google: data.google ? data.id : null,
              email: data.email,
              accountVerified: true,
              password: data.id
            }, function (err, user) {
              if (err) {
                return cb(new Error('Error Creating User'));
              }
              callback(err, user);
            });
          },
          function (user, callback) {
            Account.app.models.Contact.create({
              firstName: user.firstName,
              lastName: user.lastName,
              picture: user.picture,
              email: user.email,
              gender: data.gender || null,
              accountId: user.id,
              createdAt: new Date(),
              createdById: user.id,
              updatedAt: new Date(),
              updatedById: user.id
            }, function (err, contact) {
              if (err) {
                return cb(new Error('Error Creating User Contact'));
              }
              callback(err, user, contact);
            });
          },
          function (user, contact, callback) {
            Account.app.models.Preference.create({
              contactId: contact.id,
              createdAt: new Date(),
              createdById: contact.id,
              updatedAt: new Date(),
              updatedById: contact.id
            }, function (err, preference) {
              if (err) {
                return cb(new Error('Error Creating Preference'));
              }
              return cb(null, true);
            });
          }
        ]);
      }
    })

  }
  Account.remoteMethod('socialLogin', {
    description: 'Login with social media account',
    accepts: [{
      arg: 'data',
      type: 'object',
      required: true,
      http: {
        source: 'body'
      }
    }],
    returns: {
      arg: 'success',
      type: 'boolean',
      root: true
    },
    http: {
      path: '/social-login',
      verb: 'post',
      status: 200,
      errorStatus: 500
    }
  });

  function sendEmail(user, subject, content, cb) {

    var options = {
      to: user,
      from: emailDs.user,
      subject: subject,
      html: content,
    };
    Account.email.send(options, function (err, email) {
      if (err) return cb(err);
      return cb(null);
    });
  };

  Account.sendUserEmail = function (data, cb) {
    const emails = data.emails;
    const emailData = data.emailData;
    if (!emails instanceof Array) console.log(new Error('Data not in the correct format'));

    emails.forEach(function (email) {
      Account.findOne({
        where: {
          email: email
        }
      }, function (err, user) {
        if (err || !user) console.log(new Error('Email is not associated to an account. Use Sign up'));
        if (user.accountVerified) console.log(new Error('Email has already been verified'));
        sendEmail(user.email, emailData.subject, emailData.content, function (err, result) {
          if (err) return cb(err);
        });
      });
    });
    cb(null);
  }

  Account.remoteMethod('sendUserEmail', {
    description: 'sends email to list of users',
    accepts: [{
      arg: 'data',
      type: 'object',
      required: true,
      http: {
        source: 'body'
      }
    }],
    returns: {
      arg: 'success',
      type: 'boolean',
      root: true
    },
    http: {
      path: '/send-user-email/',
      verb: 'post',
      status: 200,
      errorStatus: 500
    }
  });

  Account.sendEmail = function (data, cb) {
    const emails = data.emails;
    const emailData = data.emailData;
    if (!emails instanceof Array) console.log(new Error('Data not in the correct format'));

    emails.forEach(function (email) {
      Account.findOne({
        where: {
          email: email
        }
      }, function (err, user) {
        sendEmail(email, emailData.subject, emailData.content, function (err, result) {
          if (err) return cb(err);
          return cb(null);
        });
      });
    });

  }

  Account.remoteMethod('sendEmail', {
    description: 'sends email to list of emails that arent users',
    accepts: [{
      arg: 'data',
      type: 'object',
      required: true,
      http: {
        source: 'body'
      }
    }],
    returns: {
      arg: 'success',
      type: 'boolean',
      root: true
    },
    http: {
      path: '/send-email/',
      verb: 'post',
      status: 200,
      errorStatus: 500
    }
  });

  Account.setInvitationCode = function (data, cb) {
    async.waterfall([
      function (callback) {
        Account.findById(data.id, function (err, user) {
          if (err || !user) return cb(new Error('Account not found'));
          callback(err, user);
        })
      },
      function (user, callback) {
        user.updateAttributes({
          "invitivationCode": passcode.generatePasscode(),
        }, function (err) {
          if (err) return cb(new Error('Error Updating Account'))
          cb(null, user);
        });
      }
    ]);
  }
  Account.remoteMethod('setInvitationCode', {
    description: 'Set Invitation Code',
    accepts: [{
      arg: 'data',
      type: 'object',
      required: true,
      http: {
        source: 'body'
      }
    }],
    returns: {
      arg: 'success',
      type: 'boolean',
      root: true
    },
    http: {
      path: '/set-invitation-code',
      verb: 'post',
      status: 200,
      errorStatus: 500
    }
  });
};
