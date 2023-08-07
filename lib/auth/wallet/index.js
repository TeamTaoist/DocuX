'use strict'

const Router = require('express').Router
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const config = require('../../config')
const models = require('../../models')
const logger = require('../../logger')
const { setReturnToFromReferer } = require('../utils')
const { urlencodedParser } = require('../../utils')
const { SiweMessage } = require('siwe')

const emailAuth = module.exports = Router()

passport.use(new LocalStrategy({
  usernameField: 'message',
  passwordField: 'signature'
}, async function (message, signature, done) {
  // console.log('message: ' + message)
  // console.log('signature: ' + signature)

  let address = ''

  try {
    const siweMessage = new SiweMessage(message)
    const result = await siweMessage.verify({ signature })

    if (result.success) {
      address = result.data.address
    } else {
      return done(result.error)
    }

    logger.info('signature verify success: ' + address)

    // const user = await models.User.findOne({
    //   where: {
    //     // email: 'xiaosong.fu@outlook.com'
    //     email: address
    //   }
    // })
    const [user, created] = await models.User.findOrCreate({
      where: {
        email: address
      }
    })

    if (!user) {
      return done('Failed to register your account, please try again.')
    }

    if (created) {
      logger.info('user registered: ' + user.id)
    } else {
      logger.info('user found: ' + user.id)
    }

    return done(null, user)
  } catch (err) {
    logger.error(err)
    return done(err)
  }
}))

emailAuth.post('/auth/ethereum', urlencodedParser, function (req, res, next) {
  setReturnToFromReferer(req)
  passport.authenticate('local', {
    successReturnToOrRedirect: config.serverURL + '/',
    failureRedirect: config.serverURL + '/',
    failureFlash: 'Invalid signature'
  })(req, res, next)
})
