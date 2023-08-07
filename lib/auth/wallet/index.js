'use strict'

const Router = require('express').Router
const passport = require('passport')
const EthereumStrategy = require('passport-ethereum-siwe')
const SessionNonceStore = require('passport-ethereum-siwe').SessionNonceStore
// const config = require('../../config')
const models = require('../../models')
const logger = require('../../logger')
// const { setReturnToFromReferer } = require('../utils')
// const { urlencodedParser } = require('../../utils')

const walletAuth = module.exports = Router()

const store = new SessionNonceStore()

passport.use(new EthereumStrategy({ store: store }, async function (address, done) {
  logger.debug('signature verify success: ' + address)
  try {
    const [user, created] = await models.User.findOrCreate({
      where: {
        email: address
      }
    })

    if (!user) {
      return done('Failed to register your account, please try again.')
    }

    if (created) {
      logger.debug('user registered: ' + user.id)
    } else {
      logger.debug('user found: ' + user.id)
    }
    return done(null, user)
  } catch (err) {
    logger.error(err)
    return done(err)
  }
}))

walletAuth.post('/auth/ethereum/challenge', function (req, res, next) {
  store.challenge(req, function (err, nonce) {
    if (err) { return next(err) }
    res.json({ nonce: nonce })
  })
})

walletAuth.post('/auth/ethereum', passport.authenticate('ethereum', { failWithError: true }),
  function (req, res, next) {
    res.json({ ok: true })
  },
  // eslint-disable-next-line handle-callback-err
  function (err, req, res, next) {
    res.json({ ok: false })
  }
)
