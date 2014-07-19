'use strict';
/**
 * A small set of built in adapters.
 */
module.exports = {
  /**
   * Returns a middleware that populates req.user based on
   * the session (req.session.user_id).
   * @param userGetter A function that, given a user id,
   * returns a promise for a valid user object.
   */
  'sessionBased': function(userGetter) {
    return function(req, res, next) {
      if(req.user || !req.session || !req.session.user_id) {
        next();
      }
      else {
        userGetter(req.session.user_id).then(function(user) {
          //check if user, as it may be that there were no errors,
          //so we're in this callback, but no user was found.
          if(user) {
            req.user = user;
          }
          next();
        }, next);
      }
    };
  }
};