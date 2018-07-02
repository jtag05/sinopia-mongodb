const mongoose = require('mongoose');
const bcrypt = require('bcrypt-nodejs');
const SinopiaUser = require('./lib/sinopiaUser.js');

function SinopiaMongodb(config, sinopia) {
    console.log('sinopia-mongodb plugin loaded.');

    /** Connection to mongodb database **/
    if (!config['host']) {
        throw new Error('Need a valid host in config file.');
    }

    const mongodb_uri = `mongodb://${config['host']}${config['port'] ? `:${config['port']}` : ''}/${config['database'] ? config['database'] : ''}`;
   
    mongoose.connect(mongodb_uri, {
        user: config['username'],
        pass: config['password'],
        auth: { authdb: 'admin' }
        useMongoClient: true
    }, function (err) {
        if (err) { throw err; }
    });

    /**
     * Always return a cb(null, true) to allow to add an user
     * @param user
     * @param password
     * @param callback
     * @returns {*}
     */
    this.adduser = function (user, password, callback) {
        if (config.registration_enabled) {
            return SinopiaUser.findOne({ username: user }, function (err, doc) {
                if (err) {
                    return callback(err, null);
                }
                if (doc) {
                    return callback(null, false);
                }

                bcrypt.genSalt(10, function (err, salt) {
                    if (err) {
                        return callback(err, null);
                    }

                    bcrypt.hash(password, salt, null, function (err, hash) {
                        if (err) {
                            return callback(err, null);
                        }

                        SinopiaUser.create({
                            username: user,
                            token: hash,
                            type: 'user',
                            enabled: true
                        }, function (err, doc) {
                            return callback(err, doc);
                        });
                    });
                });
            });
        }

        return callback(null, true);
    };

    this.authenticate = function (user, password, callback) {
        // Find the

        SinopiaUser.findOne({ username: user }, function (err, doc) {
            if (err) { return callback(err, null); }

            if (!doc) { return callback(null, false); }

            let pass = Promise.resolve();
            if (password !== doc.token) {
                pass = new Promise(function (resolve, reject) {
                    bcrypt.compare(password, doc.token, function (err, isMatch) {
                        if (err) {
                            return reject(err);
                        }
                        return resolve(isMatch);
                    });
                });
            }

            pass.then(function () {
                doc.last_download = new Date();
                doc.download += 1;
                doc.save(function (err) {
                    return callback(err, [ user ]);
                });
            }).catch(function (err) {
                return callback(err, null);
            });
        });
    };
}

module.exports = function (config, stuff) {
    return new SinopiaMongodb(config, stuff);
};
