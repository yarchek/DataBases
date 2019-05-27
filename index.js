const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const config = require('./config');

const passport = require('passport');
const passportJWT = require('passport-jwt');
const LocalStrategy = require('passport-local').Strategy;

const ExtractJwt = passportJWT.ExtractJwt;
const JwtStrategy = passportJWT.Strategy;

const jwtOptions = {};
jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
jwtOptions.secretOrKey = config.secretKey;

// use the strategy

const app = express();
// initialize passport with express
app.use(passport.initialize());

// parse application/json
app.use(bodyParser.json());
//parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: true }));

const Sequelize = require('sequelize');

// initialze an instance of Sequelize
const sequelize = new Sequelize(config.mysqlUrl);

// check the databse connection
sequelize
    .authenticate()
    .then(() => console.log('Connection has been established successfully.'))
    .catch(err => console.error('Unable to connect to the database:', err));

const profileTypes = sequelize.define('profile_type', {
    name: {
        type: Sequelize.STRING,
        allowNull: false,
        validate: {
            isAlpha: true
        }
    }
});

const types = sequelize.define('type', {
    type: {
        type: Sequelize.STRING
    },
    data_type: {
        type: Sequelize.STRING
    }
});

const permissions = sequelize.define('permission', {
    id_type: {
        type: Sequelize.INTEGER,
        allowNull: false,
        references: {
            model: types,
            key: 'id'
        }
    },
    id_profile_type: {
        type: Sequelize.INTEGER,
        references: {
            model: profileTypes,
            key: 'id'
        }
    },
    permission: {
        type: Sequelize.BOOLEAN,
        allowNull: false
    }
});



// create profile model
const Profile = sequelize.define('profile', {
    name: {
        type: Sequelize.STRING
    },
    password: {
        type: Sequelize.STRING
    },
    id_profile_type: {
        type: Sequelize.INTEGER,
        defaultValue: 1,
        references: {
            model: profileTypes,
            key: 'id'
        }
    },
    isAdmin: {
        type: Sequelize.BOOLEAN,
        defaultValue: false
    },
    isAccountant: {
        type: Sequelize.BOOLEAN,
        defaultValue: false
    }
});

const dataElem = sequelize.define('elem_data', {
    elem: {
        type: Sequelize.STRING,
        allowNull: false
    },
    id_profile: {
        type: Sequelize.INTEGER,
        allowNull: false,
        references: {
            model: Profile,
            key: 'id'
        }
    },
    id_type: {
        type: Sequelize.INTEGER,
        allowNull: false,
        references: {
            model: types,
            key: 'id'
        }
    }
});

profileTypes.sync()
    .then(() => console.log('profileTypes table created successfully'))
    .catch((err) => console.log('oooh, did you enter wrong database credentials?', err));

types.sync()
    .then(() => console.log('Types table created successfully'))
    .catch((err) => console.log('oooh, did you enter wrong database credentials?', err));

// create table with profile model
Profile.sync()
    .then(() => console.log('Profile table created successfully'))
    .catch((err) => console.log('oooh, did you enter wrong database credentials?', err));

dataElem.sync()
    .then(() => console.log('DataElem table created successfully'))
    .catch((err) => console.log('oooh, did you enter wrong database credentials?', err));

permissions.sync()
    .then(() => console.log('Permission table created successfully'))
    .catch((err) => console.log('oooh, did you enter wrong database credentials?', err));

passport.use(new JwtStrategy(jwtOptions, (jwt_payload, next) => {
    const user = getProfile({ id: jwt_payload.id });
    console.log('JWT payload: ', jwt_payload);
    if (user) {
        next(null, user);
    } else {
        next(null, false);
    }
}));

// create some helper functions to work on the database
const createProfile = async ({ name, password }) => {
    return await Profile.create({ name, password });
};

const getAllProfiles = async () => {
    return await Profile.findAll();
};

const getProfile = async obj => {
    return await Profile.findOne({
        where: obj,
    });
};

const createProfileType = async ({ name }) => {
    return await profileTypes.create({ name });
};

const createType = async ({ type, data_type }) => {
    return await types.create({  type, data_type });
};

const createPermission = async ({ id_type, id_profile_type, permission }) => {
    return await permissions.create({ id_type, id_profile_type, permission });
};

const createElemData = async ({ elem, id_profile, id_type }) => {
    return await dataElem.create({ elem, id_profile, id_type });
};

const verifyUser = passport.authenticate('jwt', {session: false});

const verifyAdmin = (req, res, next) => {
    if (req.body.name === 'admin') {
        return next();
    } else {
        const err = new Error('You are not authorized to perform this operation!');
        err.status = 403;
        return next(err);
    }
};

const verifyAccountant = (req, res, next) => {
    if (req.body.name === 'accountant') {
        return next();
    } else {
        const err = new Error('You are not authorized to perform this operation!');
        err.status = 403;
        return next(err);
    }
};

const verifyAdmin = (req, res, next) => {
    if (req.body.name === 'admin') {
        return next();
    } else {
        const err = new Error('You are not authorized to perform this operation!');
        err.status = 403;
        return next(err);
    }
};

const verifyAccountantOrAdmin = (req, res, next) => {
    if (req.body.name === 'accountant' || req.body.name === 'admin') {
        return next();
    } else {
        const err = new Error('You are not authorized to perform this operation!');
        err.status = 403;
        return next(err);
    }
};

// set some basic routes
app.get('/', function(req, res) {
    res.json({ message: 'Express is up!' });
});

// get all profiles
app.get('/profiles', verifyUser, verifyAdmin, (req, res) => {
    getAllProfiles().then(profile => res.json(profile));
});

// register route
app.post('/register', (req, res, next) => {
    createProfile(req.body).then(profile =>
        res.json({ profile, msg: 'account created successfully' })
    )
        .catch((err) => next(err));
});

//login route
app.post('/login', async function(req, res, next) {
    const { name, password } = req.body;
    if (name && password) {
        let user = await getProfile({ name: name });
        if (!user) {
            res.status(401).json({ message: 'No such user found' });
        }
        if (user.password === password) {
            // from now on we'll identify the user by the id and the id is the
            // only personalized value that goes into our token
            const payload = { id: user.id, id_profile_type: user.id_profile_type};
            const token = jwt.sign(payload, jwtOptions.secretOrKey);
            res.json({ msg: 'ok', token: token });
        } else {
            res.status(401).json({ msg: 'Password is incorrect' });
        }
    }
});

// protected route
app.get('/protected', verifyUser, (req, res) => {
    res.json('Success! You can now see this without a token.');
});

app.post('/profile_types', verifyUser, verifyAdmin, (req, res, next) => {
    createProfileType(req.body)
        .then((profileType) => {
            res.json({ profileType, msg: 'Profile type created successfully' })
        })
        .catch((err) => {
            next(err);
        })
});

app.post('/types',  verifyUser, verifyAccountant, (req, res, next) => {
    createType(req.body)
        .then((profileType) => {
            res.json({ profileType, msg: 'Profile type created successfully' })
        })
        .catch((err) => {
            next(err);
        })
});

app.post('/permissions',  verifyUser, verifyAdmin, (req, res, next) => {
    createPermission(req.body)
        .then((profileType) => {
            res.json({ profileType, msg: 'Permission created successfully' })
        })
        .catch((err) => {
            next(err);
        })
});

app.post('/elem_data',  verifyUser, verifyAccountant, (req, res, next) => {
    createElemData(req.body)
        .then((profileType) => {
            res.json({ profileType, msg: 'Data element created successfully' })
        })
        .catch((err) => {
            next(err);
        })
});

// start app
app.listen(3000, function() {
    console.log('Express is running on port 3000');
});

