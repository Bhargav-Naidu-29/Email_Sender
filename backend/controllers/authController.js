const User = require('../models/User'); // Changed from users to User
const jwt = require('jsonwebtoken');

// Resolve JWT secret with a safe fallback in development only
const JWT_SECRET = process.env.SECRET_KEY || (process.env.NODE_ENV !== 'production' ? 'dev_secret_change_me' : undefined);

const createToken = (_id) => {
    if (!JWT_SECRET) {
        throw new Error('Missing SECRET_KEY. Set it in backend .env for JWT signing.');
    }
    return jwt.sign({ _id }, JWT_SECRET, { expiresIn: '2d' });
}

//login 
const loginUser = async (req, res) => {
    const {email, password} = req.body

    try{
        const user = await User.login(email, password)
        const token = createToken(user._id)
        res.status(200).json({userName : user.userName, email, token})
    }
    catch(error){
        res.status(400).json({error : error.message})
    }
}

//signup
const signupUser = async (req, res) => {
    const {userName, email, password} = req.body;

    try{
        const user = await User.signup(userName, email, password)
        const token = createToken(user._id);
        res.status(200).json({userName, email, token});
    }
    catch(error){
        res.status(400).json({error : error.message})
    }
}

module.exports = {signupUser, loginUser};