import User from '../models/user_model.js'
import bcrypt from 'bcryptjs'
import { generateTokenAndSetCookie } from '../lib/utils/generateToken.js'

export const signup = async (req, res) => {
    try {
        const {fullName, username, email, password} = req.body

        // // Basic input validation
        // if (!fullname || !username || !email || !password) {
        //     return res.status(400).json({ error: "All fields are required." });
        // }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: "Invalid email format"})
        }

        const existingUser = await User.findOne({ username})
        if (existingUser) {
            return res.status(400).json({ error: "Username is already taken"})
        }

        const existingEmail = await User.findOne({ email })
        if (existingEmail) {
            return res.status(400).json({ error: "Email is already taken"})
        }

        if(password.length < 6 ) {
            return res.status(400).json({ error: "password must be at least 6 characters"})
        }

        // hasing the  password
        const salt = await bcrypt.genSalt(10)
        const hashedPassword = await bcrypt.hash(password, salt)

        const newUser = new User({
            fullName,
            username,
            email,
            password: hashedPassword
        })

        await newUser.save();       
        generateTokenAndSetCookie(newUser._id, res);

        res.status(201).json({
            _id: newUser._id,
            fullName: newUser.fullName,
            username: newUser.username,
            email: newUser.email,
            followers: newUser.followers,
            following: newUser.following,
            profileImg: newUser.profileImg,
            coverImg: newUser.coverImg,
        })

    } catch (error) {
        console.log("Error in signup controller", error.message);
		res.status(500).json({ error: "Internal Server Error" });
    }
}

export const login = async (req, res) => {
    try {
        const {username,password}= req.body

        // Basic input validation
        if (!username || !password) {
            return res.status(400).json({ error: "Username and password are required." });
        }

        const user = await User.findOne({username})
        if (!user) {
            return res.status(400).json({ error: "Invalid username or password." });
        }

        // Compare plain password with hashed one
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: "Invalid username or password." });
        }

        // Generate token and set it as a cookie
        generateTokenAndSetCookie(user._id, res);

        res.status(200).json({
			_id: user._id,
			fullName: user.fullName,
			username: user.username,
			email: user.email,
			followers: user.followers,
			following: user.following,
			profileImg: user.profileImg,
			coverImg: user.coverImg,
		});

    } catch (error) {
        console.log("Error in login controller", error.message);
		res.status(500).json({ error: "Internal Server Error" });
    }
}

export const logout = async (req, res) => {
    try {
        res.cookie('jwt', '', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            expires: new Date(0), // Expire immediately
          });
        
          res.status(200).json({ message: 'Logged out successfully' });
    } catch (error) {
        console.log("Error in logout controller", error.message);
		res.status(500).json({ error: "Internal Server Error" });
    }
}

export const getMe = async (req, res) => { 
    try {
        const user = await User.findById(req.user._id)
        res.status(200).json(user)
    } catch (error) {
        console.log("Error in getMe controller", error.message);
		res.status(500).json({ error: "Internal Server Error" });
    }
}