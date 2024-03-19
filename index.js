const { Sequelize, DataTypes } = require('sequelize');
const express = require('express');
const app = express();
const bcrypt = require('bcrypt'); // For password hashing
const jwt = require('jsonwebtoken'); // For generating and verifying JWT tokens
const cors = require('cors'); // Import the cors middleware

// Remove dependency on body-parser
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cors()); // Enable CORS for all requests

const sequelize = new Sequelize('postgresql://ecommerce_owner:Q8DChNd7Hbuk@ep-holy-math-a1qtcjfx.ap-southeast-1.aws.neon.tech/ecommerce?sslmode=require');

const User = sequelize.define('User', {
    name: {
        type: DataTypes.STRING,
        allowNull: false
    },
    email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false
    },
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    }
});

async function startServer() {
    try {
        await sequelize.authenticate();
        console.log('Connection has been established successfully.');

        await sequelize.sync(); // This will sync your defined models with the database

        // Define routes
        // app.post('/user/register', async (req, res) => {
        //     try {
        //         const { name, email, password } = req.body;
        //         const hashedPassword = await bcrypt.hash(password, 10);
        //         const user = await User.create({ name, email, password:hashedPassword });
        //         res.status(201).json({ status: "success", data: user });
        //     } catch (error) {
        //         console.error('Error registering user:', error);
        //         res.status(500).json({ status: "error", message: "Unable to register user" });
        //     }
        // });

        app.post('/user/register', async (req, res) => {
            try {
                const { name, email, password } = req.body;
                // Check if the email is already registered
                const existingUser = await User.findOne({ where: { email } });
                if (existingUser) {
                    return res.status(400).json({ status: "error", message: "Email is already in use" });
                }
                // If the email is not already registered, proceed with user creation
                const hashedPassword = await bcrypt.hash(password, 10);
                const user = await User.create({ name, email, password: hashedPassword });
                res.status(201).json({ status: "success", data: user });
            } catch (error) {
                console.error('Error registering user:', error);
                res.status(500).json({ status: "error", message: "Unable to register user" });
            }
        });

        // Middleware to verify JWT token
        function verifyToken(req, res, next) {
            const token = req.headers['authorization'];
            if (!token) {
                return res.status(401).json({ status: "error", message: "Token not provided" });
            }
            jwt.verify(token, 'your_secret_key', (err, decoded) => {
                if (err) {
                    return res.status(403).json({ status: "error", message: "Failed to authenticate token" });
                }
                req.userId = decoded.id;
                next();
            });
        }

        // Get user route by verifying JWT token
        app.get('/user/profile', verifyToken, async (req, res) => {
            try {
                const user = await User.findByPk(req.userId);
                if (!user) {
                    return res.status(404).json({ status: "error", message: "User not found" });
                }
                res.status(200).json({ status: "success", data: user });
            } catch (error) {
                console.error('Error fetching user profile:', error);
                res.status(500).json({ status: "error", message: "Unable to fetch user profile" });
            }
        });

        app.post('/login', async (req, res) => {
            // Handle login logic
            try {
                const { email, password } = req.body;
                const user = await User.findOne({ where: { email } });
                if (!user) {
                    return res.status(404).json({ status: "error", message: "User not found" });
                }
                const validPassword = await bcrypt.compare(password, user.password);
                if (!validPassword) {
                    return res.status(401).json({ status: "error", message: "Invalid password" });
                }
                const token = jwt.sign({ id: user.id, email: user.email }, 'your_secret_key'); // Replace 'your_secret_key' with your actual secret key
                res.status(200).json({ status: "success", token });
            } catch (error) {
                console.error('Error logging in:', error);
                res.status(500).json({ status: "error", message: "Unable to log in" });
            }
        });

        app.listen(3000, () => {
            console.log('Server is running on port 3000');
        });
    } catch (error) {
        console.error('Unable to connect to the database:', error);
    }
}

startServer();
