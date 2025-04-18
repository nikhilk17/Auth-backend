import express from 'express';
import cors from 'cors';
import 'dotenv/config';
import cookieParser from 'cookie-parser';
import connectDB from './config/mongodb.js';
import authRouter from './routes/authRouter.js'
import userRouter from './routes/userRouter.js'

const app = express();
const port = process.env.PORT || 4000;
connectDB();

const allowedOrigins = [
    'http://localhost:5173',
    'https://auth-frontend-psi-henna.vercel.app',
    'https://auth-frontend-msgiu5817-nikhils-projects-9aa3d82c.vercel.app'
];

app.use(cors({
    origin: function(origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(null, false);
        }
    },
    credentials: true,
    optionsSuccessStatus: 200
}));

app.use(express.json());
app.use(cookieParser());

// API endpoints
app.get('/',(req,res)=>{
    res.send('Hello World!!!!');
})

app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);
app.listen(port, () => console.log(`Server is running on port ${port}`));
