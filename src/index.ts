import express from 'express';
import http from 'http';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import compression from 'compression';
import cors from 'cors';
import 'dotenv/config';
import router from './router';

const app = express();

app.use(cors({ credentials: true }));
app.use(compression());
app.use(cookieParser());
app.use(bodyParser.json());
app.use('/', router);


router.get('/check', (req, res) => {
    res.status(200).json({ message: 'Server is running', status: 'OK' });
});


const server = http.createServer(app);

server.listen(8080, () => {
    console.log('Server running... at 8080');
});
