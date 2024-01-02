import express, { Express } from 'express';
import dotenv from 'dotenv';
import routes from './routes';

dotenv.config();

const app: Express = express();
app.use(express.json());

app.use('/', routes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
