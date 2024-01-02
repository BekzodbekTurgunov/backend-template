import { Router } from 'express';
import {register, login, refresh} from '../controllers/authController';
import {checkUserExists} from "../middlewares/checkUser";

const router = Router();

router.post('/register',[checkUserExists] ,register);
router.post('/login', login);
router.post('/refresh', refresh);
export default router;
