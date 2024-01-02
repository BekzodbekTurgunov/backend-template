import { Router } from 'express';
import {register, login, refresh, viewSessions} from '../controllers/authController';
import {checkUserExists, decodeToken} from "../middlewares/checkUser";

const router = Router();

router.post('/register',[checkUserExists] ,register);
router.post('/login', login);
router.post('/refresh', refresh);
router.post('/sessions',[decodeToken], viewSessions);
export default router;
