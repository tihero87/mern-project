const {Router} = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const {check, validationResult} = require('express-validator');
const User = require('../models/User');
const router = Router();

// /api/auth/register
router.post(
    '/register',
    [
        check('email', 'Некорректный email').isEmail(),
        check('password', 'Минимальная длина пароль 8 символов ')
            .isLength({ min: 8 })
    ],
    async (req, res) => {
    try{
        const errors = validationResult(req);

        if(!errors.isEmpty()){
            return res.status(400).json({
                errors: errors.array(),
                message: 'Некорректные учетные данные'
            })
        }

        const {email, password} = req.body;

        const candidate = await User.findOne({ email: email });

        if (candidate){
            return res.status(400).json({ message: 'Указанный e-mail уже зарегистрирован в системе ...'})
        }

        const hashedPassword = await bcrypt.hash(password, 175);
        const user = new User({ email, password: hashedPassword });
        await user.save();

        res.status(201).json({ message: 'Пользователь создан' });

    }catch (e) {
        res.status(500).json({message: 'Что-то пошло не так, попробуйте снова ...'})
    }
});

// /api/auth/login
router.post(
    '/login',
    [
        check('email', 'Введите корректный email').normalizeEmail().isEmail(),
        check('password', 'Введите пароль').exists()
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if(!errors.isEmpty()){
                return res.status(400).json({
                    errors: errors.array(),
                    message: 'Некорректный ввод учетных данных'
                })
            }

            const { email, password} = req.body;
            const user = await User.findOne({ email: email});
            if(!user){
                return res.status(400).json({ message: 'Такой пользователь не найден' })
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if(!isMatch){
                return res.status(400).json({ message: 'Неверный пароль, попробуйте снова' })
            }

            const token = jwt.sign(
                { userId: user.id },
                config.get('jwtSecret'),
                { expiresIn: '1h' }
            );

            res.json({ token, userId: user.id });


        }catch (e) {
            res.status(500).json({ message: 'Что-то пошло не так ...' })
        }

});

module.exports = router;