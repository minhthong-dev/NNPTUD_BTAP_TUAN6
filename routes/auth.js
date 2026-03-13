var express = require('express');
var router = express.Router();
let userController = require('../controllers/users')
let { RegisterValidator, handleResultValidator, changePassValidator } = require('../utils/validatorHandler')
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
let { checkLogin } = require('../utils/authHandler')
/* GET home page. */
router.post('/register', RegisterValidator, handleResultValidator, async function (req, res, next) {
    let newUser = userController.CreateAnUser(
        req.body.username,
        req.body.password,
        req.body.email,
        "69aa8360450df994c1ce6c4c"
    );
    await newUser.save()
    res.send({
        message: "dang ki thanh cong"
    })
});
const fs = require('fs');
const path = require('path');
const privateKey = fs.readFileSync(path.join(__dirname, '../jwtRS256.key'), 'utf8');

router.post('/login', async function (req, res, next) {
    let { username, password } = req.body;
    let getUser = await userController.FindByUsername(username);
    if (!getUser) {
        res.status(403).send("tai khoan khong ton tai")
    } else {
        if (getUser.lockTime && getUser.lockTime > Date.now()) {
            res.status(403).send("tai khoan dang bi ban");
            return;
        }
        if (bcrypt.compareSync(password, getUser.password)) {
            await userController.SuccessLogin(getUser);
            let token = jwt.sign({
                id: getUser._id
            }, privateKey, {
                algorithm: 'RS256',
                expiresIn: '30d'
            })
            res.send(token)
        } else {
            await userController.FailLogin(getUser);
            res.status(403).send("thong tin dang nhap khong dung")
        }
    }

});
router.get('/me', checkLogin, function (req, res, next) {
    res.send(req.user)
})
router.put('/change-pass', changePassValidator, checkLogin, handleResultValidator, async function (req, res, next) {
    let { newPass } = req.body;
    if (bcrypt.compareSync(newPass, req.user.password)) {
        res.status(403).send("mat khau moi khong duoc trung voi mat khau cu")
        return;
    } else {
        let result = await userController.ChangePass(req.user, newPass)
        if (!result)
            res.status(500).send("loi he thong")
        else
            res.send("thay doi mat khau thanh cong")
    }
})

module.exports = router;
