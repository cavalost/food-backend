import express from 'express';
import jsonwebtoken from 'jsonwebtoken';
import  cors from 'cors';
import dotEnv from 'dotenv';
import mongodb from 'mongodb';
import crypto from 'crypto';

const { MongoClient, ObjectID } = mongodb;
dotEnv.config();
const { MONGO_URI, MONGO_DB_NAME } = process.env;
const app = express();
const {PORT = 3000} = process.env;
app.use(cors());
app.use(express.json());


app.get('/check', authenticateToken, async (req, res) => {
    const message = "Verified";
    res.json({message});
});

app.post('/login', async (req, res) => {
    let mongoDbClient, user;
    try {
        mongoDbClient = await MongoClient.connect(MONGO_URI, { useNewUrlParser: true });
        const db = mongoDbClient.db(MONGO_DB_NAME);
        user = await db.collection('users').findOne({ email: req.body.email });
        if (user.password !== crypto.createHash("sha256").update(req.body.password).digest("hex")) throw new Error()
        return res.json({ token: jsonwebtoken.sign({ userId: user._id.toString()}, user.secret, {expiresIn: '5d'})});
    } catch (error) {
        return res.sendStatus(403);
    } finally {
        await mongoDbClient.close();
    }
});

async function authenticateToken(req, res, next) {
    let mongoDbClient, user;
    const authHeader = req.headers['authorization'];
    const payload = jsonwebtoken.decode(authHeader);
    try {
        mongoDbClient = await MongoClient.connect(MONGO_URI, { useNewUrlParser: true });
        const db = mongoDbClient.db(MONGO_DB_NAME);
        user = await db.collection('users').findOne({ _id: ObjectID(payload.userId) });
    } catch (error) {
        return res.sendStatus(403);
    } finally {
        await mongoDbClient.close();
    }
    jsonwebtoken.verify(authHeader, user.secret, (err) => {
        if (err) return res.sendStatus(403);
        next();
    })

}

app.listen(PORT, () => {
    console.log(`Example app listening at http://localhost:${PORT}`);
});

