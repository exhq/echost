import Handlebars from 'handlebars';
import { default as express, RequestHandler } from 'express';
import { readFile } from 'fs/promises';

import { nanoid } from 'nanoid';
import { DatabaseHandler } from './database.js'
import bcrypt from 'bcrypt';
import { default as cookieParser } from 'cookie-parser';
import config, { default as echostConfig } from './config.js';
import multer from 'multer';
import { createReadStream, existsSync } from 'fs';
import { lookup as mimeLookup } from 'mime-types';
import { fileURLToPath } from 'url';


const usedport = echostConfig.usedPort;
console.log(echostConfig)
const createTemplate = async (filename: string) => Handlebars.compile(await readFile(filename, { encoding: 'utf-8' }));
const indexTemplate = await createTemplate('index.handlebars');
const faqTemplate = await createTemplate('faq.handlebars');
const app = express();
const database = await DatabaseHandler.connect();
await database.createTables();

const csrfTokens = {};
const sessions = {};
declare global {
    namespace Express {
        interface Request {
            loggedInUser: string | null;
        }
    }
}
const upload = multer({ dest: echostConfig.fileStorage });
app.use(cookieParser());

app.use((req, res, next) => {
    const sessionCookie = req.cookies?.['Session-Cookie'];
    req.loggedInUser = sessions[sessionCookie] ?? null;
    next();
});
app.post('/login', upload.none(), async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password || req.loggedInUser) {
        res.redirect(400, '/');
        return;
    }
    const passwordHash = await database.getPasswordHash(username);
    if (!passwordHash) {
        res.redirect(400, '/')
        return
    }
    const isCorrectPassword = await bcrypt.compare(password, passwordHash);
    if (!isCorrectPassword) {
        res.redirect(400, '/');
        return;
    }
    const sessionCookie = nanoid();
    sessions[sessionCookie] = username;
    res.cookie('Session-Cookie', sessionCookie);
    res.redirect('/');
});

if (echostConfig.openRegistrations) {
    app.post('/register', upload.none(), async (req, res) => {
        const { username, password } = req.body;
        if (!username || !password || req.loggedInUser) {
            res.redirect(400, '/');
            return;
        }
        const passwordHash = await bcrypt.hash(password, 10);
        if (await database.getPasswordHash(username)) {
            res.redirect(400, '/')
            return
        }
        await database.createUser(username, passwordHash);
        const sessionCookie = nanoid();
        sessions[sessionCookie] = username;
        res.cookie('Session-Cookie', sessionCookie);
        res.redirect('/');
    });
}
const verifyCSRF: RequestHandler = (req, res, next) => {
    const csrfToken = req.body['csrf'];
    if (!csrfToken || csrfTokens[csrfToken] !== req.loggedInUser) {
        res.statusCode = 400;
        res.end("Invalid CSRF Token");
        return;
    }
    next();
};

const verifyLoggedIn: RequestHandler = (req, res, next) => {
    if (!req.loggedInUser) {
        res.redirect(400, '/')
        return
    }
    next()
}

app.post('/logout', upload.none(), verifyCSRF, async (req, res) => {
    res.cookie('Session-Cookie', 'logged out');
    res.redirect('/')
});

app.post('/upload', verifyLoggedIn, upload.single('file'), verifyCSRF, async (req, res) => {
    const file = req.file;
    if (file.filename) { }
    const diskName = file.filename;
    const originalName = file.originalname;
    const user = req.loggedInUser;
    await database.createFile(user, originalName, diskName);
    res.redirect(`/file/${user}/${originalName}`);
});

const fileDisplay: RequestHandler = async (req, res) => {
    const { file } = req.params;
    const user = 'user' in req.params ? req.params.user : echostConfig.defaultUser;
    const path = await database.getPathForFileName(user, file);
    if (existsSync(`${echostConfig.fileStorage}/${path}`)) {
        const mimeType = mimeLookup(file);
        if (mimeType && config.mimeTypeWhiteList.includes(mimeType)) {
            res.header("Content-Type", mimeType)
        } else {
            res.header("Content-Type", "application/octet-stream")
        }
        createReadStream(`${echostConfig.fileStorage}/${path}`).pipe(res)
    } else {
        res.status(404)
        res.header("Content-Type", "text/plain")
        res.end("Not found")
    }
};

app.get('/', (req, res) => {
    res.setHeader('content-type', 'text/html')
    const csrfToken = nanoid();
    csrfTokens[csrfToken] = req.loggedInUser;
    res.end(indexTemplate({
        isLoggedIn: !!req.loggedInUser,
        userName: req.loggedInUser,
        csrfToken: csrfToken,
        openRegistrations: echostConfig.openRegistrations
    }));
});
app.get('/faq', (req, res) => {
    res.setHeader('content-type', 'text/html')
    res.end(faqTemplate({}));
});
app.use(express.static('static'))
app.get('/file/:user/:file', fileDisplay);
app.get('/:user/:file', fileDisplay);
app.get('/:file', fileDisplay);

app.listen(usedport, () => console.log('Started with port ' + usedport));
