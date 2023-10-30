import { Application, NextFunction, Request, Response } from 'express';
import MySqlPassportModel from './mysql-provider';
import PassportModel, { Session, validateSessionId } from './model';
import { createConfiguration, installProvider, SignedInCallback } from './oauth';
import { OAuth2Profile, OAuth2Provider, TokenData } from '@evolplus/evo-oauth2';
import log4js from 'log4js-api';
import { LRUCache } from '@evolplus/evo-utils';
import { LoginConfiguration, setupLogin } from './login';

const COOKIE_NAME_SESSION_ID = "epssid";
const COOKIE_NAME_USER_ID = "epuid";
const DEFAULT_SESSION_CACHE_CAPACITY = 10000;
const DEFAULT_SESSION_COOKIES_SETTINGS = {httpOnly: true, maxAge: 30 * 86400000};

const LOGGER = log4js.getLogger('passport');

declare global {
    namespace Express {
        export interface Request {
            session?: Session;
        }
    }
}

function expressMiddleware(model: PassportModel) {
    let capacity: number = DEFAULT_SESSION_CACHE_CAPACITY;
    if (process.env.SESSION_CACHE_CAPACITY) {
        let c = parseInt(process.env.SESSION_CACHE_CAPACITY);
        if (c > 0) {
            capacity = c;
        }
    }
    let sessionCache = new LRUCache<Session>(capacity);
    return (req: Request, res: Response, next: NextFunction) => {
        let valid = false;
        if (req.cookies && req.cookies[COOKIE_NAME_SESSION_ID] && req.cookies[COOKIE_NAME_USER_ID]) {
            try {
                let sessionId = req.cookies[COOKIE_NAME_SESSION_ID],
                    userId = parseInt(req.cookies[COOKIE_NAME_USER_ID]);
                let session = sessionCache.get(sessionId);
                if (session) {
                    req.session = session;
                    next();
                    return;
                }
                if (userId && validateSessionId(sessionId, userId)) {
                    model.querySessionData(req.cookies[COOKIE_NAME_SESSION_ID], userId)
                        .then(session => {
                            if (session) {
                                req.session = session;
                                sessionCache.put(session.sessionId, session);
                            }
                            next();
                        })
                        .catch((reason) => {
                            LOGGER.error(`Error query session data: ${reason}.`);
                            next();
                        });
                    valid = true;
                }
            } catch (e) {
                LOGGER.warn(`Error validate session. Error: ${e}`);
            }
        }
        if (!valid) {
            next();
        }
    }
}

function setup(app: Application, passportModel: PassportModel, host: string, prefix: string, providers: OAuth2Provider[], useAsSession?: { [key: string]: boolean }, callback?: SignedInCallback, loginConfig?: LoginConfiguration) {
    if (!prefix.endsWith("/")) {
        prefix += "/";
    }
    app.use(expressMiddleware(passportModel));
    for (let p of providers) {
        let conf = createConfiguration(p);
        installProvider(app, host, prefix, conf, async (provider: string, token: TokenData | undefined, userInfo: OAuth2Profile, req, res) => {
            if (useAsSession && useAsSession[conf.providerName]) {
                let account = await passportModel.getOrCreateAccount(provider, token, userInfo),
                    session = await passportModel.generateSession(account);
                res.cookie(COOKIE_NAME_SESSION_ID, session.sessionId, DEFAULT_SESSION_COOKIES_SETTINGS);
                res.cookie(COOKIE_NAME_USER_ID, account.userId, DEFAULT_SESSION_COOKIES_SETTINGS);
            } else if (req.session && token && userInfo.sub) {
                await passportModel.saveToken(req.session.user.userId, provider, userInfo.sub, token);
            }
            if (callback) {
                callback(provider, token, userInfo, req, res);
            }
            if (!(res.writableEnded || res.headersSent)) {
                res.redirect('/');
                res.end();
            }
        });
    }
    app.get('/logout', (req, res) => {
        res.cookie(COOKIE_NAME_SESSION_ID, "", { maxAge: 0 });
        res.cookie(COOKIE_NAME_USER_ID, "", { maxAge: 0 });
        res.redirect('/');
    });
    if (loginConfig) {
        setupLogin(app, passportModel, host, prefix, loginConfig, (profile: OAuth2Profile, session: Session, req: Request, res: Response) => {
            res.cookie(COOKIE_NAME_SESSION_ID, session.sessionId, DEFAULT_SESSION_COOKIES_SETTINGS);
            res.cookie(COOKIE_NAME_USER_ID, session.user.userId, DEFAULT_SESSION_COOKIES_SETTINGS);
            if (callback) {
                callback('email', undefined, profile, req, res);
            }
        });
    }
}

export { PassportModel, MySqlPassportModel, Session, LoginConfiguration, setup };