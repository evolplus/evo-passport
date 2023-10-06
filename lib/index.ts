import { Application, NextFunction, Request, Response } from 'express';
import MySqlPassportModel from './mysql-provider';
import PassportModel, { Session, validateSessionId } from './model';
import { createConfiguration, installProvider, SignedInCallback } from './oauth';
import { OAuth2Profile, OAuth2Provider, TokenData } from '@evolplus/evo-oauth2';
import log4js from 'log4js-api';

const COOKIE_NAME_SESSION_ID = "epssid";
const COOKIE_NAME_USER_ID = "epuid";

let logger = log4js.getLogger('passport');

declare global {
    namespace Express {
        export interface Request {
            session?: Session;
        }
    }
}

function expressMiddleware(model: PassportModel) {
    return (req: Request, res: Response, next: NextFunction) => {
        let valid = false;
        if (req.cookies && req.cookies[COOKIE_NAME_SESSION_ID] && req.cookies[COOKIE_NAME_USER_ID]) {
            try {
                let sessionId = req.cookies[COOKIE_NAME_SESSION_ID],
                    userId = parseInt(req.cookies[COOKIE_NAME_USER_ID]);
                if (userId && validateSessionId(sessionId, userId)) {
                    model.querySessionData(req.cookies[COOKIE_NAME_SESSION_ID], userId).then(session => {
                        req.session = session;
                        next();
                    });
                    valid = true;
                }
            } catch (e) {
                logger.warn(`Error validate session. Error: ${e}`);
            }
        }
        if (!valid) {
            next();
        }
    }
}

function setup(app: Application, passportModel: PassportModel, host: string, prefix: string, providers: OAuth2Provider[], autoCreateAccount?: { [key: string]: boolean }, callback?: SignedInCallback) {
    if (!prefix.endsWith("/")) {
        prefix += "/";
    }
    app.use(expressMiddleware(passportModel));
    for (let p of providers) {
        let conf = createConfiguration(p);
        installProvider(app, host, prefix, conf, async (provider: string, token: TokenData, userInfo: OAuth2Profile, req, res) => {
            if (autoCreateAccount && autoCreateAccount[conf.providerName]) {
                let account = await passportModel.getOrCreateAccount(provider, token, userInfo),
                    session = await passportModel.generateSession(account);
                res.cookie(COOKIE_NAME_SESSION_ID, session.sessionId);
                res.cookie(COOKIE_NAME_USER_ID, account.userId);
            }
            if (callback) {
                callback(provider, token, userInfo, req, res);
            } else {
                res.redirect('/');
            }
            if (!res.writableEnded) {
                res.end();
            }
        });
    }
    app.get('/logout', (req, res) => {
        res.cookie(COOKIE_NAME_SESSION_ID, "", { maxAge: 0 });
        res.cookie(COOKIE_NAME_USER_ID, "", { maxAge: 0 });
        res.redirect('/');
    });
}

export { PassportModel, MySqlPassportModel, Session, setup };