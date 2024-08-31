import { Application, NextFunction, Request, Response } from 'express';
import MySqlPassportProvider from './mysql-provider';
import RedisPassportProvider from './redis-provider';
import PassportModel, { Session, validateSessionId } from './model';
import { createConfiguration, installProvider, SignedInCallback } from './oauth';
import { OAuth2Profile, OAuth2Provider, TokenData } from '@evolplus/evo-oauth2';
import log4js from 'log4js-api';
import { LRUCache } from '@evolplus/evo-utils';
import { LoginConfiguration, setupLogin } from './login';
import { Kafka } from 'kafkajs';
import { randomInt } from 'crypto';

const COOKIE_NAME_SESSION_ID = "epssid";
const COOKIE_NAME_USER_ID = "epuid";
const DEFAULT_SESSION_CACHE_CAPACITY = 10000;
const DEFAULT_SESSION_COOKIES_SETTINGS = { httpOnly: true, maxAge: 30 * 86400000 };

const LOGGER = log4js.getLogger('passport');

declare global {
    namespace Express {
        export interface Request {
            session?: Session;
        }
    }
}

export type WebPassportConfig = {
    passportHost: string;
    domain: string;
    prefix: string;
    loginConfig?: LoginConfiguration;
    kafka?: {
        brokers: string[];
        topic: string;
    }
}

function expressMiddleware(model: PassportModel, config: WebPassportConfig) {
    let capacity: number = DEFAULT_SESSION_CACHE_CAPACITY;
    if (process.env.SESSION_CACHE_CAPACITY) {
        let c = parseInt(process.env.SESSION_CACHE_CAPACITY);
        if (c > 0) {
            capacity = c;
        }
    }
    let sessionCache = new LRUCache<Session>(capacity);
    if (config.kafka) {
        runWorker(config.kafka.brokers, config.kafka.topic, sessionCache);
    }
    return (req: Request, res: Response, next: NextFunction) => {
        if (req.cookies && req.cookies[COOKIE_NAME_SESSION_ID] && req.cookies[COOKIE_NAME_USER_ID]) {
            try {
                let sessionId = req.cookies[COOKIE_NAME_SESSION_ID],
                    userId = parseInt(req.cookies[COOKIE_NAME_USER_ID]);
                let session = sessionCache.get(sessionId);
                if (session) {
                    LOGGER.debug(`Session found in cache for user ${userId}.`);
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
                                LOGGER.debug(`Session found for user ${userId}.`);
                            } else {
                                LOGGER.warn(`Session not found for user ${userId}.`);
                            }
                            next();
                        })
                        .catch((reason) => {
                            LOGGER.error(`Error query session data: ${reason}.`);
                            next();
                        });
                }
            } catch (e) {
                LOGGER.warn(`Error validate session. Error: ${e}`);
                next();
            }
        } else {
            next();
        }
    }
}

function setupSessionParser(app: Application, model: PassportModel, config: WebPassportConfig) {
    app.use(expressMiddleware(model, config));
}

export async function runWorker(brokers: string[], topic: string, sessionCache: LRUCache<Session>) {
    // Create the Kafka client
    let clientId = `evo-passport-${randomInt(100000)}`;
    const kafka = new Kafka({
        clientId: clientId,
        brokers: brokers,
    }),
        consumer = kafka.consumer({ groupId: clientId }),
        consumeMessages = async () => {
            await consumer.connect();
            await consumer.subscribe({ topic: topic, fromBeginning: true });

            await consumer.run({
                eachMessage: async ({ topic, partition, message }) => {
                    try {
                        let obj: any = JSON.parse(message.value!.toString());
                        LOGGER.info(`Received event from Strava: ${JSON.stringify(obj)}`);
                        switch (obj.type) {
                            case 'delete':
                                LOGGER.log(`Session deleted: ${obj.id}.`);
                                await caches.delete(obj.id);
                                break;
                            case 'create':
                                LOGGER.log("Session created: " + obj.id);
                                //TODO: do something when a new session have just created
                                break;
                        }
                    } catch (err) {
                        LOGGER.error(`Critical error while handling session data message.`, err);
                    }
                }
            });
        };
    await consumeMessages();
}

function setup(app: Application, passportModel: PassportModel, config: WebPassportConfig, providers: OAuth2Provider[], useAsSession?: { [key: string]: boolean }, callback?: SignedInCallback) {
    let prefix = config.prefix.endsWith("/") ? config.prefix : config.prefix + "/",
        host = config.passportHost,
        cookieSettings = Object.assign({}, DEFAULT_SESSION_COOKIES_SETTINGS, { domain: config.domain });
    app.use(expressMiddleware(passportModel, config));
    for (let p of providers) {
        let conf = createConfiguration(p);
        installProvider(app, host, prefix, conf, async (provider: string, token: TokenData | undefined, userInfo: OAuth2Profile | undefined, req, res) => {
            if (userInfo) {
                if (useAsSession && useAsSession[conf.providerName]) {
                    let account = await passportModel.getOrCreateAccount(provider, token, userInfo),
                        session = await passportModel.generateSession(account);
                    res.cookie(COOKIE_NAME_SESSION_ID, session.sessionId, cookieSettings);
                    res.cookie(COOKIE_NAME_USER_ID, account.userId, cookieSettings);
                } else if (req.session && token && userInfo.sub) {
                    await passportModel.saveToken(req.session.user.userId, provider, userInfo.sub, token);
                }
                if (callback) {
                    await callback(provider, token, userInfo, req, res);
                }
                if (!(res.writableEnded || res.headersSent)) {
                    res.redirect('/');
                    res.end();
                }
            } else {
                LOGGER.error(`Failed to get profile from ${provider}.`);
                res.status(500).send('Internal Server Error');
            }
        });
    }
    app.get('/logout', async (req, res) => {
        res.cookie(COOKIE_NAME_SESSION_ID, "", { maxAge: 0, domain: config.domain });
        res.cookie(COOKIE_NAME_USER_ID, "", { maxAge: 0, domain: config.domain });
        if (callback) {
            callback('logout', undefined, undefined, req, res);
        }
        if (!(res.writableEnded || res.headersSent)) {
            res.redirect('/');
        }
        if (config.kafka) {
            let kafka = new Kafka({
                clientId: `evo-passport-${randomInt(100000)}`,
                brokers: config.kafka.brokers
            }),
                producer = kafka.producer();
            try {
                await producer.connect();
                await producer.send({
                    topic: config.kafka.topic,
                    messages: [
                        { value: JSON.stringify({ type: 'delete', id: req.session?.sessionId }) }
                    ]
                });
                await producer.disconnect();
            } catch (err) {
                LOGGER.error(`Critical error while sending message to Kafka.`, err);
            }
        }
    });
    if (config.loginConfig) {
        setupLogin(app, passportModel, host, config.domain, prefix, config.loginConfig, (profile: OAuth2Profile, session: Session, req: Request, res: Response) => {
            res.cookie(COOKIE_NAME_SESSION_ID, session.sessionId, cookieSettings);
            res.cookie(COOKIE_NAME_USER_ID, session.user.userId, cookieSettings);
            if (callback) {
                callback('email', undefined, profile, req, res);
            }
        });
    }
}

export { PassportModel, MySqlPassportProvider, RedisPassportProvider, Session, LoginConfiguration, setup, setupSessionParser };