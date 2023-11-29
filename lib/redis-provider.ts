import { Redis } from 'ioredis';
import { PassportModel, PassportStorage, Session, UserAccount, generateSessionId } from './model';
import log4js from 'log4js-api';
import { TokenData, OAuth2Profile } from '@evolplus/evo-oauth2';

export interface RedisConfig {
    host: string;
    port: number;
    password?: string;
    db?: number;
}

const SESSION_KEEP_ALIVE_SECONDS = 60 * 60 * 24 * 30; // 1 month

type OAuthRecord = {
    userId: number;
    token: TokenData;
}

const LOGGER = log4js.getLogger('redis-passport');

export class RedisPassportProvider implements PassportStorage {
    private redisClient: Redis;
    private sessionKeepAlive: number;

    constructor(redisConfig: RedisConfig, sessionKeepAlive: number = SESSION_KEEP_ALIVE_SECONDS) {
        this.redisClient = new Redis(redisConfig);
        this.sessionKeepAlive = sessionKeepAlive;
    }

    async querySessionData(sessionId: string, userId?: number): Promise<Session | undefined> {
        const sessionData = await this.redisClient.get(`session:${sessionId}`);
        if (!sessionData) return undefined;

        const session = JSON.parse(sessionData) as Session;
        if (userId && session.user.userId !== userId) {
            return undefined;
        }
        return session;
    }

    async saveSessionData(session: Session): Promise<boolean> {
        await this.redisClient.set(`session:${session.sessionId}`, JSON.stringify(session), 'EX', this.sessionKeepAlive);
        return true;
    }

    async generateSession(user: UserAccount): Promise<Session> {
        let newSession: Session = {
            sessionId: generateSessionId(user.userId),
            user: user
        };
        await this.saveSessionData(newSession);
        return newSession;
    }

    async queryOAuthMapping(provider: string, sub: string): Promise<UserAccount | undefined> {
        const data = await this.redisClient.get(`oauth:${provider}:${sub}`);
        if (!data) return undefined;
        let oauth = JSON.parse(data) as OAuthRecord;
        return this.getAccountInfo(oauth.userId);
    }

    async getAccountInfo(userId: number): Promise<UserAccount | undefined> {
        const userAccountData = await this.redisClient.get(`userAccount:${userId}`);
        return userAccountData ? JSON.parse(userAccountData) : undefined;
    }

    async createAccount(account: UserAccount): Promise<void> {
        await this.redisClient.set(`userAccount:${account.userId}`, JSON.stringify(account));
        LOGGER.info(`Created new user account ${account.userId}`);
    }

    async saveToken(userId: number, provider: string, sub: string, token: TokenData): Promise<void> {
        await this.redisClient.set(`sub:${provider}:${userId}`, sub);
        await this.redisClient.set(`oauth:${provider}:${sub}`, JSON.stringify({ userId: userId, token: token }));
        LOGGER.info(`Saved token for ${provider}:${sub}`);
    }

    async loadToken(userId: number, provider: string): Promise<TokenData | undefined> {
        let sub = await this.redisClient.get(`sub:${provider}:${userId}`);
        if (!sub) return undefined;
        return this.queryToken(provider, sub);
    }

    async queryToken(provider: string, sub: string): Promise<TokenData | undefined> {
        let tokenData = await this.redisClient.get(`oauth:${provider}:${sub}`);
        if (!tokenData) return undefined;
        return (JSON.parse(tokenData) as OAuthRecord).token;
    }

    async queryProfile(provider: string, userId: number): Promise<OAuth2Profile | undefined> {
        let sub = await this.redisClient.get(`sub:${provider}:${userId}`);
        if (!sub) return undefined;
        return {
            sub: sub
        }
    }
}

export default RedisPassportProvider;