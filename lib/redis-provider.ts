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
    token?: TokenData;
}

type TokenRecord = {
    sub: string;
    token: TokenData;
}

const LOGGER = log4js.getLogger('redis-passport');

function sessionKey(sessionId: string): string {
    return `session:${sessionId}`;
}

function oauthMapKey(provider: string, sub: string): string {
    return `oauth:${provider}:${sub}`;
}

function tokenKey(provider: string, userId: number): string {
    return `token:${provider}:${userId}`;
}

function accountKey(userId: number): string {
    return `account:${userId}`;
}

export class RedisPassportProvider implements PassportStorage {
    private redisClient: Redis;
    private sessionKeepAlive: number;

    constructor(redisConfig: RedisConfig, sessionKeepAlive: number = SESSION_KEEP_ALIVE_SECONDS) {
        this.redisClient = new Redis(redisConfig);
        this.sessionKeepAlive = sessionKeepAlive;
    }

    async querySessionData(sessionId: string, userId?: number): Promise<Session | undefined> {
        const sessionData = await this.redisClient.get(sessionKey(sessionId));
        if (!sessionData) return undefined;

        const session = JSON.parse(sessionData) as Session;
        if (userId && session.user.userId !== userId) {
            return undefined;
        }
        return session;
    }

    async saveSessionData(session: Session): Promise<boolean> {
        await this.redisClient.set(sessionKey(session.sessionId), JSON.stringify(session), 'EX', this.sessionKeepAlive);
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
        const data = await this.redisClient.get(oauthMapKey(provider, sub));
        if (!data) return undefined;
        let oauth = JSON.parse(data) as OAuthRecord;
        return this.getAccountInfo(oauth.userId);
    }

    async getAccountInfo(userId: number): Promise<UserAccount | undefined> {
        const userAccountData = await this.redisClient.get(accountKey(userId));
        return userAccountData ? JSON.parse(userAccountData) : undefined;
    }

    async createAccount(account: UserAccount): Promise<void> {
        await this.redisClient.set(accountKey(account.userId), JSON.stringify(account));
        LOGGER.info(`Created new user account ${account.userId}`);
    }

    async saveToken(userId: number, provider: string, sub: string, token?: TokenData): Promise<void> {
        await this.redisClient.set(oauthMapKey(provider, sub), JSON.stringify({ userId: userId }));
        await this.redisClient.set(tokenKey(provider, userId), JSON.stringify({ sub: sub, token: token }));
        LOGGER.info(`Saved token for ${provider}:${sub}`);
    }

    async loadToken(userId: number, provider: string): Promise<TokenData | undefined> {
        let data = await this.redisClient.get(tokenKey(provider, userId));
        if (!data) return undefined;
        return (JSON.parse(data) as TokenRecord).token;
    }

    async queryToken(provider: string, sub: string): Promise<TokenData | undefined> {
        let data = await this.redisClient.get(oauthMapKey(provider, sub));
        if (!data) return undefined;
        return this.loadToken((JSON.parse(data) as OAuthRecord).userId, provider);
    }

    async queryProfile(provider: string, userId: number): Promise<OAuth2Profile | undefined> {
        let tokenRec = await this.redisClient.get(tokenKey(provider, userId));
        if (!tokenRec) return undefined;
        try {
            return {
                sub: JSON.parse(tokenRec).sub
            }
        } catch (err) {
            LOGGER.error(`Failed to parse token record for ${provider}:${userId}.`, err);
            return undefined;
        }
    }

    async disconnect(provider: string, userId: number): Promise<boolean> {
        let profile = await this.queryProfile(provider, userId);
        if (!profile) return false;
        await this.redisClient.del(tokenKey(provider, userId));
        await this.redisClient.del(oauthMapKey(provider, profile.sub));
        return true;
    }

}

export default RedisPassportProvider;