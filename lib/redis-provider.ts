import { Redis, Cluster } from 'ioredis';
import { PassportModel, PassportStorage, Session, UserAccount, generateSessionId } from './model';
import log4js from 'log4js-api';
import { TokenData, OAuth2Profile } from '@evolplus/evo-oauth2';

export interface RedisConfig {
    host: string;
    port: number;
    password?: string;
    db?: number;
    prefix?: string;
}

export interface RedisClusterConfig {
    nodes: { host: string, port: number }[];
    password?: string;
    db?: number;
    prefix?: string;
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

function sessionKey(prefix: string, sessionId: string): string {
    return `${prefix}session:${sessionId}`;
}

function oauthMapKey(prefix: string, provider: string, sub: string): string {
    return `${prefix}oauth:${provider}:${sub}`;
}

function tokenKey(prefix: string, provider: string, userId: number): string {
    return `${prefix}token:${provider}:${userId}`;
}

function accountKey(prefix: string, userId: number): string {
    return `${prefix}account:${userId}`;
}

//TODO: options to use both Redis node and Redis cluster, prefix for keys
export class RedisPassportProvider implements PassportStorage {
    private redisClient: Redis | Cluster;
    private prefix: string;
    private sessionKeepAlive: number;

    constructor(redisConfig: RedisConfig | RedisClusterConfig, sessionKeepAlive: number = SESSION_KEEP_ALIVE_SECONDS) {
        if ('nodes' in redisConfig) {
            this.redisClient = new Redis.Cluster(redisConfig.nodes, {
                redisOptions: {
                    password: redisConfig.password,
                    db: redisConfig.db
                }
            });
        } else {
            this.redisClient = new Redis(redisConfig);
        }
        this.prefix = redisConfig.prefix || '';
        this.sessionKeepAlive = sessionKeepAlive;
    }

    async querySessionData(sessionId: string, userId?: number): Promise<Session | undefined> {
        const sessionData = await this.redisClient.get(sessionKey(this.prefix, sessionId));
        if (!sessionData) return undefined;

        const session = JSON.parse(sessionData) as Session;
        if (userId && session.user.userId !== userId) {
            return undefined;
        }
        return session;
    }

    async saveSessionData(session: Session): Promise<boolean> {
        await this.redisClient.set(sessionKey(this.prefix, session.sessionId), JSON.stringify(session), 'EX', this.sessionKeepAlive);
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
        const data = await this.redisClient.get(oauthMapKey(this.prefix, provider, sub));
        if (!data) return undefined;
        let oauth = JSON.parse(data) as OAuthRecord;
        return this.getAccountInfo(oauth.userId);
    }

    async getAccountInfo(userId: number): Promise<UserAccount | undefined> {
        const userAccountData = await this.redisClient.get(accountKey(this.prefix, userId));
        return userAccountData ? JSON.parse(userAccountData) : undefined;
    }

    async createAccount(account: UserAccount): Promise<void> {
        await this.redisClient.set(accountKey(this.prefix, account.userId), JSON.stringify(account));
        LOGGER.info(`Created new user account ${account.userId}`);
    }

    async saveToken(userId: number, provider: string, sub: string, token?: TokenData): Promise<void> {
        await this.redisClient.set(oauthMapKey(this.prefix, provider, sub), JSON.stringify({ userId: userId }));
        await this.redisClient.set(tokenKey(this.prefix, provider, userId), JSON.stringify({ sub: sub, token: token }));
        LOGGER.info(`Saved token for ${provider}:${sub}`);
    }

    async loadToken(userId: number, provider: string): Promise<TokenData | undefined> {
        let data = await this.redisClient.get(tokenKey(this.prefix, provider, userId));
        if (!data) return undefined;
        return (JSON.parse(data) as TokenRecord).token;
    }

    async queryToken(provider: string, sub: string): Promise<TokenData | undefined> {
        let data = await this.redisClient.get(oauthMapKey(this.prefix, provider, sub));
        if (!data) return undefined;
        return this.loadToken((JSON.parse(data) as OAuthRecord).userId, provider);
    }

    async queryProfile(provider: string, userId: number): Promise<OAuth2Profile | undefined> {
        let tokenRec = await this.redisClient.get(tokenKey(this.prefix, provider, userId));
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
        await this.redisClient.del(tokenKey(this.prefix, provider, userId));
        await this.redisClient.del(oauthMapKey(this.prefix, provider, profile.sub));
        return true;
    }

}

export default RedisPassportProvider;