import { randomBytes, randomInt } from "crypto";
import log4js from "log4js-api";
import { OAuth2Profile, TokenData } from "@evolplus/evo-oauth2";

const MAX_ID = 281474976710655; // 2^48 - 1
const SESSION_PREFIX_LENGTH = 6;
const SESSION_ROTATE_NUMBER = 65521;

const LOGGER = log4js.getLogger("evo-passport");

export type UserAccount = {
    userId: number;
    username?: string;
    displayName?: string;
    profilePic?: string
    email?: string;
    emailVerified?: boolean;
}

export type Session = {
    sessionId: string;
    user: UserAccount;
}

export interface PassportStorage {
    querySessionData(sessionId: string, userId?: number): Promise<Session | undefined>;
    saveSessionData(session: Session): Promise<boolean>;
    generateSession(user: UserAccount): Promise<Session>;
    queryOAuthMapping(provider: string, sub: string): Promise<UserAccount | undefined>;
    getAccountInfo(userId: number): Promise<UserAccount | undefined>;
    createAccount(account: UserAccount): Promise<void>
    saveToken(userId: number, provider: string, sub: string, token: TokenData): Promise<void>;
    loadToken(userId: number, provider: string): Promise<TokenData | undefined>;
    queryToken(provider: string, sub: string): Promise<TokenData | undefined>;
    queryProfile(provider: string, userId: number): Promise<OAuth2Profile | undefined>;
}

function generateUserId(): number {
    return randomInt(MAX_ID);
}

export function generateSessionId(userId: number): string {
    let bytes = randomBytes(SESSION_PREFIX_LENGTH),
        crc = 0;
    for (var i = 0; i < SESSION_PREFIX_LENGTH; i++) {
        crc = (crc * 2 + bytes[i]) % SESSION_ROTATE_NUMBER;
    }
    crc = (crc * 2 + userId) % SESSION_ROTATE_NUMBER;
    return Buffer.concat([bytes, new Uint8Array([crc >> 8, crc % 256])]).toString("hex");
}

export function validateSessionId(sessionId: string, userId: number): boolean {
    try {
        let buff = Buffer.from(sessionId, "hex");
        if (buff.length != SESSION_PREFIX_LENGTH + 2) {
            return false;
        }
        let crc = 0;
        for (var i = 0; i < SESSION_PREFIX_LENGTH; i++) {
            crc = (crc * 2 + buff[i]) % SESSION_ROTATE_NUMBER;
        }
        crc = (crc * 2 + userId) % SESSION_ROTATE_NUMBER;
        return buff[SESSION_PREFIX_LENGTH] == (crc >> 8) && buff[SESSION_PREFIX_LENGTH + 1] == (crc % 256);
    } catch (e) {
        return false;
    }
}

export class PassportModel {
    constructor(private storage: PassportStorage) { }

    async querySessionData(sessionId: string, userId?: number): Promise<Session | undefined> {
        return await this.storage.querySessionData(sessionId, userId);
    }

    async saveSessionData(session: Session): Promise<boolean> {
        return await this.storage.saveSessionData(session);
    }

    async generateSession(user: UserAccount): Promise<Session> {
        return await this.storage.generateSession(user);
    }

    async queryOAuthMapping(provider: string, sub: string): Promise<UserAccount | undefined> {
        return await this.storage.queryOAuthMapping(provider, sub);
    }

    async getAccountInfo(userId: number): Promise<UserAccount | undefined> {
        return await this.storage.getAccountInfo(userId);
    }

    async getOrCreateAccount(provider: string, token: TokenData | undefined, userInfo: OAuth2Profile): Promise<UserAccount> {
        let acc = await this.queryOAuthMapping(provider, userInfo.sub!);
        if (acc) {
            if (token && userInfo.sub) {
                await this.saveToken(acc.userId, provider, userInfo.sub, token);
            }
            return acc;
        }
        let account: UserAccount = {
            userId: generateUserId()
        };
        if (userInfo.email) {
            account.email = userInfo.email;
            account.emailVerified = userInfo.email_verified ? true : false;
        }
        if (userInfo.picture) {
            account.profilePic = userInfo.picture;
        }
        if (userInfo.name) {
            account.displayName = userInfo.name;
        } else {
            account.displayName = `${provider}-${userInfo.sub}`
        }
        await this.storage.createAccount(account);
        if (token) {
            await this.saveToken(account.userId, provider, userInfo.sub!, token);
            LOGGER.info(`Created or update OAuth 2.0 profile: ${provider}/${userInfo.sub}.`);
        }
        return account;
    }

    async saveToken(userId: number, provider: string, sub: string, token: TokenData): Promise<void> {
        return await this.storage.saveToken(userId, provider, sub, token);
    }

    async loadToken(userId: number, provider: string): Promise<TokenData | undefined> {
        return await this.storage.loadToken(userId, provider);
    }

    async queryToken(provider: string, sub: string): Promise<TokenData | undefined> {
        return await this.storage.queryToken(provider, sub);
    }

    async queryProfile(provider: string, userId: number): Promise<OAuth2Profile | undefined> {
        return await this.storage.queryProfile(provider, userId);
    }
}

export default PassportModel;