import { randomBytes, randomInt, createHmac } from "crypto";
import log4js from "log4js-api";
import { OAuth2Profile, TokenData } from "@evolplus/evo-oauth2";

const MAX_ID = 281474976710655; // 2^48 - 1
const SESSION_PREFIX_LENGTH = 6;
const PASSPORT_SECRET_KEY = process.env.PASSPORT_SESSION_SECRET;

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
    saveToken(userId: number, provider: string, sub: string, token?: TokenData): Promise<void>;
    loadToken(userId: number, provider: string): Promise<TokenData | undefined>;
    queryToken(provider: string, sub: string): Promise<TokenData | undefined>;
    queryProfile(provider: string, userId: number): Promise<OAuth2Profile | undefined>;
    disconnect(provider: string, userId: number): Promise<boolean>;
}

function generateUserId(): number {
    return randomInt(MAX_ID);
}

// Generates a session ID using HMAC-SHA256
export function generateSessionId(userId: number): string {
    if (!PASSPORT_SECRET_KEY) {
        throw new Error("PASSPORT_SESSION_SECRET is not set.");
    }
    // Generate random bytes for the session prefix
    const prefix = randomBytes(SESSION_PREFIX_LENGTH);
    
    // Create an HMAC using SHA-256 with the secret key
    const hmac = createHmac('sha256', PASSPORT_SECRET_KEY);
    hmac.update(prefix);
    hmac.update(userId.toString());
    
    // Compute the HMAC digest
    const signature = hmac.digest();
    
    // Return the prefix and the HMAC signature as the session ID
    return Buffer.concat([prefix, signature]).toString('hex');
}

// Validates the session ID using HMAC-SHA256
export function validateSessionId(sessionId: string, userId: number): boolean {
    if (!PASSPORT_SECRET_KEY) {
        throw new Error("PASSPORT_SESSION_SECRET is not set.");
    }
    try {
        // Decode the session ID
        const buff = Buffer.from(sessionId, 'hex');
        const prefix = buff.slice(0, SESSION_PREFIX_LENGTH);
        const signature = buff.slice(SESSION_PREFIX_LENGTH);
        
        // Recompute the HMAC based on the prefix and userId
        const hmac = createHmac('sha256', PASSPORT_SECRET_KEY);
        hmac.update(prefix);
        hmac.update(userId.toString());
        const validSignature = hmac.digest();
        
        // Compare the signatures securely
        return timingSafeEqual(signature, validSignature);
    } catch (e) {
        return false;
    }
}

// Helper function to prevent timing attacks during comparison
function timingSafeEqual(a: Buffer, b: Buffer): boolean {
    if (a.length !== b.length) {
        return false;
    }
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i];
    }
    return result === 0;
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
        await this.saveToken(account.userId, provider, userInfo.sub!, token);
        LOGGER.info(`Created or update OAuth 2.0 profile: ${provider}/${userInfo.sub}.`);
        return account;
    }

    async saveToken(userId: number, provider: string, sub: string, token?: TokenData): Promise<void> {
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

    async disconnect(provider: string, userId: number): Promise<boolean> {
        return await this.storage.disconnect(provider, userId);
    }
}

export default PassportModel;