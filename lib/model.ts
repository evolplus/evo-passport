import { randomBytes, randomInt } from "crypto";
import { OAuth2Profile, TokenData } from "@evolplus/evo-oauth2";

const MAX_ID = 281474976710655; // 2^48 - 1
const SESSION_PREFIX_LENGTH = 6;
const SESSION_ROTATE_NUMBER = 65521;

export type UserAccount = {
    userId: number;
    username?: string;
    displayName?: string;
    profilePic?: string
}

export type Session = {
    sessionId: string;
    user: UserAccount;
}

export interface PassportModel {
    querySessionData(sessionId: string, userId?: number): Promise<Session | undefined>;
    saveSessionData(session: Session): Promise<boolean>;
    generateSession(user: UserAccount): Promise<Session>;
    queryOAuthMapping(provider: string, sub: string): Promise<UserAccount | undefined>;
    getAccountInfo(userId: number): Promise<UserAccount | undefined>;
    getOrCreateAccount(provider: string, token: TokenData | undefined, userInfo: OAuth2Profile): Promise<UserAccount>
    saveToken(userId: number, provider: string, sub: string, token: TokenData): Promise<void>;
    loadToken(userId: number, provider: string): Promise<TokenData | undefined>;
    queryToken(provider: string, sub: string): Promise<TokenData | undefined>;
    queryProfile(provider: string, userId: number): Promise<OAuth2Profile | undefined>;
}

export function generateUserId(): number {
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

export default PassportModel;