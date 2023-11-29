import mysql, { Pool, PoolConfig } from "mysql";
import { generateSessionId, PassportModel, PassportStorage, Session, UserAccount } from "./model";
import log4js from "log4js-api";
import { OAuth2Profile, TokenData } from "@evolplus/evo-oauth2";

const TABLE_NAME_ACCOUNTS = "accounts";
const TABLE_NAME_SESIONS = "sessions";
const TABLE_NAME_OAUTH = "oauth";

const CLEANUP_INTERVAL = 1000 * 60 * 60 * 24; // 1 day
const SESSION_KEEP_ALIVE = 1000 * 60 * 60 * 24 * 30; // 1 month
const LOGGER = log4js.getLogger("evo-passport-mysql");

function dataToSession(data: any): Session | undefined {
    if (Array.isArray(data)) {
        if (data.length == 0) {
            return undefined;
        }
        data = data[0];
    }
    return {
        sessionId: data.ssid,
        user: {
            userId: data.id,
            username: data.username,
            displayName: data.display_name,
            profilePic: data.picture
        }
    };
}

function accountToDBSchema(account: UserAccount): any {
    return {
        id: account.userId,
        username: account.username,
        display_name: account.displayName,
        picture: account.profilePic,
        email: account.email,
        email_verified: account.emailVerified
    };
}

export class MySqlPassportProvider implements PassportStorage {
    private connPool: Pool;
    private sessionKeepAlive: number;;

    constructor(config: PoolConfig, sessionKeepAlive: number = SESSION_KEEP_ALIVE) {
        this.connPool = mysql.createPool(config);
        this.sessionKeepAlive = sessionKeepAlive;
        this.cleanupExpiredSessions();
    }

    private async query(sql: string, values: any): Promise<any> {
        const conn: Pool = this.connPool;
        return new Promise((resolve, reject) => {
            conn.query(sql, values, (err, result) => {
                if (err) {
                    LOGGER.error(`Error while executing query. SQL: ${sql}. Error: ${err}`);
                    reject(err);
                } else {
                    resolve(result);
                }
            })
        });
    }

    private async cleanupExpiredSessions() {
        await this.query(`DELETE FROM ${TABLE_NAME_SESIONS} WHERE created < ?`, [Date.now() - this.sessionKeepAlive]);
        setTimeout(() => this.cleanupExpiredSessions(), CLEANUP_INTERVAL);
    }

    async saveToken(userId: number, provider: string, sub: string, token: TokenData) {
        let rs = await this.query(`INSERT INTO ${TABLE_NAME_OAUTH} SET ? ON DUPLICATE KEY UPDATE ?`, [
            { token: JSON.stringify(token), user_id: userId, provider, sub },
            { token: JSON.stringify(token) }]);
        LOGGER.info(`Save token of user ${userId} successfully.`);
        return rs;
    }


    async querySessionData(sessionId: string, userId: number | undefined): Promise<Session | undefined> {
        if (sessionId) {
            return dataToSession(await this.query(`SELECT s.id AS ssid, a.* FROM ${TABLE_NAME_SESIONS} s, ${TABLE_NAME_ACCOUNTS} a WHERE s.id=? AND s.user_id=? AND a.id=s.user_id`, [sessionId, userId]));
        }
        return undefined;
    }

    async saveSessionData(session: Session): Promise<boolean> {
        try {
            await this.query(`INSERT INTO ${TABLE_NAME_SESIONS}(id, user_id, created) VALUES(?,?,?)`, [session.sessionId, session.user.userId, Date.now()]);
            LOGGER.info(`Save session  ${session.sessionId} successfully.`);
            return true;
        } catch (err) {
            return false;
        }
    }

    async generateSession(user: UserAccount): Promise<Session> {
        let session: Session = {
            sessionId: generateSessionId(user.userId),
            user: user
        };
        await this.saveSessionData(session);
        LOGGER.info(`Generated new session: ${session.sessionId}.`);
        return session;
    }

    async getAccountInfo(userId: number): Promise<UserAccount | undefined> {
        let rs = await this.query(`SELECT * FROM ${TABLE_NAME_ACCOUNTS} WHERE id=?`, [userId]);
        if (rs && rs.length) {
            return {
                userId: userId,
                displayName: rs[0].display_name,
                username: rs[0].username,
                profilePic: rs[0].picture
            }
        }
    }

    async queryOAuthMapping(provider: string, sub: string): Promise<UserAccount | undefined> {
        let rs = await this.query(`SELECT user_id FROM ${TABLE_NAME_OAUTH} WHERE provider=? AND sub=?`, [provider, sub]);
        if (rs && rs.length) {
            return this.getAccountInfo(rs[0].user_id);
        }
        return undefined;
    }

    async createAccount(account: UserAccount): Promise<void> {
        await this.query(`INSERT INTO ${TABLE_NAME_ACCOUNTS} SET ?`, accountToDBSchema(account));
        LOGGER.info(`Created new user account ${account.userId}`);
    }

    async loadToken(userId: number, provider: string): Promise<TokenData | undefined> {
        let rs = await this.query(`SELECT * FROM ${TABLE_NAME_OAUTH} WHERE user_id=? AND provider=?`, [userId, provider]);
        if (rs && rs[0]) {
            return JSON.parse(rs[0].token) as TokenData;
        }
    }

    async queryToken(provider: string, sub: string): Promise<TokenData | undefined> {
        let rs = await this.query(`SELECT * FROM ${TABLE_NAME_OAUTH} WHERE sub=? AND provider=?`, [sub, provider]);
        if (rs && rs[0]) {
            return JSON.parse(rs[0].token) as TokenData;
        }
    }

    async queryProfile(provider: string, userId: number): Promise<OAuth2Profile | undefined> {
        let rs = await this.query(`SELECT * FROM ${TABLE_NAME_OAUTH} WHERE user_id=? AND provider=?`, [userId, provider]);
        if (rs && rs[0]) {
            // TODO: save external profile & return it here
            return {
                sub: rs[0].sub
            }
        }
    }

}

export default MySqlPassportProvider;