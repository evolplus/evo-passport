import mysql, { Pool, PoolConfig } from "mysql";
import { generateSessionId, generateUserId, PassportModel, Session, UserAccount } from "./model";
import log4js from "log4js-api";
import { OAuth2Profile, TokenData } from "@evolplus/evo-oauth2";

const TABLE_NAME_ACCOUNTS = "accounts";
const TABLE_NAME_SESIONS = "sessions";
const TABLE_NAME_OAUTH = "oauth";

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

export class MySqlPassportModel implements PassportModel {
    private connPool: Pool;

    constructor(config: PoolConfig) {
        this.connPool = mysql.createPool(config);
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

    async getOrCreateAccount(provider: string, token: TokenData | undefined, userInfo: OAuth2Profile): Promise<UserAccount> {
        let acc = await this.queryOAuthMapping(provider, userInfo.sub!);
        if (acc) {
            if (token && userInfo.sub) {
                await this.saveToken(acc.userId, provider, userInfo.sub, token);
            }
            return acc;
        }
        let account: any = {
            id: generateUserId()
        };
        if (userInfo.email) {
            account.email = userInfo.email;
            account.email_verified = userInfo.email_verified ? true : false;
        }
        if (userInfo.picture) {
            account.picture = userInfo.picture;
        }
        if (userInfo.name) {
            account.display_name = userInfo.name;
        } else {
            account.display_name = `${provider}-${userInfo.sub}`
        }
        await this.query(`INSERT INTO ${TABLE_NAME_ACCOUNTS} SET ?`, account);
        if (token) {
            await this.saveToken(account.id, provider, userInfo.sub!, token);
            LOGGER.info(`Created or update OAuth 2.0 profile: ${provider}/${userInfo.sub}.`);
        }
        return {
            userId: account.id,
            profilePic: account.picture,
            displayName: account.display_name
        }
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
            return rs[0] as TokenData;
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

export default MySqlPassportModel