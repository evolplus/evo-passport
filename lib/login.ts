import { LRUCache, DecayLimiter } from "@evolplus/evo-utils";
import { Application, Request, Response } from "express";
import PassportModel, { Session, UserAccount } from "./model";
import { OAuth2Profile } from "@evolplus/evo-oauth2";
import nodemailer from 'nodemailer';
import log4js from 'log4js-api';

const DEFAULT_CODE_CACHE_CAPACITY = 10000;
const MSG_LOGIN_MAILED = JSON.stringify({ error: 0, message: "A login link has been sent to your email address. Please check your inbox and follow the link to log in." });
const MSG_LOGIN_INVALID_EMAIL = JSON.stringify({ error: 1, message: "Invalid email address. Please make sure you enter a valid email address." });
const MSG_LOGIN_RATE_LIMIT_EXCEEDED = JSON.stringify({ error: 2, message: "Rate limit exceeded. You have reached the maximum number of login requests allowed. Please try again later." });
const MSG_LOGIN_SERVER_ERROR = JSON.stringify({ error: 5, message: "Oops! Something went wrong on our end. We apologize for the inconvenience. Please try again later or contact our support team for assistance." });

const LOGGER = log4js.getLogger('passport-email');

function isValidEmailAddress(email: string): boolean {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export type EmailRenderer = (props: any) => string;
export type MailerConfig = {
    host: string;
    port: number;
    secure?: boolean;
    requireTLS?: boolean;
    auth: {
        user: string,
        pass: string
    }
}
export type LoginConfiguration = {
    emailRenderer: EmailRenderer;
    codeCapacity?: number;
    emailLimiter?: DecayLimiter;
    ipLimiter?: DecayLimiter;
    emailSender: string;
    emailSubject: string;
    emailConfig: MailerConfig[];
}
export type LoginCallback = (profile: OAuth2Profile, session: Session, req: Request, res: Response) => void;

type LoginRequest = {
    email: string;
    ip: string;
};

function generateRandomCode(): string {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

class AutoMailer {
    private mailers: nodemailer.Transporter[];
    private identities: string[];
    private scores: number[];
    private orders: number[];
    private lastEvaluated: number = Date.now();

    constructor(configs: MailerConfig[]) {
        this.mailers = configs.map(c => nodemailer.createTransport(c));
        this.identities = configs.map(c => `${c.auth.user}@${c.host}`);
        this.scores = new Array(configs.length).fill(0);
        this.orders = new Array(configs.length).fill(0).map((_, i) => i);
    }

    private reevaluate(i: number) {
        let now = Date.now();
        for (let j = i + 1; j < this.scores.length; j++) {
            this.scores[j] *= Math.pow(2, (now - this.lastEvaluated) / 600000);
        }
        this.scores[i] += 1;
        this.orders.sort((a, b) => this.scores[b] - this.scores[a]);
        this.lastEvaluated = now;
    }

    public async sendMail(mailOptions: nodemailer.SendMailOptions): Promise<void> {
        for (let i = 0; i < this.mailers.length; i++) {
            let mailer = this.mailers[this.orders[i]];
            try {
                await mailer.sendMail(mailOptions);
                return;
            } catch (e) {
                LOGGER.error(`Failed to send email via mailer ${this.identities[this.orders[i]]}.`, e);
                this.reevaluate(this.orders[i]);
            }
        }
    }
}

export function setupLogin(app: Application, passportModel: PassportModel, host: string, origin: string, prefix: string, config: LoginConfiguration, callback: LoginCallback) {
    let loginCodes = new LRUCache<LoginRequest>(config.codeCapacity || DEFAULT_CODE_CACHE_CAPACITY),
        mailer = new AutoMailer(config.emailConfig);
    app.get(`${prefix}login`, async (req, res) => {
        let code = req.query.code;
        if (Array.isArray(code)) {
            code = code[0];
        }
        code = code?.toString();
        if (req.header('Origin') != `https://${origin}` && !code) {
            res.status(403).send('Forbidden');
            return;
        }
        let email = req.query.email;
        if (Array.isArray(email)) {
            email = email[0];
        }
        email = email?.toString();
        if (!email || !isValidEmailAddress(email)) {
            LOGGER.warn(`User login with invalid emaail: ${email}.`);
            res.status(200).send(MSG_LOGIN_INVALID_EMAIL);
            return;
        }
        if (config.ipLimiter && !config.ipLimiter.hit(req.ip)) {
            LOGGER.warn(`IP ${req.ip} exceeded rate limit of login.`);
            res.status(200).send(MSG_LOGIN_RATE_LIMIT_EXCEEDED);
            return;
        }
        if (config.emailLimiter && !config.emailLimiter.hit(email)) {
            LOGGER.warn(`Email ${email} exceeded rate limit of login.`);
            res.status(200).send(MSG_LOGIN_RATE_LIMIT_EXCEEDED);
            return;
        }
        if (code) {
            let lr = loginCodes.get(code);
            if (lr && lr.email == email && lr.ip == req.ip) {
                let account = await passportModel.getOrCreateAccount('email', undefined, { email, sub: email, email_verified: true, name: email }),
                    session = await passportModel.generateSession(account);
                await callback({ email, sub: email, email_verified: true, name: email }, session, req, res);
                loginCodes.delete(code);
                if (!res.headersSent) {
                    res.redirect('/');
                    res.end();
                }
            } else {
                res.status(400)
                    .send('Invalid or expired code!');
            }
            return;
        }
        code = generateRandomCode();
        loginCodes.put(code, { email, ip: req.ip });
        let loginUrl = `${host}${prefix}login?code=${code}&email=${encodeURIComponent(email)}`,
            html = config.emailRenderer({ email, loginUrl });
        res.status(200)
            .header({
                'Content-Type': 'application/json; charset=utf-8',
                'Access-Control-Allow-Origin': `https://${origin}`,
                'Access-Control-Allow-Credentials': 'true'
            });
        try {
            await mailer.sendMail({
                from: config.emailSender,
                to: email,
                subject: config.emailSubject,
                html
            });
            res.send(MSG_LOGIN_MAILED);
            LOGGER.info(`Mailed login URL to ${email} successfully.`)
        } catch (err) {
            res.send(MSG_LOGIN_SERVER_ERROR);
            LOGGER.error(`Failed to send login URL to ${email}. Detailes: ${err}`);
        }
    });
}