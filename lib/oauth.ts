import log4js from 'log4js-api';
import { Application, Request, Response } from 'express';
import { OAuth2Client, OAuth2Profile, OAuth2ProviderConfiguration, TokenData, SupportedOAuth2Provider, getConfigurationByProvider, OAuth2Provider } from '@evolplus/evo-oauth2';

let logger = log4js.getLogger('oauth');

const PROVIDERS: { [key in SupportedOAuth2Provider]: OAuth2ProviderConfiguration } = {
    google: getConfigurationByProvider('google', process.env.GOOGLE_OAUTH2_CLIENT_ID || '', process.env.GOOGLE_OAUTH2_CLIENT_SECRET || ''),
    facebook: getConfigurationByProvider('facebook', process.env.FACEBOOK_OAUTH2_CLIENT_ID || '', process.env.FACEBOOK_OAUTH2_CLIENT_SECRET || ''),
    strava: getConfigurationByProvider('strava', process.env.STRAVA_OAUTH2_CLIENT_ID || '', process.env.STRAVA_OAUTH2_CLIENT_SECRET || '')
};

export type SignedInCallback = (provider: string, token: TokenData, userInfo: OAuth2Profile, req: Request, resp: Response) => Promise<void>;

export function createConfiguration(conf: OAuth2Provider): OAuth2ProviderConfiguration {
    if (typeof conf != 'string') {
        return conf;
    }
    return PROVIDERS[conf];
}

export function installProvider(app: Application, host: string, prefix: string, config: OAuth2ProviderConfiguration | OAuth2Provider, signedInCallback?: SignedInCallback) {
    const conf = createConfiguration(config);
    const client = new OAuth2Client(conf);
    const callback = `${prefix}${conf.providerName}/callback`;

    app.get(`${prefix}${conf.providerName}`, (req, res) => {
        const authorizationUri = client.generateAuthorizeUrl(`${host}${callback}`); // TODO: Add state here
        res.redirect(authorizationUri);
        res.end();
    });
    app.get(callback, async (req, res) => {
        const code = req.query.code as string;
        try {
            let token = await client.exchangeToken(code, 'authorization_code', `${host}${callback}`),
                profile = await client.getProfile(token);
            if (signedInCallback) {
                await signedInCallback(conf.providerName, token, profile, req, res);
            }
        } catch (error) {
            logger.error(error);
        }
        res.redirect('/');
        res.end();
    });
    logger.info(`Added OAuth2 provider [${conf.providerName}] for authentication and authorization.`);
}
