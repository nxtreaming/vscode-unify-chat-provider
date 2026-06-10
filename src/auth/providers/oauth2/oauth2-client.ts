import * as vscode from 'vscode';
import { randomBytes } from 'crypto';
import {
  OAuth2AuthCodeConfig,
  OAuth2ClientCredentialsConfig,
  OAuth2Config,
  OAuth2DeviceCodeConfig,
  OAuth2TokenData,
} from '../../types';
import {
  DeviceCodeResponse,
  OAuth2AuthState,
  PKCEChallenge,
  TokenResponse,
} from './types';
import { t } from '../../../i18n';
import {
  createOAuth2ErrorFromResponse,
  createOAuth2ErrorFromNetworkError,
} from './errors';
import { authLog } from '../../../logger';
import { generatePKCE as generatePKCEUtil } from '../../../utils';

/**
 * Generate a random state string for OAuth
 */
export function generateState(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * Generate PKCE challenge
 */
export function generatePKCE(): PKCEChallenge {
  const pkce = generatePKCEUtil(43);

  return {
    codeVerifier: pkce.verifier,
    codeChallenge: pkce.challenge,
    codeChallengeMethod: pkce.method,
  };
}

/**
 * Build authorization URL for authorization code flow
 */
export function buildAuthorizationUrl(
  config: OAuth2AuthCodeConfig,
  state: OAuth2AuthState,
): string {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: state.redirectUri,
    state: state.state,
  });

  if (config.scopes && config.scopes.length > 0) {
    params.set('scope', config.scopes.join(' '));
  }

  if (state.pkce) {
    params.set('code_challenge', state.pkce.codeChallenge);
    params.set('code_challenge_method', state.pkce.codeChallengeMethod);
  }

  return `${config.authorizationUrl}?${params.toString()}`;
}

/**
 * Exchange authorization code for tokens
 */
export async function exchangeCodeForToken(
  config: OAuth2AuthCodeConfig,
  code: string,
  state: OAuth2AuthState,
  signal?: AbortSignal,
): Promise<OAuth2TokenData> {
  authLog.verbose('oauth2-client', `Exchanging authorization code for token (tokenUrl: ${config.tokenUrl})`);
  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: config.clientId,
    code,
    redirect_uri: state.redirectUri,
  });

  if (config.clientSecret) {
    params.set('client_secret', config.clientSecret);
  }

  if (state.pkce) {
    params.set('code_verifier', state.pkce.codeVerifier);
  }

  const response = await fetch(config.tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
    signal,
  });

  if (!response.ok) {
    const error = await response.text();
    authLog.error('oauth2-client', `Token exchange failed (status: ${response.status})`, error);
    throw new Error(t('Token exchange failed: {0}', error));
  }

  const data = (await response.json()) as TokenResponse;
  authLog.verbose('oauth2-client', 'Token exchange successful');
  return tokenResponseToData(data);
}

/**
 * Get token using client credentials flow
 */
export async function getClientCredentialsToken(
  config: OAuth2ClientCredentialsConfig,
  signal?: AbortSignal,
): Promise<OAuth2TokenData> {
  authLog.verbose('oauth2-client', `Getting token using client_credentials (tokenUrl: ${config.tokenUrl})`);
  const params = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: config.clientId,
    client_secret: config.clientSecret,
  });

  if (config.scopes && config.scopes.length > 0) {
    params.set('scope', config.scopes.join(' '));
  }

  let response: Response;
  try {
    response = await fetch(config.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
      signal,
    });
  } catch (error) {
    authLog.error('oauth2-client', 'Network error during client_credentials token request', error);
    throw createOAuth2ErrorFromNetworkError(error);
  }

  if (!response.ok) {
    const oauth2Error = await createOAuth2ErrorFromResponse(
      response,
      t('Token request failed'),
    );
    authLog.error('oauth2-client', `Client credentials token request failed (status: ${response.status})`, oauth2Error);
    throw oauth2Error;
  }

  const data = (await response.json()) as TokenResponse;
  authLog.verbose('oauth2-client', 'Client credentials token request successful');
  return tokenResponseToData(data);
}

/**
 * Start device code flow
 */
export async function startDeviceCodeFlow(
  config: OAuth2DeviceCodeConfig,
): Promise<DeviceCodeResponse> {
  authLog.verbose('oauth2-client', `Starting device code flow (deviceAuthorizationUrl: ${config.deviceAuthorizationUrl})`);
  const params = new URLSearchParams({
    client_id: config.clientId,
  });

  if (config.scopes && config.scopes.length > 0) {
    params.set('scope', config.scopes.join(' '));
  }

  const response = await fetch(config.deviceAuthorizationUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });

  if (!response.ok) {
    const error = await response.text();
    authLog.error('oauth2-client', `Device authorization failed (status: ${response.status})`, error);
    throw new Error(t('Device authorization failed: {0}', error));
  }

  const data = await response.json();
  authLog.verbose('oauth2-client', `Device code flow started (userCode: ${data.user_code})`);
  return {
    deviceCode: data.device_code,
    userCode: data.user_code,
    verificationUri: data.verification_uri,
    verificationUriComplete: data.verification_uri_complete,
    expiresIn: data.expires_in,
    interval: data.interval || 5,
  };
}

/**
 * Poll for device code token
 */
export async function pollDeviceCodeToken(
  config: OAuth2DeviceCodeConfig,
  deviceCode: string,
  token: vscode.CancellationToken,
): Promise<OAuth2TokenData | null> {
  authLog.verbose('oauth2-client', 'Polling for device code token');
  const params = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    client_id: config.clientId,
    device_code: deviceCode,
  });

  const controller = new AbortController();
  const cancelSubscription = token.onCancellationRequested(() => {
    controller.abort();
  });
  if (token.isCancellationRequested) {
    controller.abort();
  }

  let response: Response;
  try {
    response = await fetch(config.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
      signal: controller.signal,
    });
  } finally {
    cancelSubscription.dispose();
  }

  if (token.isCancellationRequested) {
    authLog.verbose('oauth2-client', 'Device code polling cancelled');
    return null;
  }

  if (!response.ok) {
    const data = await response.json();
    const error = data.error;

    if (error === 'authorization_pending') {
      // User hasn't completed authorization yet
      authLog.verbose('oauth2-client', 'Device code authorization pending');
      return null;
    }

    if (error === 'slow_down') {
      // Need to slow down polling
      authLog.verbose('oauth2-client', 'Device code polling: slow_down received');
      return null;
    }

    if (error === 'expired_token') {
      authLog.error('oauth2-client', 'Device code expired');
      throw new Error(t('Device code expired. Please try again.'));
    }

    if (error === 'access_denied') {
      authLog.error('oauth2-client', 'Device code authorization was denied');
      throw new Error(t('Authorization was denied.'));
    }

    authLog.error('oauth2-client', `Device code token request failed: ${error}`, data.error_description);
    throw new Error(t('Token request failed: {0}', data.error_description || error));
  }

  const data = (await response.json()) as TokenResponse;
  authLog.verbose('oauth2-client', 'Device code token obtained successfully');
  return tokenResponseToData(data);
}

/**
 * Refresh an access token
 */
export async function refreshToken(
  config: OAuth2Config,
  refreshTokenValue: string,
  signal?: AbortSignal,
): Promise<OAuth2TokenData> {
  authLog.verbose('oauth2-client', `Refreshing access token (tokenUrl: ${config.tokenUrl})`);
  if (config.grantType === 'device_code') {
    authLog.error('oauth2-client', 'Device code flow does not support refresh tokens');
    throw new Error('Device code flow does not support refresh tokens');
  }

  const params = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshTokenValue,
  });

  if ('clientId' in config) {
    params.set('client_id', config.clientId);
  }

  if ('clientSecret' in config && config.clientSecret) {
    params.set('client_secret', config.clientSecret);
  }

  let response: Response;
  try {
    response = await fetch(config.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
      signal,
    });
  } catch (error) {
    authLog.error('oauth2-client', 'Network error during token refresh', error);
    throw createOAuth2ErrorFromNetworkError(error);
  }

  if (!response.ok) {
    const oauth2Error = await createOAuth2ErrorFromResponse(
      response,
      t('Token refresh failed'),
    );
    authLog.error('oauth2-client', `Token refresh failed (status: ${response.status})`, oauth2Error);
    throw oauth2Error;
  }

  const data = (await response.json()) as TokenResponse;
  authLog.verbose('oauth2-client', 'Token refresh successful');
  return tokenResponseToData(data);
}

export type OAuth2RevocationTokenTypeHint = 'access_token' | 'refresh_token';

/**
 * Revoke a token via OAuth2 revocation endpoint, if configured.
 * Best-effort: callers may choose to swallow errors.
 */
export async function revokeToken(
  config: OAuth2Config,
  tokenValue: string,
  hint: OAuth2RevocationTokenTypeHint,
  signal?: AbortSignal,
): Promise<void> {
  const revocationUrl = config.revocationUrl;
  if (!revocationUrl) {
    authLog.verbose('oauth2-client', 'No revocation URL configured, skipping remote revocation');
    return;
  }

  authLog.verbose('oauth2-client', `Revoking token (revocationUrl: ${revocationUrl}, hint: ${hint})`);
  const params = new URLSearchParams({
    token: tokenValue,
    token_type_hint: hint,
  });

  if ('clientId' in config) {
    params.set('client_id', config.clientId);
  }

  if ('clientSecret' in config && config.clientSecret) {
    params.set('client_secret', config.clientSecret);
  }

  let response: Response;
  try {
    response = await fetch(revocationUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
      signal,
    });
  } catch (error) {
    authLog.error('oauth2-client', 'Network error during token revocation', error);
    throw createOAuth2ErrorFromNetworkError(error);
  }

  if (!response.ok) {
    const oauth2Error = await createOAuth2ErrorFromResponse(
      response,
      t('Token revocation failed'),
    );
    authLog.error('oauth2-client', `Token revocation failed (status: ${response.status})`, oauth2Error);
    throw oauth2Error;
  }

  authLog.verbose('oauth2-client', 'Token revocation successful');
}

/**
 * Convert token response to OAuth2TokenData
 */
function tokenResponseToData(response: TokenResponse): OAuth2TokenData {
  return {
    accessToken: response.access_token,
    tokenType: response.token_type || 'Bearer',
    refreshToken: response.refresh_token,
    expiresAt: response.expires_in
      ? Date.now() + response.expires_in * 1000
      : undefined,
    scope: response.scope,
  };
}
