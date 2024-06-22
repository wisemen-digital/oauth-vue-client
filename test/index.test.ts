import axios, { AxiosHeaders } from 'axios'
import {
  describe,
  expect,
  it,
  vi,
} from 'vitest'

import {
  addAuthorizationHeader,
  OAuth2VueClient,
} from '../src'
import type { OAuth2ClientTokensWithExpiration } from '../src/oAuthClient'

describe('oAuth2VueClient', () => {
  const CLIENT_ID = 'client_id'
  const CLIENT_SECRET = 'client_secret'
  const TOKEN_ENDPOINT = `auth`

  const MOCK_TOKENS: OAuth2ClientTokensWithExpiration = {
    expires_at: Date.now() + 3600 * 1000,
    access_token: 'access_token',
    expires_in: 3600,
    refresh_token: 'refresh_token',
    scope: 'scope',
    token_type: 'token_type',
  }

  it('creates a new client using the constructor', () => {
    expect(1).toEqual(1)

    const oAuthClient = new OAuth2VueClient({
      clientId: CLIENT_ID,
      axios,
      clientSecret: CLIENT_SECRET,
      tokenEndpoint: TOKEN_ENDPOINT,
    })

    expect(oAuthClient).toBeDefined()
  })

  it('authenticates using a password', async () => {
    const oAuthClient = new OAuth2VueClient({
      clientId: CLIENT_ID,
      axios,
      clientSecret: CLIENT_SECRET,
      tokenEndpoint: TOKEN_ENDPOINT,
    })

    vi.spyOn(axios, 'post').mockImplementation(() => Promise.resolve({ data: MOCK_TOKENS }))

    await oAuthClient.loginPassword('username', 'password')

    const actualTokens = oAuthClient.getClient()?.getTokens()

    const expectedTokens = {
      ...MOCK_TOKENS,
      expires_at: actualTokens?.expires_at,
    }

    expect(actualTokens).toStrictEqual(expectedTokens)
  })

  it('adds an authorization header to the axios config', async () => {
    const oAuthClient = new OAuth2VueClient({
      clientId: CLIENT_ID,
      axios,
      clientSecret: CLIENT_SECRET,
      tokenEndpoint: TOKEN_ENDPOINT,
    })

    vi.spyOn(axios, 'post').mockImplementation(() => Promise.resolve({ data: MOCK_TOKENS }))

    await oAuthClient.loginPassword('username', 'password')

    const config = {
      headers: new AxiosHeaders(),
    }

    await addAuthorizationHeader(oAuthClient, config)

    expect(config.headers.Authorization).toEqual(`Bearer ${MOCK_TOKENS.access_token}`)
  })
})
