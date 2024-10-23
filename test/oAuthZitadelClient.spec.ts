import { Buffer } from 'node:buffer'

import type {
  InternalAxiosRequestConfig,
} from 'axios'
import axios, { AxiosHeaders } from 'axios'
import AxiosMockAdapter from 'axios-mock-adapter'
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest'

import { OAuth2ZitadelClient } from '../src'
import type {
  OAuth2Tokens,
  OAuth2VueClientOptions,
} from '../src/zitadelClient'

let mockAxios: AxiosMockAdapter
const tokenEndpoint = '/token-endpoint'

interface Token {
  exp: number
}

function encodeJwt(token: Token): string {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64')

  const payload = Buffer.from(JSON.stringify(token)).toString('base64')

  return `${header}.${payload}.signature`
}

const mockAccessToken = encodeJwt({ exp: Date.now() })
const mockExpiresAt = Date.now() + 1000

const mockTokens: OAuth2Tokens = {
  expires_at: mockExpiresAt,
  access_token: mockAccessToken,
  id_token: 'id_token_value',
  refresh_token: 'refresh_token_value',
  scope: 'openid',
  token_type: 'Bearer',
}

const axiosInstance = axios.create({
  baseURL: 'http://auth.base.url',
})

const clientOptions: OAuth2VueClientOptions = {
  authorization: {
    clientId: 'client_id_value',
    grantType: 'authorization_code',
    logoutUrl: '/logout',
    postLogoutRedirectUri: '/post-logout',
    redirectUri: '/redirect',
    scopes: [
      'openid',
    ],
    url: '/authorize',
  },
  axios: axiosInstance,
  offline: false,
  tokenEndpoint,
  userInfoEndpoint: '/userinfo',
}

describe('oAuth2ZitadelClient', () => {
  let client: OAuth2ZitadelClient

  beforeEach(() => {
    // eslint-disable-next-line ts/ban-ts-comment
    // @ts-ignore MockAdapter is not typed correctly https://github.com/ctimmerm/axios-mock-adapter/issues/400
    mockAxios = new AxiosMockAdapter(axiosInstance)
    client = new OAuth2ZitadelClient(clientOptions)
  })

  afterEach(() => {
    mockAxios.reset()
  })

  describe('constructor', () => {
    it('should initialize a new TokenStore with the correct clientId and tokenEndpoint', () => {
      const tokenStore = client.getClient()

      expect(tokenStore).not.toBeNull()
    })
  })

  describe('getLoginUrl', () => {
    it('should generate the login URL with PKCE challenge', async () => {
      const pkceSpy = vi.spyOn(client, 'getLoginUrl').mockResolvedValueOnce('code_challenge_value')
      const url = await client.getLoginUrl()

      expect(pkceSpy).toHaveBeenCalledWith()
      expect(url).toContain('code_challenge_value')
      pkceSpy.mockRestore()
    })
  })

  describe('getLogoutUrl', () => {
    it('should generate the logout URL', () => {
      const url = client.getLogoutUrl()

      expect(url).toContain('/logout?client_id=client_id_value&post_logout_redirect_uri=%2Fpost-logout')
    })
  })

  describe('addAuthorizationHeader', () => {
    it('should add the Authorization header with the access token', async () => {
      localStorage.setItem('tokens', JSON.stringify(mockTokens))

      const config: InternalAxiosRequestConfig = {
        headers: AxiosHeaders.from(),
      }

      const result = await client.addAuthorizationHeader(config)

      expect(result.headers.Authorization).toBe(`Bearer ${mockAccessToken}`)
    })

    it('should refresh the access token if expired', async () => {
      const expiredTokens = {
        ...mockTokens,
        expires_at: mockExpiresAt * 1000,
      }

      localStorage.setItem('tokens', JSON.stringify(expiredTokens))

      mockAxios.onPost(tokenEndpoint).reply(200, mockTokens)

      const config: InternalAxiosRequestConfig = {
        headers: AxiosHeaders.from(),
      }

      const result = await client.addAuthorizationHeader(config)

      expect(result.headers.Authorization).toBe(`Bearer ${mockAccessToken}`)

      const expectedTokens = {
        expires_at: mockExpiresAt * 1000,
        access_token: mockAccessToken,
        id_token: 'id_token_value',
        refresh_token: 'refresh_token_value',
        scope: 'openid',
        token_type: 'Bearer',
      }

      expect(localStorage.getItem('tokens')).toContain(JSON.stringify(expectedTokens))
    })
  })

  describe('getUserInfo', () => {
    it('should fetch user info from the userInfo endpoint', async () => {
      localStorage.setItem('tokens', JSON.stringify(mockTokens))

      mockAxios.onGet('/userinfo').reply(200, { name: 'Test User' })

      const userInfo = await client.getUserInfo<{ name: string }>()

      expect(userInfo.name).toBe('Test User')
    })

    it('should throw an error if client is not logged in', async () => {
      localStorage.removeItem('tokens')
      client.logout()

      await expect(client.getUserInfo()).rejects.toThrow('Client is not logged in')
    })
  })

  describe('loginAuthorization', () => {
    it('should perform login using authorization code', async () => {
      localStorage.setItem('code_verifier', 'code_verifier_value')

      mockAxios.onPost(tokenEndpoint).reply(200, mockTokens)

      await client.loginAuthorization('authorization_code_value')

      const storedTokens = JSON.parse(localStorage.getItem('tokens') as string)

      expect(storedTokens.access_token).toBe(mockAccessToken)
    })
  })

  describe('logout', () => {
    it('should clear tokens on logout', () => {
      localStorage.setItem('tokens', JSON.stringify(mockTokens))

      client.logout()

      expect(localStorage.getItem('tokens')).toBeNull()
    })
  })

  describe('isLoggedIn', () => {
    it('should return true if tokens exist', () => {
      localStorage.setItem('tokens', JSON.stringify(mockTokens))

      expect(client.isLoggedIn()).toBeTruthy()
    })

    it('should return false if tokens do not exist', () => {
      localStorage.removeItem('tokens')

      expect(client.isLoggedIn()).toBeFalsy()
    })
  })
})
